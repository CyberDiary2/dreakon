"""
HTTP probing: probe all resolved subdomains on multiple ports.
Captures status, title, redirect chain, TLS cert SANs, response hash.
"""
import asyncio
import hashlib
import json
import re
import ssl
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse
import httpx
from rich.console import Console
from ...core.config import settings
from ...core.ratelimiter import rate_limiter

console = Console()

PROBE_PORTS = [(80, "http"), (443, "https"), (8080, "http"), (8443, "https"),
               (8888, "http"), (3000, "http"), (4000, "http"), (5000, "http"),
               (9000, "http"), (9200, "http"), (9443, "https")]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


@dataclass
class HttpProbeResult:
    fqdn: str
    port: int
    protocol: str
    status_code: int | None = None
    final_url: str | None = None
    title: str | None = None
    headers: dict = field(default_factory=dict)
    response_hash: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    cert_sans: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    error: str | None = None


def get_cert_sans(hostname: str, port: int) -> list[str]:
    """Extract Subject Alternative Names from TLS certificate."""
    sans: list[str] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type == "DNS":
                        sans.append(san_value.lstrip("*.").lower())
    except Exception:
        pass
    return list(set(sans))


def fingerprint_tech(headers: dict, body: str) -> list[str]:
    """Basic technology detection from headers and body."""
    tech = []
    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()
    combined = (server + " " + powered_by + " " + body[:5000]).lower()

    checks = {
        "nginx": "nginx",
        "apache": "apache",
        "iis": "iis",
        "cloudflare": "cloudflare",
        "fastly": "fastly",
        "wordpress": "wp-content",
        "drupal": "drupal",
        "django": "django",
        "laravel": "laravel",
        "rails": "rails",
        "spring": "spring",
        "express": "express",
        "react": "__react",
        "vue": "vue",
        "angular": "ng-version",
        "jquery": "jquery",
        "graphql": "graphql",
        "swagger": "swagger-ui",
        "php": "php",
        "asp.net": "asp.net",
        "next.js": "__next",
        "nuxt": "__nuxt",
    }
    for name, pattern in checks.items():
        if pattern in combined:
            tech.append(name)
    return tech


async def probe_target(fqdn: str, port: int, protocol: str) -> HttpProbeResult:
    result = HttpProbeResult(fqdn=fqdn, port=port, protocol=protocol)
    url = f"{protocol}://{fqdn}:{port}" if port not in (80, 443) else f"{protocol}://{fqdn}"

    import random
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    try:
        bucket = await rate_limiter.get(fqdn, rate=10.0, capacity=20)
        await bucket.acquire()

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=settings.http_timeout,
            headers=headers,
        ) as client:
            r = await client.get(url)
            body = r.text

            result.status_code = r.status_code
            result.final_url = str(r.url)
            result.headers = dict(r.headers)
            result.redirect_chain = [str(h.url) for h in r.history]
            result.response_hash = hashlib.md5(body[:10240].encode(errors="ignore")).hexdigest()
            result.tech_stack = fingerprint_tech(dict(r.headers), body)

            title_match = TITLE_RE.search(body)
            if title_match:
                result.title = title_match.group(1).strip()[:256]

            await rate_limiter.record_success(fqdn)

    except httpx.HTTPStatusError as e:
        result.status_code = e.response.status_code
        await rate_limiter.record_error(fqdn)
    except Exception as e:
        result.error = str(e)[:128]
        await rate_limiter.record_error(fqdn)

    # TLS SANs
    if protocol == "https":
        result.cert_sans = get_cert_sans(fqdn, port)

    return result


async def probe_all(resolved_fqdns: set[str]) -> list[HttpProbeResult]:
    semaphore = asyncio.Semaphore(settings.http_concurrency)
    results: list[HttpProbeResult] = []

    async def bounded_probe(fqdn: str, port: int, protocol: str):
        async with semaphore:
            r = await probe_target(fqdn, port, protocol)
            if r.status_code is not None:
                results.append(r)

    tasks = [
        bounded_probe(fqdn, port, protocol)
        for fqdn in resolved_fqdns
        for port, protocol in PROBE_PORTS
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    alive = [r for r in results if r.status_code is not None]
    console.print(f"[bold green]HTTP probe:[/bold green] {len(alive)} live endpoints across {len(resolved_fqdns)} hosts")
    return results
