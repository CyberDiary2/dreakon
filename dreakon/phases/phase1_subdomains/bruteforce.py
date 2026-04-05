"""
DNS brute force using aiodns with resolver rotation.
"""
import asyncio
import aiodns
import random
from pathlib import Path
from rich.console import Console
from ...core.config import settings

console = Console()

# Public resolvers — rotate to avoid rate limiting
DEFAULT_RESOLVERS = [
    "8.8.8.8", "8.8.4.4",           # Google
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",       # Verisign
    "77.88.8.8", "77.88.8.1",       # Yandex
    "94.140.14.14", "94.140.15.15", # AdGuard
]

WORDLIST_PATH = Path(__file__).parent.parent.parent / "wordlists" / "dns_common.txt"


def load_wordlist() -> list[str]:
    if WORDLIST_PATH.exists():
        return [line.strip() for line in WORDLIST_PATH.read_text().splitlines() if line.strip()]
    # Minimal built-in fallback
    return [
        "www", "mail", "ftp", "api", "admin", "app", "dev", "staging", "test",
        "beta", "portal", "vpn", "cdn", "static", "assets", "media", "secure",
        "auth", "login", "dashboard", "internal", "intranet", "corp", "prod",
        "production", "qa", "uat", "sandbox", "demo", "preview", "legacy",
        "old", "new", "v1", "v2", "v3", "m", "mobile", "shop", "store",
        "blog", "forum", "support", "help", "docs", "status", "monitor",
        "smtp", "pop", "imap", "webmail", "mx", "ns", "ns1", "ns2",
        "gateway", "proxy", "lb", "load", "backend", "frontend", "web",
        "img", "images", "video", "upload", "download", "files", "s3",
    ]


async def resolve_one(resolver: aiodns.DNSResolver, hostname: str) -> tuple[str, bool]:
    try:
        await resolver.query(hostname, "A")
        return hostname, True
    except Exception:
        return hostname, False


async def brute_force(domain: str, extra_wordlist: list[str] | None = None) -> set[str]:
    """Brute-force subdomains using DNS resolution."""
    wordlist = load_wordlist()
    if extra_wordlist:
        wordlist = list(set(wordlist + extra_wordlist))

    candidates = [f"{word}.{domain}" for word in wordlist]
    console.print(f"[cyan]Brute force:[/cyan] {len(candidates)} candidates")

    found: set[str] = set()
    semaphore = asyncio.Semaphore(settings.dns_concurrency)

    async def check(hostname: str):
        # Rotate resolvers
        nameserver = random.choice(DEFAULT_RESOLVERS)
        resolver = aiodns.DNSResolver(nameservers=[nameserver], timeout=settings.dns_timeout)
        async with semaphore:
            _, alive = await resolve_one(resolver, hostname)
            if alive:
                found.add(hostname)

    await asyncio.gather(*[check(c) for c in candidates], return_exceptions=True)
    console.print(f"[bold cyan]Brute force:[/bold cyan] {len(found)} resolved")
    return found
