"""
Async DNS resolution: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA records.
Wildcard detection + zone transfer attempts.
"""
import asyncio
import random
import aiodns
import dns.resolver
import dns.query
import dns.zone
import dns.exception
from dataclasses import dataclass, field
from rich.console import Console
from ...core.config import settings
from ..phase1_subdomains.bruteforce import DEFAULT_RESOLVERS

console = Console()

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"]

# Known dangling CNAME fingerprints (subdomain takeover)
TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    ".cloudfront.net": "CloudFront",
    "azurewebsites.net": "Azure",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "fastly.net": "Fastly",
    "shopify.com": "Shopify",
    "tumblr.com": "Tumblr",
    "ghost.io": "Ghost",
    "webflow.io": "Webflow",
    "netlify.app": "Netlify",
    "surge.sh": "Surge",
    "fly.dev": "Fly.io",
}


@dataclass
class DnsResult:
    fqdn: str
    resolved: bool = False
    records: dict[str, list[str]] = field(default_factory=dict)
    takeover_candidate: str | None = None
    cert_sans: list[str] = field(default_factory=list)


async def detect_wildcard(domain: str) -> set[str]:
    """Resolve random subdomains to detect wildcard DNS. Returns wildcard IPs if found."""
    import uuid
    wildcard_ips: set[str] = set()
    resolver = aiodns.DNSResolver(
        nameservers=[random.choice(DEFAULT_RESOLVERS)],
        timeout=settings.dns_timeout,
    )
    for _ in range(3):
        random_sub = f"{uuid.uuid4().hex[:12]}.{domain}"
        try:
            result = await resolver.query(random_sub, "A")
            for r in result:
                wildcard_ips.add(r.host)
        except Exception:
            pass
    if wildcard_ips:
        console.print(f"[yellow]Wildcard DNS detected for {domain}: {wildcard_ips}[/yellow]")
    return wildcard_ips


async def attempt_zone_transfer(domain: str) -> set[str]:
    """Try AXFR against all nameservers. Returns discovered hostnames."""
    found: set[str] = set()
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        nameservers = [str(ns) for ns in ns_answers]
    except Exception:
        return found

    for ns in nameservers:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
            for name in z.nodes:
                fqdn = f"{name}.{domain}".strip("@").lower()
                if fqdn and fqdn != domain:
                    found.add(fqdn)
            if found:
                console.print(f"[bold red]Zone transfer succeeded on {ns}! Got {len(found)} records[/bold red]")
        except Exception:
            pass
    return found


def check_takeover(cname_chain: list[str]) -> str | None:
    """Check if a CNAME chain ends at a vulnerable third-party service."""
    for cname in cname_chain:
        for fingerprint, service in TAKEOVER_FINGERPRINTS.items():
            if fingerprint in cname:
                return service
    return None


async def resolve_subdomain(fqdn: str, wildcard_ips: set[str]) -> DnsResult:
    result = DnsResult(fqdn=fqdn)
    resolver = aiodns.DNSResolver(
        nameservers=[random.choice(DEFAULT_RESOLVERS)],
        timeout=settings.dns_timeout,
    )

    for rtype in RECORD_TYPES:
        try:
            answers = await resolver.query(fqdn, rtype)
            values = []
            for ans in answers:
                if rtype == "A":
                    values.append(ans.host)
                elif rtype == "AAAA":
                    values.append(ans.host)
                elif rtype == "CNAME":
                    values.append(ans.cname)
                elif rtype == "MX":
                    values.append(f"{ans.priority} {ans.host}")
                elif rtype == "TXT":
                    values.append(" ".join(ans.text) if hasattr(ans, "text") else str(ans))
                elif rtype == "NS":
                    values.append(ans.host)
                else:
                    values.append(str(ans))
            if values:
                result.records[rtype] = values
        except Exception:
            pass

    # Resolved if we have at least an A or AAAA record
    a_records = result.records.get("A", [])
    aaaa_records = result.records.get("AAAA", [])
    all_ips = set(a_records + aaaa_records)

    if all_ips:
        # Filter out wildcard matches
        real_ips = all_ips - wildcard_ips
        if real_ips or not wildcard_ips:
            result.resolved = True

    # Check for subdomain takeover via CNAME
    if "CNAME" in result.records:
        cname_chain = result.records["CNAME"]
        takeover = check_takeover(cname_chain)
        if takeover:
            result.takeover_candidate = takeover
            console.print(f"[bold red]TAKEOVER CANDIDATE: {fqdn} -> {cname_chain[-1]} ({takeover})[/bold red]")

    return result


async def resolve_all(subdomains: set[str], domain: str) -> list[DnsResult]:
    wildcard_ips = await detect_wildcard(domain)
    zone_subs = await attempt_zone_transfer(domain)
    all_targets = subdomains | zone_subs

    semaphore = asyncio.Semaphore(settings.dns_concurrency)
    results: list[DnsResult] = []

    async def bounded_resolve(fqdn: str):
        async with semaphore:
            r = await resolve_subdomain(fqdn, wildcard_ips)
            results.append(r)

    await asyncio.gather(*[bounded_resolve(s) for s in all_targets], return_exceptions=True)

    resolved = [r for r in results if r.resolved]
    console.print(f"[bold green]DNS:[/bold green] {len(resolved)}/{len(all_targets)} resolved")
    return results
