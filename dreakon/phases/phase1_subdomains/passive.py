"""
Passive subdomain enumeration from OSINT sources.
No packets sent directly to the target.
"""
import asyncio
import re
import json
from urllib.parse import urlparse
import httpx
from rich.console import Console
from ...core.config import settings

console = Console()

SUBDOMAIN_RE = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*")

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def extract_subdomains(text: str, domain: str) -> set[str]:
    """Pull all valid subdomains of domain from arbitrary text."""
    found = set()
    pattern = re.compile(
        r"(?:[a-zA-Z0-9\-]+\.)*" + re.escape(domain),
        re.IGNORECASE
    )
    for match in pattern.finditer(text):
        sub = match.group(0).lower().strip(".")
        if sub.endswith(domain):
            found.add(sub)
    return found


async def query_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    found = set()
    try:
        r = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
            headers={"User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain):
                        found.add(name.lower())
    except Exception as e:
        console.print(f"[yellow]crt.sh error: {e}[/yellow]")
    console.print(f"[green]crt.sh:[/green] {len(found)} subdomains")
    return found


async def query_virustotal(domain: str, client: httpx.AsyncClient) -> set[str]:
    found = set()
    if not settings.virustotal_api_key:
        return found
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
            headers={"x-apikey": settings.virustotal_api_key, "User-Agent": USER_AGENT},
            params={"limit": 40},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for item in data.get("data", []):
                sub = item.get("id", "").lower()
                if sub.endswith(domain):
                    found.add(sub)
    except Exception as e:
        console.print(f"[yellow]VirusTotal error: {e}[/yellow]")
    console.print(f"[green]VirusTotal:[/green] {len(found)} subdomains")
    return found


async def query_securitytrails(domain: str, client: httpx.AsyncClient) -> set[str]:
    found = set()
    if not settings.securitytrails_api_key:
        return found
    try:
        r = await client.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"apikey": settings.securitytrails_api_key, "User-Agent": USER_AGENT},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for sub in data.get("subdomains", []):
                found.add(f"{sub}.{domain}".lower())
    except Exception as e:
        console.print(f"[yellow]SecurityTrails error: {e}[/yellow]")
    console.print(f"[green]SecurityTrails:[/green] {len(found)} subdomains")
    return found


async def query_shodan(domain: str, client: httpx.AsyncClient) -> set[str]:
    found = set()
    if not settings.shodan_api_key:
        return found
    try:
        r = await client.get(
            "https://api.shodan.io/dns/domain/{domain}".format(domain=domain),
            params={"key": settings.shodan_api_key},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for sub in data.get("subdomains", []):
                found.add(f"{sub}.{domain}".lower())
    except Exception as e:
        console.print(f"[yellow]Shodan error: {e}[/yellow]")
    console.print(f"[green]Shodan:[/green] {len(found)} subdomains")
    return found


async def query_urlscan(domain: str, client: httpx.AsyncClient) -> set[str]:
    found = set()
    headers = {"User-Agent": USER_AGENT}
    if settings.urlscan_api_key:
        headers["API-Key"] = settings.urlscan_api_key
    try:
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 100},
            headers=headers,
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                hostname = page.get("domain", "")
                if hostname.endswith(domain):
                    found.add(hostname.lower())
                # Also extract from all indexed URLs
                for url in result.get("lists", {}).get("urls", []):
                    try:
                        h = urlparse(url).hostname or ""
                        if h.endswith(domain):
                            found.add(h.lower())
                    except Exception:
                        pass
    except Exception as e:
        console.print(f"[yellow]URLScan error: {e}[/yellow]")
    console.print(f"[green]URLScan:[/green] {len(found)} subdomains")
    return found


async def query_wayback_subdomains(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Extract unique hostnames from Wayback Machine CDX."""
    found = set()
    try:
        r = await client.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": 10000,
            },
            timeout=60,
        )
        if r.status_code == 200:
            for row in r.json()[1:]:  # skip header row
                try:
                    hostname = urlparse(row[0]).hostname or ""
                    if hostname.endswith(domain):
                        found.add(hostname.lower())
                except Exception:
                    pass
    except Exception as e:
        console.print(f"[yellow]Wayback subdomains error: {e}[/yellow]")
    console.print(f"[green]Wayback (subdomains):[/green] {len(found)} subdomains")
    return found


async def query_github(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Search GitHub code for references to the domain."""
    found = set()
    if not settings.github_token:
        return found
    try:
        r = await client.get(
            "https://api.github.com/search/code",
            params={"q": domain, "per_page": 100},
            headers={
                "Authorization": f"token {settings.github_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": USER_AGENT,
            },
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", []):
                # Download the file content and extract subdomains
                file_url = item.get("url", "")
                if file_url:
                    try:
                        fr = await client.get(
                            file_url,
                            headers={
                                "Authorization": f"token {settings.github_token}",
                                "Accept": "application/vnd.github.v3.raw",
                            },
                            timeout=10,
                        )
                        found.update(extract_subdomains(fr.text, domain))
                    except Exception:
                        pass
    except Exception as e:
        console.print(f"[yellow]GitHub error: {e}[/yellow]")
    console.print(f"[green]GitHub:[/green] {len(found)} subdomains")
    return found


async def query_censys(domain: str, client: httpx.AsyncClient) -> set[str]:
    found = set()
    if not settings.censys_api_id or not settings.censys_api_secret:
        return found
    try:
        r = await client.post(
            "https://search.censys.io/api/v2/certificates/search",
            json={"q": f"parsed.names: {domain}", "per_page": 100},
            auth=(settings.censys_api_id, settings.censys_api_secret),
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for hit in data.get("result", {}).get("hits", []):
                for name in hit.get("parsed", {}).get("names", []):
                    name = name.lstrip("*.").lower()
                    if name.endswith(domain):
                        found.add(name)
    except Exception as e:
        console.print(f"[yellow]Censys error: {e}[/yellow]")
    console.print(f"[green]Censys:[/green] {len(found)} subdomains")
    return found


async def run_passive(domain: str) -> set[str]:
    """Run all passive sources concurrently and return combined results."""
    all_found: set[str] = set()
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        results = await asyncio.gather(
            query_crtsh(domain, client),
            query_virustotal(domain, client),
            query_securitytrails(domain, client),
            query_shodan(domain, client),
            query_urlscan(domain, client),
            query_wayback_subdomains(domain, client),
            query_github(domain, client),
            query_censys(domain, client),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, set):
                all_found.update(result)
    # Always include the apex domain itself
    all_found.add(domain)
    console.print(f"[bold green]Passive total:[/bold green] {len(all_found)} unique subdomains")
    return all_found
