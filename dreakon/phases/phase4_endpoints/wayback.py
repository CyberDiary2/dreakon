"""
Historical endpoint discovery: Wayback Machine, Common Crawl, AlienVault OTX, URLScan.
"""
import asyncio
from urllib.parse import urlparse
import httpx
from rich.console import Console
from ...core.config import settings

console = Console()


async def query_wayback(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Fetch all archived URLs for a domain from Wayback CDX API."""
    urls: set[str] = set()
    try:
        r = await client.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": 50000,
            },
            timeout=60,
        )
        if r.status_code == 200:
            data = r.json()
            for row in data[1:]:  # skip header
                try:
                    urls.add(row[0])
                except (IndexError, TypeError):
                    pass
    except Exception as e:
        console.print(f"[yellow]Wayback error: {e}[/yellow]")
    console.print(f"[green]Wayback:[/green] {len(urls)} historical URLs")
    return urls


async def query_commoncrawl(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Query the most recent Common Crawl index."""
    urls: set[str] = set()
    try:
        # Get the latest index
        idx_r = await client.get("https://index.commoncrawl.org/collinfo.json", timeout=15)
        if idx_r.status_code != 200:
            return urls
        indexes = idx_r.json()
        latest = indexes[0]["cdx-api"]

        r = await client.get(
            latest,
            params={"url": f"*.{domain}/*", "output": "json", "limit": 10000},
            timeout=60,
        )
        if r.status_code == 200:
            for line in r.text.strip().splitlines():
                try:
                    import json
                    data = json.loads(line)
                    url = data.get("url", "")
                    if url:
                        urls.add(url)
                except Exception:
                    pass
    except Exception as e:
        console.print(f"[yellow]Common Crawl error: {e}[/yellow]")
    console.print(f"[green]Common Crawl:[/green] {len(urls)} historical URLs")
    return urls


async def query_otx(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Query AlienVault OTX for URL history."""
    urls: set[str] = set()
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            params={"limit": 500, "page": 1},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for entry in data.get("url_list", []):
                url = entry.get("url", "")
                if url:
                    urls.add(url)
    except Exception as e:
        console.print(f"[yellow]OTX error: {e}[/yellow]")
    console.print(f"[green]OTX:[/green] {len(urls)} historical URLs")
    return urls


async def query_urlscan_endpoints(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Extract all request URLs from URLScan page scans."""
    urls: set[str] = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    if settings.urlscan_api_key:
        headers["API-Key"] = settings.urlscan_api_key
    try:
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{domain}", "size": 100},
            headers=headers,
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            for result in data.get("results", []):
                # Get the full scan result for network requests
                scan_url = result.get("result", "")
                if scan_url:
                    try:
                        sr = await client.get(scan_url, timeout=10)
                        if sr.status_code == 200:
                            scan_data = sr.json()
                            for req in scan_data.get("data", {}).get("requests", []):
                                url = req.get("request", {}).get("url", "")
                                if url and domain in url:
                                    urls.add(url)
                    except Exception:
                        pass
    except Exception as e:
        console.print(f"[yellow]URLScan endpoints error: {e}[/yellow]")
    console.print(f"[green]URLScan endpoints:[/green] {len(urls)} URLs")
    return urls


def extract_paths(urls: set[str], domain: str) -> set[str]:
    """Normalize and deduplicate paths from a set of URLs, filtering to domain."""
    paths: set[str] = set()
    for url in urls:
        try:
            p = urlparse(url)
            if p.hostname and p.hostname.endswith(domain):
                path = p.path
                if path and path != "/":
                    paths.add(url)  # Keep full URL for endpoint tracking
        except Exception:
            pass
    return paths


async def run_historical(domain: str) -> set[str]:
    """Run all historical sources and return unique URLs."""
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        results = await asyncio.gather(
            query_wayback(domain, client),
            query_commoncrawl(domain, client),
            query_otx(domain, client),
            query_urlscan_endpoints(domain, client),
            return_exceptions=True,
        )

    all_urls: set[str] = set()
    for r in results:
        if isinstance(r, set):
            all_urls.update(r)

    filtered = extract_paths(all_urls, domain)
    console.print(f"[bold green]Historical total:[/bold green] {len(filtered)} unique URLs for {domain}")
    return filtered
