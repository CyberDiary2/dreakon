"""
JavaScript endpoint extraction.
Handles minified bundles, webpack chunks, source maps, and inline scripts.
"""
import asyncio
import re
import json
from urllib.parse import urljoin, urlparse
import httpx
from rich.console import Console
from ...core.config import settings

console = Console()

# Patterns for extracting URLs and paths from JS
PATTERNS = [
    # Fetch/axios/XHR calls
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    # String literals that look like API paths
    re.compile(r'["\'](/(?:api|v\d+|graphql|rest|service|endpoint)[^\s"\'<>]*)["\']', re.IGNORECASE),
    # General path-like string literals
    re.compile(r'["\'](/[a-zA-Z0-9_\-./]{3,})["\']'),
    # URL construction patterns: baseUrl + "/path"
    re.compile(r'[\+`]\s*["\'](/[a-zA-Z0-9_\-./]+)["\']'),
    # Template literals: `${base}/users`
    re.compile(r'`[^`]*\$\{[^}]+\}(/[a-zA-Z0-9_\-./]+)`'),
    # process.env references (may reveal staging URLs)
    re.compile(r'process\.env\.[A-Z_]+\s*[=:]\s*["\']([^"\']+)["\']'),
    # Absolute URLs
    re.compile(r'["\']https?://[^\s"\'<>]{10,}["\']'),
]

# Webpack chunk manifest pattern
WEBPACK_CHUNK_RE = re.compile(
    r'(?:webpackJsonp|__webpack_require__|chunkId)\b.*?(?:\.js["\'])',
    re.DOTALL
)


def extract_endpoints_from_js(content: str, base_url: str) -> set[str]:
    """Extract all potential endpoints from JS content."""
    found: set[str] = set()
    base_parsed = urlparse(base_url)
    base = f"{base_parsed.scheme}://{base_parsed.netloc}"

    for pattern in PATTERNS:
        for match in pattern.finditer(content):
            url = match.group(1).strip()
            if url.startswith("http"):
                found.add(url)
            elif url.startswith("/"):
                found.add(urljoin(base, url))

    return found


def extract_subdomains_from_js(content: str, domain: str) -> set[str]:
    """Find any subdomains of the target domain referenced in JS."""
    found: set[str] = set()
    pattern = re.compile(
        r'["\'](?:https?://)?([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.' + re.escape(domain) + r')["\'/]',
        re.IGNORECASE
    )
    for match in pattern.finditer(content):
        found.add(match.group(1).lower())
    return found


async def fetch_and_parse_js(url: str, client: httpx.AsyncClient, domain: str) -> tuple[set[str], set[str]]:
    """Fetch a JS file and extract (endpoints, new_subdomains)."""
    endpoints: set[str] = set()
    subdomains: set[str] = set()

    try:
        r = await client.get(url, timeout=settings.http_timeout)
        if r.status_code != 200:
            return endpoints, subdomains

        content = r.text
        base = url
        endpoints.update(extract_endpoints_from_js(content, base))
        subdomains.update(extract_subdomains_from_js(content, domain))

        # Try to fetch source map
        source_map_url = url + ".map"
        try:
            mr = await client.get(source_map_url, timeout=5)
            if mr.status_code == 200:
                map_data = mr.json()
                # Source map contains original source files and their content
                for source_content in map_data.get("sourcesContent", []):
                    if source_content:
                        endpoints.update(extract_endpoints_from_js(source_content, base))
                        subdomains.update(extract_subdomains_from_js(source_content, domain))
                console.print(f"[bold yellow]Source map found:[/bold yellow] {source_map_url}")
        except Exception:
            pass

        # Detect webpack and extract chunk URLs
        if "__webpack_require__" in content or "webpackJsonp" in content:
            chunk_urls = extract_webpack_chunks(content, url)
            for chunk_url in chunk_urls:
                try:
                    cr = await client.get(chunk_url, timeout=settings.http_timeout)
                    if cr.status_code == 200:
                        endpoints.update(extract_endpoints_from_js(cr.text, base))
                        subdomains.update(extract_subdomains_from_js(cr.text, domain))
                except Exception:
                    pass

    except Exception as e:
        pass

    return endpoints, subdomains


def extract_webpack_chunks(content: str, base_url: str) -> list[str]:
    """Extract webpack chunk URLs from a bundle."""
    chunks: list[str] = []
    base = "/".join(base_url.split("/")[:-1]) + "/"

    # Match chunk id maps: {0:"abc123", 1:"def456"}
    chunk_map_re = re.compile(r'\{(\d+:"[a-f0-9]+",?\s*)+\}')
    hash_re = re.compile(r'"([a-f0-9]{8,})"')

    for m in chunk_map_re.finditer(content):
        for hash_match in hash_re.finditer(m.group(0)):
            chunk_hash = hash_match.group(1)
            chunks.append(f"{base}{chunk_hash}.js")

    return chunks[:50]  # Cap to avoid runaway


async def analyze_js_files(js_urls: list[str], domain: str) -> tuple[set[str], set[str]]:
    """Analyze all collected JS files. Returns (all_endpoints, new_subdomains)."""
    all_endpoints: set[str] = set()
    all_subdomains: set[str] = set()

    async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                  headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}) as client:
        tasks = [fetch_and_parse_js(url, client, domain) for url in set(js_urls)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, tuple):
            endpoints, subdomains = result
            all_endpoints.update(endpoints)
            all_subdomains.update(subdomains)

    console.print(f"[bold green]JS analysis:[/bold green] {len(all_endpoints)} endpoints, {len(all_subdomains)} new subdomains")
    return all_endpoints, all_subdomains
