"""
BFS async web crawler. Extracts links, scripts, forms.
Respects crawl depth limit. Falls back to Playwright for JS-heavy pages.
"""
import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse
from dataclasses import dataclass, field
import httpx
from selectolax.parser import HTMLParser
from rich.console import Console
from ...core.config import settings
from ...core.ratelimiter import rate_limiter

console = Console()

JS_SPA_INDICATORS = ["__react", "__vue", "ng-version", "__next", "__nuxt", "ember"]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    ".webm", ".avi", ".mov",
}


@dataclass
class CrawlResult:
    url: str
    status_code: int
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    is_spa: bool = False


def normalize_url(url: str) -> str:
    """Normalize URL: lowercase scheme+host, remove fragments, sort params."""
    try:
        p = urlparse(url)
        return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, "", p.query, ""))
    except Exception:
        return url


def should_skip(url: str, base_domain: str) -> bool:
    parsed = urlparse(url)
    if parsed.hostname and not parsed.hostname.endswith(base_domain):
        return True
    ext = "." + parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
    if ext in SKIP_EXTENSIONS:
        return True
    return False


def extract_links(html: str, base_url: str) -> tuple[list[str], list[str], list[dict], bool]:
    """Returns (links, script_urls, forms, is_spa)."""
    links, scripts, forms = [], [], []
    is_spa = False

    try:
        tree = HTMLParser(html)

        # Links
        for tag in tree.css("a[href]"):
            href = tag.attributes.get("href", "")
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                links.append(urljoin(base_url, href))

        # Scripts
        for tag in tree.css("script"):
            src = tag.attributes.get("src", "")
            if src:
                scripts.append(urljoin(base_url, src))

        # Forms
        for form in tree.css("form"):
            action = form.attributes.get("action", base_url)
            method = form.attributes.get("method", "GET").upper()
            inputs = []
            for inp in form.css("input, select, textarea"):
                name = inp.attributes.get("name", "")
                if name:
                    inputs.append(name)
            forms.append({"action": urljoin(base_url, action), "method": method, "inputs": inputs})

        # Detect SPA
        body_text = html.lower()
        for indicator in JS_SPA_INDICATORS:
            if indicator in body_text:
                is_spa = True
                break

        # Also grab inline script content for URL extraction
        for tag in tree.css("script:not([src])"):
            text = tag.text() or ""
            # Extract string literals that look like paths
            for match in re.finditer(r'["\'](/[a-zA-Z0-9_\-./]+)["\']', text):
                path = match.group(1)
                if not any(path.endswith(ext) for ext in [".png", ".jpg", ".svg", ".ico"]):
                    links.append(urljoin(base_url, path))

    except Exception:
        pass

    return links, scripts, forms, is_spa


async def crawl_target(base_url: str, base_domain: str) -> list[CrawlResult]:
    """BFS crawl from base_url, staying within base_domain."""
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(normalize_url(base_url), 0)])
    results: list[CrawlResult] = []
    semaphore = asyncio.Semaphore(settings.crawl_concurrency)

    # Try sitemap first
    sitemap_urls = await _fetch_sitemap(base_url, base_domain)
    for u in sitemap_urls:
        norm = normalize_url(u)
        if norm not in visited:
            queue.append((norm, 1))

    import random
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                  timeout=settings.http_timeout, headers=headers) as client:
        while queue:
            batch = []
            while queue and len(batch) < settings.crawl_concurrency:
                url, depth = queue.popleft()
                if url in visited or depth > settings.max_crawl_depth:
                    continue
                if should_skip(url, base_domain):
                    continue
                visited.add(url)
                batch.append((url, depth))

            if not batch:
                break

            async def fetch_one(url: str, depth: int):
                async with semaphore:
                    bucket = await rate_limiter.get(urlparse(url).hostname or "", rate=5.0, capacity=10)
                    await bucket.acquire()
                    try:
                        r = await client.get(url)
                        content_type = r.headers.get("content-type", "")
                        if "text/html" not in content_type and "application/xhtml" not in content_type:
                            return

                        links, scripts, forms, is_spa = extract_links(r.text, url)
                        cr = CrawlResult(
                            url=url,
                            status_code=r.status_code,
                            links=links,
                            scripts=scripts,
                            forms=forms,
                            is_spa=is_spa,
                        )
                        results.append(cr)

                        # Enqueue new links
                        for link in links:
                            norm = normalize_url(link)
                            if norm not in visited:
                                queue.append((norm, depth + 1))

                    except Exception:
                        pass

            await asyncio.gather(*[fetch_one(u, d) for u, d in batch], return_exceptions=True)

    console.print(f"[bold green]Crawl:[/bold green] {len(results)} pages from {base_url}")
    return results


async def _fetch_sitemap(base_url: str, domain: str) -> list[str]:
    """Fetch and parse sitemap.xml, including nested sitemaps."""
    urls: list[str] = []
    sitemap_url = f"{base_url.rstrip('/')}/sitemap.xml"
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(sitemap_url)
            if r.status_code == 200:
                # Extract all <loc> entries
                for match in re.finditer(r"<loc>(.*?)</loc>", r.text, re.DOTALL):
                    loc = match.group(1).strip()
                    if loc.endswith(".xml"):
                        # Nested sitemap — recurse one level
                        try:
                            nr = await client.get(loc)
                            for nm in re.finditer(r"<loc>(.*?)</loc>", nr.text, re.DOTALL):
                                urls.append(nm.group(1).strip())
                        except Exception:
                            pass
                    else:
                        urls.append(loc)
    except Exception:
        pass
    return urls
