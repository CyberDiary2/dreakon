"""
Path fuzzer: technology-aware wordlist-based path discovery.
"""
import asyncio
import random
from urllib.parse import urljoin, urlparse
import httpx
from pybloom_live import BloomFilter
from rich.console import Console
from ...core.config import settings
from ...core.ratelimiter import rate_limiter

console = Console()

# Technology-specific paths
TECH_WORDLISTS: dict[str, list[str]] = {
    "spring": [
        "actuator", "actuator/health", "actuator/info", "actuator/env",
        "actuator/beans", "actuator/mappings", "actuator/threaddump",
        "actuator/heapdump", "actuator/loggers", "actuator/metrics",
        "h2-console", "swagger-ui.html", "v2/api-docs",
    ],
    "django": [
        "admin/", "admin/login/", "__debug__/", "api/schema/",
        "api/redoc/", "api/docs/",
    ],
    "rails": [
        "rails/info", "rails/info/properties", "rails/info/routes",
        "sidekiq", "sidekiq/queues", "letter_opener",
    ],
    "wordpress": [
        "wp-admin/", "wp-login.php", "wp-json/", "wp-json/wp/v2/users",
        "wp-json/wp/v2/posts", "xmlrpc.php", "wp-config.php.bak",
        "wp-content/debug.log",
    ],
    "laravel": [
        "_ignition/health-check", "horizon/api/stats",
        "telescope/requests", ".env", "storage/logs/laravel.log",
    ],
    "php": [
        "info.php", "phpinfo.php", "test.php", "config.php",
        "admin.php", "login.php", "install.php", "setup.php",
    ],
    "graphql": [
        "graphql", "graphql/console", "graphiql", "playground",
        "api/graphql", "v1/graphql",
    ],
}

# Generic wordlist (keep concise — heavy fuzzing is a last resort)
GENERIC_PATHS = [
    "admin", "api", "api/v1", "api/v2", "api/v3", "app",
    "login", "logout", "register", "signup", "dashboard",
    "users", "user", "profile", "account", "settings",
    "config", "configuration", "health", "healthz", "status",
    "metrics", "logs", "debug", "test", "dev", "staging",
    "backup", "old", "new", "v1", "v2", "internal",
    "private", "public", "static", "assets", "upload", "uploads",
    "download", "downloads", "files", "file", "export", "import",
    "docs", "documentation", "help", "support",
    "console", "manage", "management", "panel", "portal",
    "search", "query", "data", "info", "about",
    ".git/config", ".env", "server-status", "robots.txt",
]


def get_paths_for_tech(tech_stack: list[str]) -> list[str]:
    paths = list(GENERIC_PATHS)
    for tech in tech_stack:
        tech_lower = tech.lower()
        for key, wordlist in TECH_WORDLISTS.items():
            if key in tech_lower:
                paths.extend(wordlist)
    return list(set(paths))


async def fuzz_target(
    base_url: str,
    tech_stack: list[str],
    bloom: BloomFilter,
) -> list[dict]:
    """Fuzz a single base URL with tech-appropriate wordlist."""
    results = []
    paths = get_paths_for_tech(tech_stack)
    host = urlparse(base_url).hostname or base_url
    semaphore = asyncio.Semaphore(settings.fuzz_concurrency)

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                  timeout=settings.http_timeout, headers=headers) as client:

        async def check_path(path: str):
            url = urljoin(base_url.rstrip("/") + "/", path)
            if url in bloom:
                return
            bloom.add(url)

            async with semaphore:
                bucket = await rate_limiter.get(host, rate=3.0, capacity=5)
                await bucket.acquire()
                try:
                    r = await client.get(url)
                    # Interesting: anything that isn't a generic 404
                    if r.status_code not in (404, 410):
                        results.append({
                            "url": url,
                            "status": r.status_code,
                            "method": "GET",
                            "source": "fuzz",
                            "content_length": len(r.content),
                        })
                    await rate_limiter.record_success(host)
                except Exception:
                    await rate_limiter.record_error(host)

        await asyncio.gather(*[check_path(p) for p in paths], return_exceptions=True)

    interesting = [r for r in results if r["status"] not in (404, 410)]
    if interesting:
        console.print(f"[bold green]Fuzz {base_url}:[/bold green] {len(interesting)} interesting paths")
    return interesting


async def run_fuzzer(live_targets: list[dict]) -> list[dict]:
    """
    live_targets: list of {url, tech_stack} dicts from HTTP prober.
    """
    bloom = BloomFilter(capacity=1_000_000, error_rate=0.001)
    all_results: list[dict] = []

    for target in live_targets:
        results = await fuzz_target(
            target["url"],
            target.get("tech_stack", []),
            bloom,
        )
        all_results.extend(results)

    console.print(f"[bold green]Fuzzer total:[/bold green] {len(all_results)} interesting paths")
    return all_results
