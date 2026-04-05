"""
API specification discovery: OpenAPI/Swagger, GraphQL, WSDL, OIDC.
"""
import asyncio
import json
from urllib.parse import urljoin
import httpx
from rich.console import Console
from ...core.config import settings

console = Console()

OPENAPI_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml", "/openapi/v1/openapi.json",
    "/api-docs", "/api-docs.json", "/api/swagger.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs/openapi.json", "/docs/swagger.json",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/robots.txt",
]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]

GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { queryType { name } types { name kind fields { name } } } }"
}

WSDL_SUFFIXES = ["?wsdl", "?WSDL"]

SPRING_ACTUATOR_PATHS = [
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/beans", "/actuator/mappings", "/actuator/routes",
    "/actuator/httptrace", "/actuator/loggers", "/actuator/metrics",
    "/h2-console", "/heapdump",
]

DJANGO_PATHS = ["/admin/", "/__debug__/", "/api/schema/", "/api/redoc/"]

RAILS_PATHS = ["/rails/info", "/rails/info/properties", "/sidekiq", "/letter_opener"]

GENERIC_INTERESTING = [
    "/admin", "/admin/", "/administrator", "/wp-admin/", "/phpmyadmin/",
    "/config", "/config.json", "/config.yaml", "/settings.json",
    "/.env", "/.git/config", "/.git/HEAD", "/server-status", "/server-info",
    "/metrics", "/health", "/health/", "/healthz", "/ping", "/status",
    "/debug", "/trace", "/console", "/shell",
    "/api/v1/", "/api/v2/", "/api/v3/", "/api/",
]

ALL_SPEC_PATHS = (
    OPENAPI_PATHS + GRAPHQL_PATHS + SPRING_ACTUATOR_PATHS +
    DJANGO_PATHS + RAILS_PATHS + GENERIC_INTERESTING
)


def extract_endpoints_from_openapi(spec: dict, base_url: str) -> list[dict]:
    """Parse OpenAPI spec and return list of {url, method} dicts."""
    endpoints = []
    servers = spec.get("servers", [{"url": base_url}])
    base = servers[0].get("url", base_url) if servers else base_url

    for path, path_item in spec.get("paths", {}).items():
        for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
            if method in path_item:
                endpoints.append({
                    "url": urljoin(base, path),
                    "method": method.upper(),
                    "source": "openapi",
                })
    return endpoints


async def probe_spec_paths(base_url: str, client: httpx.AsyncClient) -> list[dict]:
    """Probe all known spec and interesting paths."""
    found = []

    async def check(path: str):
        url = urljoin(base_url, path)
        try:
            r = await client.get(url, timeout=settings.http_timeout)
            if r.status_code in (200, 201, 301, 302, 401, 403):
                result = {"url": url, "status": r.status_code, "source": "spec_probe"}

                # Parse OpenAPI if detected
                if r.status_code == 200 and any(k in url for k in ["swagger", "openapi", "api-docs"]):
                    try:
                        spec = r.json()
                        if "paths" in spec or "openapi" in spec or "swagger" in spec:
                            endpoints = extract_endpoints_from_openapi(spec, base_url)
                            result["openapi_endpoints"] = endpoints
                            console.print(f"[bold yellow]OpenAPI found:[/bold yellow] {url} ({len(endpoints)} endpoints)")
                    except Exception:
                        pass

                found.append(result)
        except Exception:
            pass

    semaphore = asyncio.Semaphore(10)

    async def bounded(path: str):
        async with semaphore:
            await check(path)

    await asyncio.gather(*[bounded(p) for p in ALL_SPEC_PATHS], return_exceptions=True)
    return found


async def probe_graphql(base_url: str, client: httpx.AsyncClient) -> list[dict]:
    """Probe for GraphQL endpoints and attempt introspection."""
    found = []
    for path in GRAPHQL_PATHS:
        url = urljoin(base_url, path)
        try:
            r = await client.post(url, json=GRAPHQL_INTROSPECTION, timeout=settings.http_timeout)
            if r.status_code in (200, 400):
                try:
                    data = r.json()
                    if "data" in data or "errors" in data:
                        types_found = 0
                        if "data" in data and "__schema" in (data["data"] or {}):
                            types_found = len(data["data"]["__schema"].get("types", []))
                        found.append({
                            "url": url,
                            "method": "POST",
                            "source": "graphql",
                            "notes": f"GraphQL endpoint, {types_found} types" if types_found else "GraphQL (introspection disabled)",
                        })
                        console.print(f"[bold yellow]GraphQL found:[/bold yellow] {url}")
                except Exception:
                    pass
        except Exception:
            pass
    return found


async def discover_api_specs(live_urls: list[str], domain: str) -> list[dict]:
    """Run spec discovery against all live base URLs."""
    all_found: list[dict] = []
    base_urls = list({f"{p.scheme}://{p.netloc}" for u in live_urls
                      if (p := __import__('urllib.parse', fromlist=['urlparse']).urlparse(u)).netloc})

    async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                  headers={"User-Agent": "Mozilla/5.0"}) as client:
        for base_url in base_urls:
            spec_results = await probe_spec_paths(base_url, client)
            graphql_results = await probe_graphql(base_url, client)
            all_found.extend(spec_results)
            all_found.extend(graphql_results)

    console.print(f"[bold green]API spec discovery:[/bold green] {len(all_found)} interesting paths found")
    return all_found
