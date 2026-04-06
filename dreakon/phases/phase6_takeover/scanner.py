"""
Phase 6: Subdomain Takeover Scanner
Receives already-enumerated subdomains from dreakon phases 1-2
and checks for takeover candidates using STAB fingerprints.
"""
import asyncio
import socket

import dns.resolver
import httpx

CNAME_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.com"],
        "http_body": ["There isn't a GitHub Pages site here"],
        "http_status": [404],
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokudns.com", "herokussl.com", "herokuapp.com"],
        "http_body": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "http_status": [404],
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.com", "netlify.app"],
        "http_body": ["Not Found - Request ID"],
        "http_status": [404],
    },
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "http_body": ["NoSuchBucket", "The specified bucket does not exist"],
        "http_status": [404],
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "http_body": ["Fastly error: unknown domain"],
        "http_status": [404],
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "http_body": ["Sorry, this shop is currently unavailable"],
        "http_status": [404],
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["tumblr.com"],
        "http_body": ["Whatever you were looking for doesn't currently exist at this address"],
        "http_status": [404],
    },
    {
        "service": "WordPress",
        "cname_patterns": ["wordpress.com"],
        "http_body": ["Do you want to register"],
        "http_status": [404],
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "http_body": ["project not found"],
        "http_status": [404],
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "http_body": ["Help Center Closed"],
        "http_status": [404],
    },
    {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.net", "hubspotpagebuilder.com"],
        "http_body": ["Domain not found"],
        "http_status": [404],
    },
    {
        "service": "Azure",
        "cname_patterns": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "http_body": ["404 Web Site not found"],
        "http_status": [404],
    },
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "vercel.com"],
        "http_body": ["The deployment could not be found"],
        "http_status": [404],
    },
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev"],
        "http_body": ["404 Not Found"],
        "http_status": [404],
    },
]

S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1", "ap-south-1",
]


async def resolve_cname(subdomain: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(subdomain, "CNAME")
        )
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


async def resolve_ns(subdomain: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(subdomain, "NS")
        )
        return [str(r.target).rstrip(".") for r in answers]
    except Exception:
        return []


async def check_http_fingerprint(subdomain: str, cnames: list[str], client: httpx.AsyncClient) -> dict | None:
    for fp in CNAME_FINGERPRINTS:
        if not any(pat in cname for cname in cnames for pat in fp["cname_patterns"]):
            continue
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{subdomain}", timeout=10, follow_redirects=True)
                body = r.text.lower()
                status_match = r.status_code in fp["http_status"]
                body_match = any(sig.lower() in body for sig in fp["http_body"])
                if status_match or body_match:
                    return {
                        "type": "cname_takeover",
                        "service": fp["service"],
                        "cname": cnames,
                        "http_status": r.status_code,
                        "evidence": next((s for s in fp["http_body"] if s.lower() in body), None),
                    }
            except Exception:
                continue
    return None


async def check_s3(subdomain: str, client: httpx.AsyncClient) -> dict | None:
    bucket_name = subdomain.split(".")[0]
    for region in S3_REGIONS:
        url = f"https://{bucket_name}.s3.{region}.amazonaws.com"
        try:
            r = await client.get(url, timeout=8)
            if r.status_code == 404 and "NoSuchBucket" in r.text:
                return {
                    "type": "s3_takeover",
                    "service": "AWS S3",
                    "bucket": bucket_name,
                    "region": region,
                    "evidence": "NoSuchBucket",
                }
        except Exception:
            continue
    return None


async def check_ns(subdomain: str) -> dict | None:
    ns_records = await resolve_ns(subdomain)
    for ns in ns_records:
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, ns)
        except socket.gaierror:
            return {
                "type": "ns_takeover",
                "service": "NS",
                "ns_record": ns,
                "evidence": f"NS record {ns} does not resolve",
            }
    return None


async def check_subdomain(subdomain: str, client: httpx.AsyncClient) -> dict | None:
    cnames = await resolve_cname(subdomain)
    if cnames:
        result = await check_http_fingerprint(subdomain, cnames, client)
        if result:
            return {**result, "subdomain": subdomain}

    s3 = await check_s3(subdomain, client)
    if s3:
        return {**s3, "subdomain": subdomain}

    ns = await check_ns(subdomain)
    if ns:
        return {**ns, "subdomain": subdomain}

    return None


async def run_takeover_scan(subdomains: set[str], concurrency: int = 20) -> list[dict]:
    findings = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        async def bounded_check(sub: str):
            async with semaphore:
                result = await check_subdomain(sub, client)
                if result:
                    findings.append(result)

        await asyncio.gather(*[bounded_check(s) for s in subdomains])

    return findings
