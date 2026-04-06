"""
Phase 7: Cloud footprint mapping (powered by DRACO).
Runs AWS, Azure, GCP, and intel scans against the target domain.
"""
import asyncio

import httpx

# AWS regions to check
S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1", "ap-south-1",
]

PREFIXES = [
    "dev", "prod", "staging", "test", "backup", "static", "assets",
    "media", "cdn", "files", "uploads", "data", "api", "app", "admin",
]

SUFFIXES = [
    "dev", "prod", "staging", "test", "backup", "static", "assets",
    "media", "cdn", "files", "uploads", "data", "api", "app", "bucket",
    "store", "storage", "s3", "blob",
]


def generate_candidates(domain: str) -> list[str]:
    parts = domain.split(".")
    base = parts[-2] if len(parts) >= 2 else parts[0]
    candidates = {base, domain.replace(".", "-"), domain.replace(".", "")}
    for p in PREFIXES:
        candidates.add(f"{p}-{base}")
        candidates.add(f"{base}-{p}")
    for s in SUFFIXES:
        candidates.add(f"{base}-{s}")
    return sorted(candidates)


async def _check(url: str, client: httpx.AsyncClient) -> int | None:
    try:
        r = await client.get(url, timeout=7)
        return r.status_code
    except Exception:
        return None


async def run_cloud_scan(domain: str, concurrency: int = 20) -> list[dict]:
    """Run full cloud footprint scan. Returns findings list."""
    from draco.core.aws import run_aws_scan
    from draco.core.azure import run_azure_scan
    from draco.core.gcp import run_gcp_scan
    from draco.core.intel import run_intel_scan
    from draco.core.permutations import generate

    candidates = generate(domain)
    aws, azure, gcp, intel = await asyncio.gather(
        run_aws_scan(domain, candidates, concurrency=concurrency),
        run_azure_scan(candidates, concurrency=concurrency),
        run_gcp_scan(candidates, concurrency=concurrency),
        run_intel_scan(domain),
    )
    return aws + azure + gcp + intel
