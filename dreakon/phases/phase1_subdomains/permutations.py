"""
Permutation engine: mutate confirmed subdomains to discover neighbors.
"""
import itertools
import re

ENVS = ["dev", "development", "staging", "stage", "stg", "prod", "production",
        "test", "testing", "uat", "qa", "sandbox", "demo", "preview", "preprod"]

PREFIXES = ["api", "admin", "app", "web", "mail", "smtp", "ftp", "vpn", "cdn",
            "static", "assets", "media", "img", "images", "portal", "dashboard",
            "internal", "intranet", "corp", "secure", "auth", "login", "sso",
            "gateway", "proxy", "beta", "legacy", "old", "new", "v1", "v2", "v3"]

REGIONS = ["us", "eu", "ap", "sg", "uk", "ca", "au", "us-east", "us-west",
           "eu-west", "ap-southeast", "us-east-1", "us-west-2"]

SEPARATORS = ["-", "."]

NUMBER_LIMIT = 10


def _get_parts(subdomain: str, domain: str) -> list[str]:
    """Return the subdomain prefix parts (strip the base domain)."""
    if subdomain == domain:
        return []
    prefix = subdomain[: -(len(domain) + 1)]
    return prefix.split(".")


def generate_permutations(confirmed_subdomains: set[str], domain: str) -> set[str]:
    """Generate candidate subdomains by mutating confirmed ones."""
    candidates: set[str] = set()

    for sub in confirmed_subdomains:
        if sub == domain:
            continue
        parts = _get_parts(sub, domain)
        if not parts:
            continue

        for part in parts:
            # Number increment/decrement
            match = re.search(r"(\d+)$", part)
            if match:
                num = int(match.group(1))
                base = part[: match.start()]
                for n in range(max(0, num - 2), num + NUMBER_LIMIT):
                    candidates.add(f"{base}{n}.{domain}")

            # Environment substitution
            for env in ENVS:
                if part in ENVS:
                    candidates.add(f"{env}.{domain}")
                    for sep in SEPARATORS:
                        for prefix in parts:
                            if prefix != part:
                                candidates.add(f"{env}{sep}{prefix}.{domain}")
                                candidates.add(f"{prefix}{sep}{env}.{domain}")

            # Region suffix
            for region in REGIONS:
                for sep in SEPARATORS:
                    candidates.add(f"{part}{sep}{region}.{domain}")

            # Common prefix additions
            for prefix in PREFIXES:
                for sep in SEPARATORS:
                    candidates.add(f"{prefix}{sep}{part}.{domain}")
                    candidates.add(f"{part}{sep}{prefix}.{domain}")

        # Add all standard prefixes as direct subdomains
        for prefix in PREFIXES:
            candidates.add(f"{prefix}.{domain}")

        for env in ENVS:
            candidates.add(f"{env}.{domain}")

    # Remove already-confirmed and the bare domain
    candidates -= confirmed_subdomains
    candidates.discard(domain)
    return candidates
