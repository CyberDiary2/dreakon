"""
Orchestrator: coordinates all phases, handles re-feed loops via the event bus.

Re-feed loops:
  - JS analysis finds new subdomains → re-enter Phase 2+3+4
  - TLS cert SANs reveal new subdomains → re-enter Phase 2+3+4
  - Historical URLs reference unknown subdomains → re-enter Phase 2
"""
import asyncio
import json
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from .db import init_db, AsyncSessionLocal
from .config import settings
from .events import bus, EventType
from ..phases.phase1_subdomains.passive import run_passive
from ..phases.phase1_subdomains.bruteforce import brute_force
from ..phases.phase1_subdomains.permutations import generate_permutations
from ..phases.phase2_dns.resolver import resolve_all, DnsResult
from ..phases.phase3_http.prober import probe_all, HttpProbeResult
from ..phases.phase4_endpoints.crawler import crawl_target
from ..phases.phase4_endpoints.js_parser import analyze_js_files
from ..phases.phase4_endpoints.wayback import run_historical
from ..phases.phase4_endpoints.openapi import discover_api_specs
from ..phases.phase4_endpoints.fuzzer import run_fuzzer
from ..phases.phase5_output.exporter import export_all
from ..phases.phase5_output.screenshotter import screenshot_urls
from ..phases.phase6_takeover.scanner import run_takeover_scan

console = Console()


class ReconOrchestrator:
    def __init__(
        self,
        domain: str,
        output_dir: str = ".",
        skip_fuzz: bool = False,
        skip_brute: bool = False,
        skip_screenshots: bool = False,
        skip_takeover: bool = False,
        skip_dns: bool = False,
        skip_http: bool = False,
        skip_endpoints: bool = False,
        skip_output: bool = False,
    ):
        self.domain = domain
        self.output_dir = output_dir
        self.skip_fuzz = skip_fuzz
        self.skip_brute = skip_brute
        self.skip_screenshots = skip_screenshots
        self.skip_takeover = skip_takeover
        self.skip_dns = skip_dns
        self.skip_http = skip_http
        self.skip_endpoints = skip_endpoints
        self.skip_output = skip_output

        # State
        self.all_subdomains: set[str] = set()
        self.resolved_subdomains: set[str] = set()
        self.dns_results: list[DnsResult] = []
        self.http_results: list[HttpProbeResult] = []
        self.all_endpoints: list[dict] = []
        self.all_js_urls: list[str] = []
        self.all_findings: list[dict] = []
        self.processed_subdomains: set[str] = set()

    async def run(self):
        await init_db()
        start = datetime.utcnow()
        console.print(f"\n[bold magenta]dreakon[/bold magenta] starting recon on [bold]{self.domain}[/bold]\n")

        # Phase 1: Subdomain enumeration
        console.rule("[bold cyan]phase 1: subdomain enumeration[/bold cyan]")
        passive_subs = await run_passive(self.domain)
        self.all_subdomains.update(passive_subs)

        if not self.skip_brute:
            brute_subs = await brute_force(self.domain)
            self.all_subdomains.update(brute_subs)

        perm_subs = generate_permutations(self.all_subdomains, self.domain)
        console.print(f"[cyan]Permutations:[/cyan] {len(perm_subs)} candidates generated")
        self.all_subdomains.update(perm_subs)

        console.print(f"[bold cyan]Phase 1 total:[/bold cyan] {len(self.all_subdomains)} candidates\n")

        # Phase 2 + 3 initial pass
        await self._run_phases_2_and_3(self.all_subdomains)

        # Phase 4: Endpoint discovery
        console.rule("[bold blue]phase 4: endpoint discovery[/bold blue]")

        live_base_urls = self._get_live_base_urls()
        console.print(f"[blue]Live base URLs for crawling:[/blue] {len(live_base_urls)}")

        # Crawl
        for base_url in live_base_urls:
            host = urlparse(base_url).hostname or self.domain
            crawl_results = await crawl_target(base_url, self.domain)
            for cr in crawl_results:
                self.all_endpoints.append({
                    "url": cr.url,
                    "method": "GET",
                    "source": "crawl",
                    "status_code": cr.status_code,
                })
                self.all_js_urls.extend(cr.scripts)

        # JS analysis (with re-feed)
        js_endpoints, js_new_subs = await analyze_js_files(self.all_js_urls, self.domain)
        for ep in js_endpoints:
            self.all_endpoints.append({"url": ep, "method": "GET", "source": "js_analysis"})

        if js_new_subs:
            new_subs = js_new_subs - self.all_subdomains
            console.print(f"[bold yellow]Re-feed:[/bold yellow] JS analysis found {len(new_subs)} new subdomains")
            self.all_subdomains.update(new_subs)
            await self._run_phases_2_and_3(new_subs)

        # Historical data
        historical_urls = await run_historical(self.domain)
        for url in historical_urls:
            self.all_endpoints.append({"url": url, "method": "GET", "source": "historical"})

        # Extract new subdomains from historical URLs
        hist_new_subs = set()
        for url in historical_urls:
            try:
                host = urlparse(url).hostname or ""
                if host.endswith(self.domain) and host not in self.all_subdomains:
                    hist_new_subs.add(host)
            except Exception:
                pass
        if hist_new_subs:
            console.print(f"[bold yellow]Re-feed:[/bold yellow] Historical data found {len(hist_new_subs)} new subdomains")
            self.all_subdomains.update(hist_new_subs)
            await self._run_phases_2_and_3(hist_new_subs)

        # API spec discovery
        all_live_urls = [r.final_url for r in self.http_results if r.final_url and r.status_code]
        spec_results = await discover_api_specs(all_live_urls, self.domain)
        for spec in spec_results:
            self.all_endpoints.append({
                "url": spec["url"],
                "method": spec.get("method", "GET"),
                "source": spec.get("source", "spec"),
                "status_code": spec.get("status"),
                "notes": spec.get("notes"),
            })
            # Expand OpenAPI paths
            for ep in spec.get("openapi_endpoints", []):
                self.all_endpoints.append(ep)

        # Fuzzer (optional)
        if not self.skip_fuzz:
            fuzz_targets = [
                {"url": r.final_url, "tech_stack": r.tech_stack}
                for r in self.http_results
                if r.final_url and r.status_code and r.tech_stack
            ]
            fuzz_results = await run_fuzzer(fuzz_targets)
            for fr in fuzz_results:
                self.all_endpoints.append({
                    "url": fr["url"],
                    "method": fr["method"],
                    "source": "fuzz",
                    "status_code": fr["status"],
                })

        # Deduplicate endpoints
        seen_urls: set[str] = set()
        unique_endpoints = []
        for ep in self.all_endpoints:
            url = ep.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_endpoints.append(ep)
        self.all_endpoints = unique_endpoints

        # Collect findings (takeovers, etc.)
        self._collect_findings()

        # Phase 6: Subdomain takeover scan
        if not self.skip_takeover:
            console.rule("[bold red]phase 6: subdomain takeover scan[/bold red]")
            console.print(f"[dim]checking {len(self.all_subdomains)} subdomains for takeover...[/dim]")
            takeover_findings = await run_takeover_scan(self.all_subdomains)
            for f in takeover_findings:
                self.all_findings.append({
                    "type": f["type"],
                    "severity": "high",
                    "url": f["subdomain"],
                    "detail": f"{f['service']} - {f.get('evidence') or f.get('ns_record') or f.get('bucket') or ''}",
                    "evidence": str(f),
                })
            console.print(f"[bold red]phase 6 total:[/bold red] {len(takeover_findings)} takeover candidate(s)\n")

        # Phase 5: Output
        console.rule("[bold green]phase 5: output[/bold green]")
        subdomain_dicts = self._build_subdomain_dicts()
        paths = export_all(
            domain=self.domain,
            subdomains=subdomain_dicts,
            endpoints=self.all_endpoints,
            findings=self.all_findings,
            output_dir=self.output_dir,
        )

        # Screenshots
        screenshots_dir = None
        if not self.skip_screenshots:
            from pathlib import Path as _Path
            live_urls = list(self._get_live_base_urls())
            console.print(f"[bold green]screenshots:[/bold green] capturing {len(live_urls)} live URLs")
            shots = await screenshot_urls(live_urls, _Path(self.output_dir))
            if shots:
                screenshots_dir = str(shots[0].parent)

        elapsed = (datetime.utcnow() - start).total_seconds()
        console.print(f"\n[bold green]done in {elapsed:.1f}s[/bold green]")
        console.print(f"  subdomains : {len(self.all_subdomains)}")
        console.print(f"  resolved   : {len(self.resolved_subdomains)}")
        console.print(f"  endpoints  : {len(self.all_endpoints)}")
        console.print(f"  findings   : {len(self.all_findings)}")
        console.print(f"\n  [cyan]jsonl   :[/cyan] {paths['jsonl']}")
        console.print(f"  [cyan]nuclei  :[/cyan] {paths['nuclei']}")
        console.print(f"  [cyan]report  :[/cyan] {paths['markdown']}")
        if screenshots_dir:
            console.print(f"  [cyan]screenshots:[/cyan] {screenshots_dir}")

    async def _run_phases_2_and_3(self, subdomains: set[str]):
        """Run DNS resolution and HTTP probing for a set of subdomains."""
        new_subs = subdomains - self.processed_subdomains
        if not new_subs:
            return
        self.processed_subdomains.update(new_subs)

        # Phase 2
        console.rule(f"[bold yellow]phase 2: dns resolution ({len(new_subs)} targets)[/bold yellow]")
        dns_results = await resolve_all(new_subs, self.domain)
        self.dns_results.extend(dns_results)

        newly_resolved = {r.fqdn for r in dns_results if r.resolved}
        self.resolved_subdomains.update(newly_resolved)

        # Cert SAN re-feed
        all_sans: set[str] = set()
        for r in dns_results:
            for san in r.cert_sans:
                if san.endswith(self.domain):
                    all_sans.add(san)
        san_new = all_sans - self.all_subdomains
        if san_new:
            console.print(f"[bold yellow]Re-feed:[/bold yellow] {len(san_new)} new subdomains from cert SANs")
            self.all_subdomains.update(san_new)

        # Check for takeover findings
        for r in dns_results:
            if r.takeover_candidate:
                self.all_findings.append({
                    "type": "subdomain_takeover",
                    "severity": "high",
                    "url": r.fqdn,
                    "detail": f"Possible takeover via {r.takeover_candidate}",
                    "evidence": str(r.records.get("CNAME", [])),
                })

        # Phase 3
        console.rule(f"[bold yellow]phase 3: http probing ({len(newly_resolved)} resolved)[/bold yellow]")
        http_results = await probe_all(newly_resolved)
        self.http_results.extend(http_results)

        # Cert SANs from HTTP probing
        for r in http_results:
            for san in r.cert_sans:
                if san.endswith(self.domain) and san not in self.all_subdomains:
                    self.all_subdomains.add(san)
                    console.print(f"[yellow]Re-feed (HTTP cert SAN):[/yellow] {san}")

        # Add live HTTP responses as initial endpoints
        for r in http_results:
            if r.final_url and r.status_code:
                self.all_endpoints.append({
                    "url": r.final_url,
                    "method": "GET",
                    "source": "http_probe",
                    "status_code": r.status_code,
                    "tech_stack": r.tech_stack,
                })

    def _get_live_base_urls(self) -> list[str]:
        seen: set[str] = set()
        urls = []
        for r in self.http_results:
            if r.final_url and r.status_code and r.status_code < 500:
                parsed = urlparse(r.final_url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                if base not in seen:
                    seen.add(base)
                    urls.append(base)
        return urls

    def _build_subdomain_dicts(self) -> list[dict]:
        dns_map = {r.fqdn: r for r in self.dns_results}
        http_map: dict[str, list[HttpProbeResult]] = {}
        for r in self.http_results:
            http_map.setdefault(r.fqdn, []).append(r)

        result = []
        for sub in sorted(self.all_subdomains):
            dns = dns_map.get(sub)
            http_list = http_map.get(sub, [])
            tech_stack = []
            for hr in http_list:
                tech_stack.extend(hr.tech_stack)

            result.append({
                "fqdn": sub,
                "resolved": sub in self.resolved_subdomains,
                "source": dns.cert_sans[0] if dns and dns.cert_sans else "passive",
                "tech_stack": list(set(tech_stack)),
                "records": dns.records if dns else {},
            })
        return result

    def _collect_findings(self):
        """Scan collected data for interesting security findings."""
        seen_urls: set[str] = set()

        for ep in self.all_endpoints:
            url = ep.get("url", "")
            status = ep.get("status_code")
            if not url or url in seen_urls:
                continue

            url_lower = url.lower()

            # Exposed admin panels
            if any(p in url_lower for p in ["/admin", "/administrator", "/wp-admin", "/phpmyadmin"]):
                if status in (200, 301, 302):
                    seen_urls.add(url)
                    self.all_findings.append({
                        "type": "exposed_admin",
                        "severity": "medium",
                        "url": url,
                        "detail": f"Admin panel accessible (HTTP {status})",
                    })

            # Exposed debug/config
            if any(p in url_lower for p in ["/.env", "/.git/config", "/debug", "/actuator/env", "/h2-console"]):
                if status == 200:
                    seen_urls.add(url)
                    self.all_findings.append({
                        "type": "sensitive_exposure",
                        "severity": "high",
                        "url": url,
                        "detail": f"Sensitive path exposed (HTTP {status})",
                    })

            # GraphQL
            if "graphql" in url_lower and status == 200:
                seen_urls.add(url)
                self.all_findings.append({
                    "type": "graphql_endpoint",
                    "severity": "info",
                    "url": url,
                    "detail": "GraphQL endpoint found",
                })
