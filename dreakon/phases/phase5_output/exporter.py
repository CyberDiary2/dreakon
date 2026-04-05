"""
Export run results to multiple formats: JSONL, Markdown report, Nuclei targets list.
"""
import json
from datetime import datetime
from pathlib import Path
from dataclasses import asdict


def _ts() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def export_jsonl(endpoints: list[dict], output_dir: Path, domain: str):
    path = output_dir / f"{domain}_{_ts()}_endpoints.jsonl"
    with open(path, "w") as f:
        for ep in endpoints:
            f.write(json.dumps(ep) + "\n")
    return path


def export_nuclei_targets(live_urls: list[str], output_dir: Path, domain: str) -> Path:
    """Plain URL list consumable by: nuclei -list targets.txt"""
    path = output_dir / f"{domain}_{_ts()}_nuclei_targets.txt"
    path.write_text("\n".join(sorted(set(live_urls))) + "\n")
    return path


def export_markdown(
    domain: str,
    subdomains: list[dict],
    endpoints: list[dict],
    findings: list[dict],
    output_dir: Path,
) -> Path:
    lines = [
        f"# dreakon recon report: {domain}",
        f"\nGenerated: {datetime.utcnow().isoformat()}Z\n",
        "---\n",
        f"## summary\n",
        f"- **subdomains discovered:** {len(subdomains)}",
        f"- **subdomains resolved:** {sum(1 for s in subdomains if s.get('resolved'))}",
        f"- **unique endpoints:** {len(endpoints)}",
        f"- **findings:** {len(findings)}\n",
    ]

    if findings:
        lines.append("## findings\n")
        lines.append("| severity | type | url | detail |")
        lines.append("|---|---|---|---|")
        for f in sorted(findings, key=lambda x: x.get("severity", ""), reverse=True):
            lines.append(
                f"| {f.get('severity','?')} | {f.get('type','?')} | "
                f"`{f.get('url','')}` | {f.get('detail','')} |"
            )
        lines.append("")

    lines.append("## subdomains\n")
    lines.append("| fqdn | resolved | source | tech |")
    lines.append("|---|---|---|---|")
    for s in sorted(subdomains, key=lambda x: x.get("fqdn", "")):
        lines.append(
            f"| `{s.get('fqdn','')}` | {'yes' if s.get('resolved') else 'no'} | "
            f"{s.get('source','')} | {', '.join(s.get('tech_stack', []))} |"
        )
    lines.append("")

    lines.append("## endpoints\n")
    lines.append("| url | method | status | source |")
    lines.append("|---|---|---|---|")
    for ep in sorted(endpoints, key=lambda x: x.get("url", "")):
        lines.append(
            f"| `{ep.get('url','')}` | {ep.get('method','GET')} | "
            f"{ep.get('status_code','?')} | {ep.get('source','')} |"
        )

    path = output_dir / f"{domain}_{_ts()}_report.md"
    path.write_text("\n".join(lines))
    return path


def export_all(
    domain: str,
    subdomains: list[dict],
    endpoints: list[dict],
    findings: list[dict],
    output_dir: str = ".",
) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    live_urls = [ep["url"] for ep in endpoints if ep.get("status_code") not in (None, 404, 410)]

    paths = {
        "jsonl": str(export_jsonl(endpoints, out, domain)),
        "nuclei": str(export_nuclei_targets(live_urls, out, domain)),
        "markdown": str(export_markdown(domain, subdomains, endpoints, findings, out)),
    }
    return paths
