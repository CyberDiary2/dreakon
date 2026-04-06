"""
dreakon - wildcard domain recon tool
usage: python -m dreakon <domain> [options]
"""
import asyncio
from typing import Annotated
import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .core.orchestrator import ReconOrchestrator

app = typer.Typer(
    name="dreakon",
    help="wildcard domain recon - find every endpoint for a target",
    add_completion=False,
)
console = Console()

LOGO = r"""
                              ______________
                        ,===:'.,            `-._
Art by                       `:.`---.__         `-._
 John VanderZwaag              `:.     `--.         `.
                                 \.        `.         `.
                         (,,(,    \.         `.   ____,-`.,
                      (,'     `/   \.   ,--.___`.'
                  ,  ,'  ,--.  `,   \.;'         `
                   `{D, {    \  :    \;
                     V,,'    /  /    //
                     j;;    /  ,' ,-//.    ,---.      ,
                     \;'   /  ,' /  _  \  /  _  \   ,'/
                           \   `'  / \  `'  / \  `.' /
                            `.___,'   `.__,'   `.__,'

                         drew's recon  |  andrew@cyberdiary.net
"""

PHASES = [
    ("1", "subdomain enumeration     (passive osint + brute force + permutations)"),
    ("2", "dns resolution            (A/AAAA/CNAME/MX/TXT/NS, wildcard, zone transfer)"),
    ("3", "http probing              (11 ports, redirects, TLS certs, tech fingerprint)"),
    ("4", "endpoint discovery        (crawler, JS, wayback, openapi, fuzzing)"),
    ("5", "output                    (JSONL, nuclei targets, markdown report)"),
    ("6", "subdomain takeover        (dangling CNAMEs, S3, NS takeover - powered by STAB)"),
    ("7", "cloud footprint mapping   (AWS/Azure/GCP assets from domain - powered by DRACO)"),
]


def phase_selector() -> set[str]:
    """Interactive phase selector. Returns set of selected phase numbers."""
    import questionary

    console.print()
    choices = questionary.checkbox(
        "select phases to run:",
        choices=[
            questionary.Choice(
                title=f"  phase {num} - {desc}",
                value=num,
                checked=True,
            )
            for num, desc in PHASES
        ],
        instruction="(space to toggle, enter to confirm)",
        style=questionary.Style([
            ("question", "bold"),
            ("pointer", "fg:#ff0000 bold"),
            ("highlighted", "fg:#ff0000 bold"),
            ("selected", "fg:#00aa00"),
            ("instruction", "fg:#555555 italic"),
        ]),
    ).ask()

    if not choices:
        console.print("[red]no phases selected, exiting[/red]")
        raise typer.Exit()

    return set(choices)


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="target domain (e.g. example.com)")],
    output: Annotated[str, typer.Option("--output", "-o", help="output directory")] = ".",
    no_fuzz: Annotated[bool, typer.Option("--no-fuzz", help="skip path fuzzing")] = False,
    no_brute: Annotated[bool, typer.Option("--no-brute", help="skip dns brute force")] = False,
    no_screenshots: Annotated[bool, typer.Option("--no-screenshots", help="skip screenshotting live URLs")] = False,
    no_takeover: Annotated[bool, typer.Option("--no-takeover", help="skip subdomain takeover scan")] = False,
    no_cloud: Annotated[bool, typer.Option("--no-cloud", help="skip cloud footprint mapping")] = False,
    db: Annotated[str, typer.Option("--db", help="sqlite db path")] = "dreakon.db",
    interactive: Annotated[bool, typer.Option("--interactive", "-I", help="interactively select phases")] = False,
):
    """
    run full recon pipeline against a domain.

    example:
        dreakon scan example.com
        dreakon scan example.com --output ./results --no-fuzz
        dreakon scan example.com --interactive
    """
    domain = domain.lower().strip().lstrip("*.").rstrip(".")

    console.print(LOGO, markup=False, highlight=False)

    # Phase selector
    selected_phases: set[str] | None = None
    if interactive:
        selected_phases = phase_selector()
        console.print()
        console.print(Panel(
            Text("  ".join(f"phase {p}" for p in sorted(selected_phases)), style="bold green"),
            title="running",
            border_style="green",
        ))
        console.print()

    # Override db path in settings
    from .core import config as cfg_module
    cfg_module.settings.db_path = db

    orchestrator = ReconOrchestrator(
        domain=domain,
        output_dir=output,
        skip_fuzz=no_fuzz or (selected_phases is not None and "4" not in selected_phases),
        skip_brute=no_brute or (selected_phases is not None and "1" not in selected_phases),
        skip_screenshots=no_screenshots or (selected_phases is not None and "5" not in selected_phases),
        skip_takeover=no_takeover or (selected_phases is not None and "6" not in selected_phases),
        skip_cloud=no_cloud or (selected_phases is not None and "7" not in selected_phases),
        skip_dns=selected_phases is not None and "2" not in selected_phases,
        skip_http=selected_phases is not None and "3" not in selected_phases,
        skip_endpoints=selected_phases is not None and "4" not in selected_phases,
        skip_output=selected_phases is not None and "5" not in selected_phases,
    )
    asyncio.run(orchestrator.run())


@app.command()
def version():
    """print the current dreakon version."""
    from importlib.metadata import version as pkg_version
    try:
        console.print(pkg_version("dreakon"))
    except Exception:
        console.print("unknown")


def main():
    app()


if __name__ == "__main__":
    main()
