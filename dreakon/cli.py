"""
dreakon — wildcard domain recon tool
usage: python -m dreakon <domain> [options]
"""
import asyncio
from typing import Annotated
import typer
from rich.console import Console
from rich import print as rprint

from .core.orchestrator import ReconOrchestrator

app = typer.Typer(
    name="dreakon",
    help="wildcard domain recon — find every endpoint for a target",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="target domain (e.g. example.com)")],
    output: Annotated[str, typer.Option("--output", "-o", help="output directory")] = ".",
    no_fuzz: Annotated[bool, typer.Option("--no-fuzz", help="skip path fuzzing")] = False,
    no_brute: Annotated[bool, typer.Option("--no-brute", help="skip dns brute force")] = False,
    no_screenshots: Annotated[bool, typer.Option("--no-screenshots", help="skip screenshotting live URLs")] = False,
    db: Annotated[str, typer.Option("--db", help="sqlite db path")] = "dreakon.db",
):
    """
    run full recon pipeline against a domain.

    example:
        dreakon scan example.com
        dreakon scan example.com --output ./results --no-fuzz
    """
    # Normalize domain
    domain = domain.lower().strip().lstrip("*.").rstrip(".")

    console.print(f"""
[bold magenta]
    ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔═══██╗████╗  ██║
    ██║  ██║██████╔╝█████╗  ███████║█████╔╝ ██║   ██║██╔██╗ ██║
    ██║  ██║██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██║   ██║██║╚██╗██║
    ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗╚██████╔╝██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold magenta]""")

    # Override db path in settings
    from .core import config as cfg_module
    cfg_module.settings.db_path = db

    orchestrator = ReconOrchestrator(
        domain=domain,
        output_dir=output,
        skip_fuzz=no_fuzz,
        skip_brute=no_brute,
        skip_screenshots=no_screenshots,
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
