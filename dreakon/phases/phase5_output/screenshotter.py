"""
Screenshot live URLs using Playwright.
One PNG per URL, filename derived from the URL itself.
"""
import asyncio
import re
from pathlib import Path

from playwright.async_api import async_playwright
from rich.console import Console

console = Console()

_MAX_FILENAME = 180  # keep paths sane on any FS


def _url_to_filename(url: str) -> str:
    """Turn a URL into a safe filename, keeping it human-readable."""
    name = url.replace("://", "__").replace("/", "_").replace(":", "_")
    name = re.sub(r"[^\w\-.]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if len(name) > _MAX_FILENAME:
        name = name[:_MAX_FILENAME]
    return name + ".png"


async def screenshot_urls(urls: list[str], output_dir: Path, concurrency: int = 5) -> list[Path]:
    """Screenshot each URL and save to output_dir/screenshots/<url>.png."""
    if not urls:
        return []

    shots_dir = output_dir / "screenshots"
    shots_dir.mkdir(parents=True, exist_ok=True)

    saved: list[Path] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def _shoot(browser, url: str):
        async with semaphore:
            dest = shots_dir / _url_to_filename(url)
            try:
                page = await browser.new_page()
                await page.goto(url, timeout=15_000, wait_until="domcontentloaded")
                await page.screenshot(path=str(dest))
                await page.close()
                saved.append(dest)
                console.print(f"[green]screenshot:[/green] {dest.name}")
            except Exception as e:
                console.print(f"[yellow]screenshot failed:[/yellow] {url} — {e}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        await asyncio.gather(*[_shoot(browser, url) for url in urls])
        await browser.close()

    return saved
