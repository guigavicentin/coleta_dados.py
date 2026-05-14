#!/usr/bin/env python3
"""
js_live_crawler.py — Captura os arquivos .js carregados ao VIVO por um site,
exatamente como um browser real faria. Sem caches históricos, sem wayback.

Requerimentos:
    pip install playwright
    playwright install chromium
"""

import asyncio
import argparse
import json
import sys
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[ERRO] Playwright não instalado. Execute:")
    print("       pip install playwright && playwright install chromium")
    sys.exit(1)


# ─────────────────────────────────────────────
#  Core
# ─────────────────────────────────────────────

async def crawl(url: str, timeout: int, wait: int, headless: bool, output_json: str | None):
    """Abre a URL num browser real e intercepta todos os .js carregados."""

    js_files: list[dict] = []
    seen: set[str] = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # ── Intercepta cada requisição de rede ──────────────────────────────
        def on_request(request):
            req_url = request.url
            parsed  = urlparse(req_url)
            path    = parsed.path.lower()

            if ".js" in path and req_url not in seen:
                seen.add(req_url)
                js_files.append({
                    "url":        req_url,
                    "domain":     parsed.netloc,
                    "path":       parsed.path,
                    "resource":   request.resource_type,
                    "initiator":  request.headers.get("referer", "—"),
                })

        page.on("request", on_request)

        # ── Navega ──────────────────────────────────────────────────────────
        print(f"\n🌐  Acessando: {url}")
        print(f"⏳  Aguardando página carregar (timeout {timeout}s, wait extra {wait}s)…\n")

        try:
            await page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
        except Exception as e:
            print(f"[AVISO] networkidle timeout: {e}")
            print("        Continuando com o que foi capturado…")

        if wait > 0:
            await asyncio.sleep(wait)

        await browser.close()

    # ── Resultado ────────────────────────────────────────────────────────────
    target_domain = urlparse(url).netloc
    own    = [j for j in js_files if target_domain in j["domain"]]
    thirds = [j for j in js_files if target_domain not in j["domain"]]

    _print_results(url, js_files, own, thirds)

    if output_json:
        data = {
            "crawled_at":   datetime.utcnow().isoformat() + "Z",
            "target":       url,
            "total":        len(js_files),
            "own_domain":   own,
            "third_party":  thirds,
        }
        _merge_json(output_json, data)

    return js_files


async def crawl_many(urls: list[str], timeout: int, wait: int, headless: bool, output_json: str | None):
    """Processa uma lista de URLs sequencialmente."""
    all_results = []
    total = len(urls)

    for idx, url in enumerate(urls, 1):
        print(f"\n{'═' * 70}")
        print(f"  [{idx}/{total}] Processando: {url}")
        print(f"{'═' * 70}")
        try:
            js_files = await crawl(url, timeout, wait, headless, output_json)
            all_results.append({"url": url, "js_count": len(js_files), "status": "ok"})
        except Exception as e:
            print(f"[ERRO] Falha ao processar {url}: {e}")
            all_results.append({"url": url, "js_count": 0, "status": f"erro: {e}"})

    # ── Resumo final ─────────────────────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print(f"  📋  RESUMO FINAL — {total} domínio(s) processado(s)")
    print(f"{'═' * 70}")
    for r in all_results:
        status_icon = "✅" if r["status"] == "ok" else "❌"
        print(f"  {status_icon}  {r['url']:<50}  {r['js_count']} JS")
    print(f"{'═' * 70}\n")


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def _merge_json(filepath: str, new_data: dict):
    """Acumula resultados num único arquivo JSON (lista de crawls)."""
    path = Path(filepath)
    existing = []
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
                existing = content if isinstance(content, list) else [content]
        except Exception:
            pass

    existing.append(new_data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
    print(f"\n💾  Resultado acumulado em: {filepath}")


def load_urls_from_file(filepath: str) -> list[str]:
    """
    Lê um arquivo de domínios/URLs (um por linha).
    Linhas vazias e comentários (#) são ignorados.
    Domínios sem protocolo recebem https:// automaticamente.
    """
    path = Path(filepath)
    if not path.exists():
        print(f"[ERRO] Arquivo não encontrado: {filepath}")
        sys.exit(1)

    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith(("http://", "https://")):
                line = "https://" + line
            urls.append(line)

    if not urls:
        print(f"[ERRO] Nenhum domínio válido encontrado em: {filepath}")
        sys.exit(1)

    print(f"📄  {len(urls)} domínio(s) carregado(s) de '{filepath}'")
    return urls


def _print_results(url, all_js, own, thirds):
    sep = "─" * 70

    print(sep)
    print(f"  🎯  Target  : {url}")
    print(f"  📦  Total JS: {len(all_js)}")
    print(sep)

    if own:
        print(f"\n  ✅  JS DO PRÓPRIO DOMÍNIO ({len(own)})\n")
        for i, j in enumerate(own, 1):
            print(f"  [{i:02d}] {j['url']}")

    if thirds:
        print(f"\n  🌍  JS DE TERCEIROS ({len(thirds)})\n")
        for i, j in enumerate(thirds, 1):
            domain_label = j["domain"].ljust(35)
            print(f"  [{i:02d}] {domain_label}  {j['path']}")

    print(f"\n{sep}\n")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="js_live_crawler",
        description="Captura .js carregados AO VIVO por um site (como um browser real).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # URL única
  python js_live_crawler.py https://example.com

  # URL única com saída JSON
  python js_live_crawler.py https://example.com -w 3 -o result.json

  # Arquivo com lista de domínios
  python js_live_crawler.py -f dominios.txt

  # Arquivo com lista + saída JSON acumulada
  python js_live_crawler.py -f dominios.txt -o result.json

  # Abre o browser visível (útil para debug)
  python js_live_crawler.py https://example.com --no-headless

Formato do arquivo de domínios (dominios.txt):
  # comentários são ignorados
  example.com
  https://outro.com
  http://terceiro.com.br
        """,
    )

    # Origem: URL direta OU arquivo — pelo menos um é obrigatório
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("url",   nargs="?",       help="URL alvo (ex: https://example.com)")
    source.add_argument("-f", "--file",            help="Arquivo com domínios/URLs, um por linha")

    p.add_argument("-t", "--timeout", type=int, default=30,  help="Timeout de navegação em segundos (padrão: 30)")
    p.add_argument("-w", "--wait",    type=int, default=2,   help="Segundos extras após networkidle (padrão: 2)")
    p.add_argument("-o", "--output",  default=None,          help="Salvar resultado em JSON (ex: -o result.json)")
    p.add_argument("--no-headless",   action="store_true",   help="Abre o browser visível (útil para debug)")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    headless = not args.no_headless

    if args.file:
        # ── Modo arquivo ────────────────────────────────────────────────────
        urls = load_urls_from_file(args.file)
        asyncio.run(
            crawl_many(
                urls        = urls,
                timeout     = args.timeout,
                wait        = args.wait,
                headless    = headless,
                output_json = args.output,
            )
        )
    else:
        # ── Modo URL única ──────────────────────────────────────────────────
        url = args.url
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        asyncio.run(
            crawl(
                url         = url,
                timeout     = args.timeout,
                wait        = args.wait,
                headless    = headless,
                output_json = args.output,
            )
        )


if __name__ == "__main__":
    main()
