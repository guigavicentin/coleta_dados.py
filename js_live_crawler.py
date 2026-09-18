#!/usr/bin/env python3
"""
js_live_crawler.py — Captura os arquivos .js carregados ao VIVO por um site,
exatamente como um browser real faria. Sem caches históricos, sem wayback.

Requerimentos:
    pip install playwright requests
    playwright install chromium
"""

import asyncio
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[ERRO] Playwright não instalado. Execute:")
    print("       pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# Extensões JS capturadas — inclui .mjs, .cjs e chunks de bundlers
_JS_EXT_RE = re.compile(r'\.(m?js|cjs)(\?|#|$)', re.IGNORECASE)


def _is_js_url(path: str) -> bool:
    """Verifica se o path é de um arquivo JS, incluindo chunks de bundler."""
    clean = path.split("?")[0].split("#")[0]
    return bool(_JS_EXT_RE.search(clean))


def _is_own_domain(netloc: str, target: str) -> bool:
    """Verifica se netloc pertence ao domínio alvo (evita match por substring)."""
    return netloc == target or netloc.endswith("." + target)


# ─────────────────────────────────────────────
#  Core
# ─────────────────────────────────────────────

async def crawl(
    url: str,
    timeout: int,
    wait: int,
    headless: bool,
    output_json: str | None,
    download: bool = False,
    scroll: bool = True,
):
    """Abre a URL num browser real e intercepta todos os JS carregados."""

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
            path    = parsed.path

            if _is_js_url(path) and req_url not in seen:
                seen.add(req_url)
                js_files.append({
                    "url":       req_url,
                    "domain":    parsed.netloc,
                    "path":      path,
                    "resource":  request.resource_type,
                    "initiator": request.headers.get("referer", ""),
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

        # Simula scroll para disparar lazy-load de scripts
        if scroll:
            try:
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(1)
                await page.evaluate("window.scrollTo(0, 0)")
            except Exception:
                pass

        if wait > 0:
            await asyncio.sleep(wait)

        await browser.close()

    # ── Download de conteúdo (opcional) ─────────────────────────────────────
    if download and _REQUESTS_OK:
        js_files = _download_js_content(js_files)
    elif download and not _REQUESTS_OK:
        print("[AVISO] --download requer 'requests'. Execute: pip install requests")

    # ── Resultado ────────────────────────────────────────────────────────────
    target_domain = urlparse(url).netloc
    own    = [j for j in js_files if _is_own_domain(j["domain"], target_domain)]
    thirds = [j for j in js_files if not _is_own_domain(j["domain"], target_domain)]

    _print_results(url, js_files, own, thirds)

    if output_json:
        data = {
            "crawled_at":  datetime.now(timezone.utc).isoformat(),
            "target":      url,
            "total":       len(js_files),
            "own_domain":  own,
            "third_party": thirds,
        }
        _merge_json(output_json, data)

    return js_files


def _download_js_content(js_files: list[dict]) -> list[dict]:
    """Faz download do conteúdo de cada JS e adiciona hash + snippet."""
    import requests as req
    enriched = []
    for entry in js_files:
        try:
            r = req.get(
                entry["url"], timeout=10, verify=False,
                headers={"User-Agent": "Mozilla/5.0 recon"},
            )
            content = r.text
            entry["sha256"]      = hashlib.sha256(content.encode()).hexdigest()
            entry["size_bytes"]  = len(r.content)
            entry["snippet"]     = content[:200]
            entry["status_code"] = r.status_code
        except Exception as exc:
            entry["download_error"] = str(exc)
        enriched.append(entry)
    return enriched


async def crawl_many(
    urls: list[str],
    timeout: int,
    wait: int,
    headless: bool,
    output_json: str | None,
    download: bool = False,
    scroll: bool = True,
    concurrency: int = 1,
):
    """Processa uma lista de URLs com concorrência configurável."""
    all_results = []
    total = len(urls)
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(idx: int, url: str):
        async with sem:
            print(f"\n{'═' * 70}")
            print(f"  [{idx}/{total}] Processando: {url}")
            print(f"{'═' * 70}")
            try:
                js_files = await crawl(url, timeout, wait, headless, output_json, download, scroll)
                return {"url": url, "js_count": len(js_files), "status": "ok"}
            except Exception as e:
                print(f"[ERRO] Falha ao processar {url}: {e}")
                return {"url": url, "js_count": 0, "status": f"erro: {e}"}

    tasks = [_bounded(i, u) for i, u in enumerate(urls, 1)]
    results = await asyncio.gather(*tasks)
    all_results = list(results)

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
    """Acumula resultados num único arquivo JSON, deduplicando por URL."""
    path = Path(filepath)
    existing: list[dict] = []
    seen_urls: set[str] = set()

    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                content = json.load(f)
                existing = content if isinstance(content, list) else [content]
        except Exception:
            pass

    # Coleta URLs já registradas para dedup
    for entry in existing:
        for js in entry.get("own_domain", []) + entry.get("third_party", []):
            seen_urls.add(js["url"])

    # Remove da nova entrada os JS já presentes
    new_data["own_domain"]  = [j for j in new_data["own_domain"]  if j["url"] not in seen_urls]
    new_data["third_party"] = [j for j in new_data["third_party"] if j["url"] not in seen_urls]
    new_data["total"]       = len(new_data["own_domain"]) + len(new_data["third_party"])

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
    with open(path, encoding="utf-8") as f:
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
            size = f"  [{j['size_bytes']:,} B]" if "size_bytes" in j else ""
            print(f"  [{i:02d}] {j['url']}{size}")

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
        description="Captura .js/.mjs carregados AO VIVO por um site (como um browser real).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # URL única
  python js_live_crawler.py https://example.com

  # URL única com download de conteúdo + hash
  python js_live_crawler.py https://example.com --download -o result.json

  # Arquivo com lista de domínios, 3 em paralelo
  python js_live_crawler.py -f dominios.txt -c 3 -o result.json

  # Sem scroll (sites simples sem lazy-load)
  python js_live_crawler.py https://example.com --no-scroll

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
    source.add_argument("url",  nargs="?",  help="URL alvo (ex: https://example.com)")
    source.add_argument("-f", "--file",     help="Arquivo com domínios/URLs, um por linha")

    p.add_argument("-t", "--timeout",    type=int, default=30,
                   help="Timeout de navegação em segundos (padrão: 30)")
    p.add_argument("-w", "--wait",       type=int, default=2,
                   help="Segundos extras após networkidle (padrão: 2)")
    p.add_argument("-o", "--output",     default=None,
                   help="Salvar resultado em JSON (ex: -o result.json)")
    p.add_argument("-c", "--concurrency",type=int, default=1,
                   help="Domínios em paralelo — modo arquivo (padrão: 1)")
    p.add_argument("--download",         action="store_true",
                   help="Baixa conteúdo dos JS e adiciona sha256 + tamanho (requer requests)")
    p.add_argument("--no-headless",      action="store_true",
                   help="Abre o browser visível (útil para debug)")
    p.add_argument("--no-scroll",        action="store_true",
                   help="Desativa scroll automático para lazy-load")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    headless = not args.no_headless
    scroll   = not args.no_scroll

    if args.file:
        urls = load_urls_from_file(args.file)
        asyncio.run(
            crawl_many(
                urls        = urls,
                timeout     = args.timeout,
                wait        = args.wait,
                headless    = headless,
                output_json = args.output,
                download    = args.download,
                scroll      = scroll,
                concurrency = args.concurrency,
            )
        )
    else:
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
                download    = args.download,
                scroll      = scroll,
            )
        )


if __name__ == "__main__":
    main()
