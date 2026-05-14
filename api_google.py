#!/usr/bin/env python3
"""
google_api_test.py — Valida permissões de uma Google API Key.

Uso:
    python3 google_api_test.py <API_KEY>
    python3 google_api_test.py <API_KEY> --json          # saída em JSON
    python3 google_api_test.py --file keys.txt           # testa múltiplas chaves
"""

import sys
import json
import argparse
import urllib3
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Endpoints ─────────────────────────────────────────────────────────────────

def build_endpoints(key: str) -> dict[str, str]:
    return {
        "Static Maps":               f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={key}",
        "Street View":               f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&key={key}",
        "Directions":                f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={key}",
        "Geocoding":                 f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={key}",
        "Distance Matrix":           f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=40.6655101,-73.8918897&destinations=40.6905615,-73.9976592&key={key}",
        "Find Place":                f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&fields=name&key={key}",
        "Autocomplete":              f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key={key}",
        "Elevation":                 f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={key}",
        "Timezone":                  f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={key}",
        "Roads":                     f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795&key={key}",
        "Generative Language":       f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
        "YouTube Data":              f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={key}",
        "Custom Search":             f"https://www.googleapis.com/customsearch/v1?q=test&key={key}",
        "Cloud Translation":         f"https://translation.googleapis.com/language/translate/v2?q=hello&target=pt&key={key}",
        "Firebase (FCM)":            f"https://fcm.googleapis.com/fcm/send",  # POST — tratado separadamente
    }

# ── Resultado ─────────────────────────────────────────────────────────────────

STATUS_OK       = "VULNERÁVEL"
STATUS_DENIED   = "NEGADO"
STATUS_INVALID  = "CHAVE INVÁLIDA"
STATUS_NO_PERM  = "SEM PERMISSÃO"
STATUS_ERROR    = "ERRO"
STATUS_FAIL     = "FALHA"

COLORS = {
    STATUS_OK:      "\033[91m",   # vermelho — atenção: vulnerável
    STATUS_DENIED:  "\033[32m",   # verde — negado corretamente
    STATUS_INVALID: "\033[33m",   # amarelo
    STATUS_NO_PERM: "\033[32m",   # verde — sem permissão
    STATUS_ERROR:   "\033[33m",   # amarelo
    STATUS_FAIL:    "\033[90m",   # cinza
}
RESET = "\033[0m"
BOLD  = "\033[1m"


@dataclass
class CheckResult:
    name: str
    status: str
    http_code: int | None = None
    note: str = ""
    url: str = ""

    def colored_line(self) -> str:
        color = COLORS.get(self.status, "")
        code = f" HTTP {self.http_code}" if self.http_code else ""
        note = f" — {self.note}" if self.note else ""
        return f"{color}[{self.status}]{RESET} {self.name}{code}{note}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "http_code": self.http_code,
            "note": self.note,
        }


# ── Lógica de verificação ─────────────────────────────────────────────────────

def classify(r: requests.Response) -> tuple[str, str]:
    """Retorna (status, note) a partir da resposta HTTP."""
    text = r.text

    if r.status_code == 400 and "API key not valid" in text:
        return STATUS_INVALID, "chave rejeitada pela API"
    if "API key not valid" in text:
        return STATUS_INVALID, ""
    if "REQUEST_DENIED" in text:
        return STATUS_DENIED, ""
    if "PERMISSION_DENIED" in text or r.status_code == 403:
        return STATUS_NO_PERM, ""
    if r.status_code == 200:
        return STATUS_OK, "resposta válida recebida"
    if "error" in text.lower():
        return STATUS_ERROR, f"HTTP {r.status_code}"

    return STATUS_ERROR, f"HTTP {r.status_code} inesperado"


def check_endpoint(name: str, url: str, timeout: int = 10) -> CheckResult:
    # Firebase FCM exige POST — tratamento especial
    if "fcm.googleapis.com" in url:
        return CheckResult(name=name, status=STATUS_NO_PERM,
                           note="FCM requer POST autenticado (fora do escopo)", url=url)
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 recon"})
        status, note = classify(r)
        return CheckResult(name=name, status=status, http_code=r.status_code, note=note, url=url)
    except requests.exceptions.Timeout:
        return CheckResult(name=name, status=STATUS_FAIL, note="timeout", url=url)
    except requests.exceptions.ConnectionError as exc:
        return CheckResult(name=name, status=STATUS_FAIL, note=f"conexão: {exc}", url=url)
    except Exception as exc:
        return CheckResult(name=name, status=STATUS_FAIL, note=str(exc), url=url)


def test_key(api_key: str, workers: int = 8, timeout: int = 10) -> list[CheckResult]:
    endpoints = build_endpoints(api_key)
    results: list[CheckResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(check_endpoint, name, url, timeout): name
            for name, url in endpoints.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Ordena: vulneráveis primeiro, depois por nome
    order = {STATUS_OK: 0, STATUS_ERROR: 1, STATUS_NO_PERM: 2,
             STATUS_DENIED: 3, STATUS_INVALID: 4, STATUS_FAIL: 5}
    results.sort(key=lambda r: (order.get(r.status, 9), r.name))
    return results


# ── Saída ─────────────────────────────────────────────────────────────────────

def print_results(api_key: str, results: list[CheckResult]) -> None:
    vuln = [r for r in results if r.status == STATUS_OK]
    print(f"\n{BOLD}Chave:{RESET} {api_key}")
    print(f"{BOLD}Endpoints testados:{RESET} {len(results)}")
    print(f"{BOLD}Vulneráveis:{RESET} {len(vuln)}\n")
    print("─" * 55)
    for r in results:
        print(r.colored_line())
    print("─" * 55)

    if vuln:
        print(f"\n{BOLD}\033[91m⚠ ATENÇÃO — {len(vuln)} endpoint(s) acessível(is):{RESET}")
        for r in vuln:
            print(f"  • {r.name}")
    else:
        print(f"\n\033[32m✓ Nenhum endpoint acessível com essa chave.{RESET}")
    print()


def print_json(api_key: str, results: list[CheckResult]) -> None:
    out = {
        "key": api_key,
        "total": len(results),
        "vulnerable": sum(1 for r in results if r.status == STATUS_OK),
        "results": [r.to_dict() for r in results],
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Valida permissões de Google API Keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("key", nargs="?", help="API key para testar")
    p.add_argument("--file", "-f", help="Arquivo com uma chave por linha")
    p.add_argument("--json", "-j", action="store_true", help="Saída em JSON")
    p.add_argument("--workers", "-w", type=int, default=8, help="Threads paralelas (padrão: 8)")
    p.add_argument("--timeout", "-t", type=int, default=10, help="Timeout por request em segundos")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    keys: list[str] = []

    if args.file:
        try:
            keys = [l.strip() for l in open(args.file) if l.strip()]
        except FileNotFoundError:
            print(f"Arquivo não encontrado: {args.file}")
            sys.exit(1)
    elif args.key:
        keys = [args.key]
    else:
        print("Uso: python3 google_api_test.py <API_KEY> [--json] [--file keys.txt]")
        sys.exit(1)

    for key in keys:
        results = test_key(key, workers=args.workers, timeout=args.timeout)
        if args.json:
            print_json(key, results)
        else:
            print_results(key, results)


if __name__ == "__main__":
    main()
