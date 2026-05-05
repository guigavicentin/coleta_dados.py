#!/usr/bin/env python3
"""
recon.py — Script de reconhecimento web passivo/ativo.

Etapas:
  1. Coleta de URLs (gau + waybackurls + katana)
  2. Filtragem com GF (xss, sqli, ssrf, redirect, ssti)
  3. Extração de arquivos sensíveis por extensão
  4. Coleta de arquivos JS
  5. Análise de segredos em JS — inclui detecção e validação de Google API Keys
"""

import subprocess
import re
import math
import collections
import logging
import sys
import urllib3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Filtros de qualidade para password/senha ──────────────────────────────────

# Valores que quase certamente são placeholders, labels de UI ou exemplos
_PLACEHOLDER_RE = re.compile(
    r'^('
    r'enter|your|change|example|placeholder|sample|dummy|fake|'
    r'test|demo|default|secret|senha|password|passwd|pass|'
    r'my[-_]?pass(word)?|new[-_]?pass(word)?|old[-_]?pass(word)?|'
    r'confirm|repeat|retype|current|'
    r'xxxx+|\*+|\.{3,}|#{3,}|changeme|mustchange|'
    r'123456|abcdef|qwerty|letmein|welcome|admin|'
    r'<[^>]+>|\$\{[^}]+\}|%[a-z_]+%'   # template vars: <PASSWORD>, ${pw}, %pw%
    r')',
    re.I,
)

# Contextos de UI/i18n que nunca contêm credenciais reais
_UI_CONTEXT_RE = re.compile(
    r'(label|placeholder|hint|aria[-_]label|title|description|'
    r'tooltip|helper|message|text|i18n|translate|t\()',
    re.I,
)

# Comprimento mínimo do valor para ser considerado real
_MIN_VALUE_LEN = 8

# Entropia mínima (bits) — senhas reais tendem a ter > 3.0
_MIN_ENTROPY = 3.0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_value(raw_match: str) -> str:
    """Extrai só o valor após := da string capturada pela regex."""
    m = re.search(r'[:=]\s*["\']([^"\']*)', raw_match)
    return m.group(1).strip() if m else ""


def is_likely_real_credential(raw_match: str, context_line: str = "") -> bool:
    """
    Retorna True se o match parece uma credencial real (não placeholder).
    Aplica três filtros em cascata:
      1. Comprimento mínimo do valor
      2. Blocklist de placeholders comuns
      3. Entropia de Shannon mínima
    """
    value = _extract_value(raw_match)

    if len(value) < _MIN_VALUE_LEN:
        return False

    if _PLACEHOLDER_RE.match(value):
        return False

    if _UI_CONTEXT_RE.search(context_line):
        return False

    if _shannon_entropy(value) < _MIN_ENTROPY:
        return False

    return True


# ── Detector de strings ofuscadas via char code arrays ────────────────────────
#
# Padrão alvo (uma ou mais variações):
#   [83, 121, 115, 54, ...]                          → array literal
#   for(...) n += String.fromCharCode(l[u])          → loop de montagem
#   "abc".split("").map(c => c.charCodeAt(0))        → encode (menos comum)
#
# Estratégia: encontrar todos os arrays de inteiros no JS, reconstruir a string
# e verificar se o resultado bate com algum padrão de segredo conhecido.

# Captura arrays do tipo [83, 121, 115, ...]  com 6+ elementos no range ASCII imprimível
_CHARCODE_ARRAY_RE = re.compile(r'\[\s*(\d{2,3}(?:\s*,\s*\d{2,3}){5,})\s*\]')

# Padrões aplicados à string reconstruída
_DECODED_SECRET_CHECKS: list[tuple[str, re.Pattern]] = [
    ("bcrypt_hash_decoded",   re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}')),
    ("google_key_decoded",    re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("aws_key_decoded",       re.compile(r'AKIA[0-9A-Z]{16}')),
    ("jwt_decoded",           re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),
    ("high_entropy_string",   None),   # fallback: entropia alta sem padrão específico
]

# Limite de entropia para o fallback "high_entropy_string"
_DECODED_ENTROPY_MIN = 3.5


def _decode_charcode_array(array_str: str) -> str | None:
    """
    Converte '83, 121, 115, 54, ...' numa string.
    Retorna None se algum código estiver fora do range ASCII imprimível (32-126).
    """
    try:
        codes = [int(x.strip()) for x in array_str.split(",")]
        # Rejeita arrays com valores fora do imprimível — provavelmente não é texto
        if any(c < 32 or c > 126 for c in codes):
            return None
        return "".join(chr(c) for c in codes)
    except ValueError:
        return None


def scan_charcode_obfuscation(
    content: str,
    url: str,
    out_file,
    logger: logging.Logger,
) -> int:
    """
    Varre o conteúdo JS em busca de arrays de char codes e tenta decodificá-los.
    Loga e grava apenas os que contêm segredos reconhecíveis ou alta entropia.
    Retorna o número de achados.
    """
    found = 0

    for m in _CHARCODE_ARRAY_RE.finditer(content):
        decoded = _decode_charcode_array(m.group(1))
        if not decoded or len(decoded) < 8:
            continue

        matched_label = None

        for label, pattern in _DECODED_SECRET_CHECKS:
            if pattern is None:
                # Fallback: verifica entropia
                if _shannon_entropy(decoded) >= _DECODED_ENTROPY_MIN:
                    matched_label = label
                break
            if pattern.search(decoded):
                matched_label = label
                break

        if matched_label:
            # Recupera até 120 chars de contexto ao redor do array para o relatório
            start = max(0, m.start() - 60)
            end = min(len(content), m.end() + 60)
            context = content[start:end].replace("\n", " ")

            logger.warning("[!!!] %s (ofuscado) → %s", matched_label, url)
            logger.warning("      decoded: %s", decoded[:80])

            out_file.write(
                f"[{matched_label}] {url}\n"
                f"  decoded : {decoded}\n"
                f"  context : ...{context}...\n"
                + "-" * 60 + "\n"
            )
            found += 1

    return found




def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("recon")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ── Configuração ──────────────────────────────────────────────────────────────

def get_config(domain: str) -> dict:
    base = Path(f"coleta_{domain}")
    base.mkdir(exist_ok=True)
    (base / "gf").mkdir(exist_ok=True)
    (base / "js").mkdir(exist_ok=True)

    return {
        "domain": domain,
        "base_dir": base,
        "urls_file": base / "urls.txt",
        "js_file": base / "js_urls.txt",
        "result_file": base / "js_sensiveis.txt",
        "google_keys_file": base / "google_keys.txt",
        "google_report_file": base / "google_keys_report.txt",
        "log_file": base / "recon.log",
        "gf_dir": base / "gf",
        "sensitive_file": base / "urls_analisar.txt",

        "gf_patterns": ["xss", "sqli", "ssrf", "redirect", "ssti"],

        "sensitive_regex": re.compile(
            r"\.(php|html|xml|zip|gz|env|log|bak|sql|txt|conf|ini|yml|yaml|db|pem|key|crt|sh|py|jsp|asp|aspx)$",
            re.IGNORECASE,
        ),

        # Regex para Google API Keys (AIza... — padrão público e bem documentado)
        "google_key_regex": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),

        "secret_patterns": {
            "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            "api_key":        re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}', re.I),
            "token":          re.compile(r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{16,}', re.I),
            "jwt":            re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
            "aws_key":        re.compile(r'AKIA[0-9A-Z]{16}'),
            "secret":         re.compile(r'secret["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\/+=]{16,}', re.I),
            "authorization":  re.compile(r'Bearer\s+[A-Za-z0-9_\-\.]{16,}'),
            # password/senha: captura o match bruto; filtrado por is_likely_real_credential()
            "password":       re.compile(r'password["\']?\s*[:=]\s*["\'][^"\']{8,}', re.I),
            "senha":          re.compile(r'senha["\']?\s*[:=]\s*["\'][^"\']{8,}', re.I),
            # Hashes hardcoded — bcrypt, MD5, SHA1/256 em contexto de atribuição
            "bcrypt_hash":    re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'),
            "md5_hash":       re.compile(r'''(?:hash|md5|digest)["\']?\s*[:=]\s*["\'][0-9a-f]{32}["\']''', re.I),
            "sha_hash":       re.compile(r'''(?:hash|sha(?:1|256)?|digest)["\']?\s*[:=]\s*["\'][0-9a-f]{40,64}["\']''', re.I),
        },

        "headers": {"User-Agent": "Mozilla/5.0 recon"},
        "js_workers": 20,
        "request_timeout": 10,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], logger: logging.Logger) -> list[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.stderr:
            logger.debug("[stderr] %s: %s", cmd[0], result.stderr.strip())
        return result.stdout.splitlines()
    except FileNotFoundError:
        logger.warning("Ferramenta não encontrada: %s — pulando.", cmd[0])
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Timeout ao executar: %s", " ".join(cmd))
        return []
    except Exception as exc:
        logger.error("Erro ao executar %s: %s", cmd[0], exc)
        return []


# ── Etapa 1: Coleta de URLs ───────────────────────────────────────────────────

def collect_urls(cfg: dict, logger: logging.Logger) -> int:
    domain = cfg["domain"]

    logger.info("Coletando URLs com gau…")
    gau = run_cmd(["gau", domain], logger)

    logger.info("Coletando URLs com waybackurls…")
    try:
        wb = subprocess.run(["waybackurls"], input=domain, text=True,
                            capture_output=True, timeout=300)
        wayback = wb.stdout.splitlines()
        if wb.stderr:
            logger.debug("[stderr] waybackurls: %s", wb.stderr.strip())
    except FileNotFoundError:
        logger.warning("waybackurls não encontrado — pulando.")
        wayback = []
    except Exception as exc:
        logger.error("Erro no waybackurls: %s", exc)
        wayback = []

    logger.info("Coletando URLs com katana…")
    katana = run_cmd([
        "katana", "-u", domain, "-d", "5",
        "-ps", "waybackarchive,commoncrawl,alienvault",
        "-kf", "-jc",
        "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif",
    ], logger)

    urls = sorted(set(gau + wayback + katana))
    cfg["urls_file"].write_text("\n".join(urls) + "\n", encoding="utf-8")
    logger.info("URLs coletadas: %d → %s", len(urls), cfg["urls_file"])
    return len(urls)


# ── Etapa 2: GF ───────────────────────────────────────────────────────────────

def run_gf(cfg: dict, logger: logging.Logger) -> None:
    for pattern in cfg["gf_patterns"]:
        output = cfg["gf_dir"] / f"gf_{pattern}.txt"
        logger.info("GF pattern: %s", pattern)
        try:
            with open(output, "w", encoding="utf-8") as out:
                subprocess.run(
                    f"cat {cfg['urls_file']} | gf {pattern}",
                    shell=True, stdout=out, timeout=120,
                )
        except subprocess.TimeoutExpired:
            logger.warning("Timeout no gf %s", pattern)
        except Exception as exc:
            logger.error("Erro no gf %s: %s", pattern, exc)


# ── Etapa 3: Arquivos sensíveis ───────────────────────────────────────────────

def extract_sensitive(cfg: dict, logger: logging.Logger) -> int:
    regex = cfg["sensitive_regex"]
    matches = []
    with open(cfg["urls_file"], encoding="utf-8") as f:
        for line in f:
            if regex.search(line.strip()):
                matches.append(line)
    cfg["sensitive_file"].write_text("".join(matches), encoding="utf-8")
    logger.info("Arquivos sensíveis: %d → %s", len(matches), cfg["sensitive_file"])
    return len(matches)


# ── Etapa 4: Coleta de JS ─────────────────────────────────────────────────────

def collect_js(cfg: dict, logger: logging.Logger) -> int:
    js_urls = set()
    with open(cfg["urls_file"], encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if ".js" in line.lower():
                js_urls.add(line)
    cfg["js_file"].write_text("\n".join(sorted(js_urls)) + "\n", encoding="utf-8")
    logger.info("Arquivos JS: %d → %s", len(js_urls), cfg["js_file"])
    return len(js_urls)


# ── Google API Key: validação de endpoints ────────────────────────────────────

GOOGLE_ENDPOINTS = [
    ("Geocoding",           "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={key}"),
    ("Directions",          "https://maps.googleapis.com/maps/api/directions/json?origin=A&destination=B&key={key}"),
    ("Distance Matrix",     "https://maps.googleapis.com/maps/api/distancematrix/json?origins=0,0&destinations=1,1&key={key}"),
    ("Find Place",          "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&fields=name&key={key}"),
    ("Autocomplete",        "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key={key}"),
    ("Elevation",           "https://maps.googleapis.com/maps/api/elevation/json?locations=39.74,-104.98&key={key}"),
    ("Timezone",            "https://maps.googleapis.com/maps/api/timezone/json?location=39.60,-119.68&timestamp=1331161200&key={key}"),
    ("Roads",               "https://roads.googleapis.com/v1/nearestRoads?points=60.17,24.94&key={key}"),
    ("Static Maps",         "https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={key}"),
    ("Street View",         "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.72,-73.99&key={key}"),
    ("YouTube Data",        "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={key}"),
    ("Custom Search",       "https://www.googleapis.com/customsearch/v1?q=test&key={key}"),
    ("Cloud Translation",   "https://translation.googleapis.com/language/translate/v2?q=hello&target=pt&key={key}"),
    ("Generative Language", "https://generativelanguage.googleapis.com/v1beta/models?key={key}"),
]


def _classify_google(r: requests.Response) -> str:
    text = r.text
    if "API key not valid" in text:
        return "CHAVE INVÁLIDA"
    if "REQUEST_DENIED" in text:
        return "NEGADO"
    if "PERMISSION_DENIED" in text or r.status_code == 403:
        return "SEM PERMISSÃO"
    if r.status_code == 200:
        return "VULNERÁVEL"
    if "error" in text.lower():
        return "ERRO"
    return f"HTTP {r.status_code}"


def validate_google_key(key: str, cfg: dict, logger: logging.Logger) -> dict:
    results = {}

    def _check(name: str, url_tpl: str) -> tuple[str, str]:
        url = url_tpl.format(key=key)
        try:
            r = requests.get(url, timeout=cfg["request_timeout"],
                             verify=False, headers=cfg["headers"])
            return name, _classify_google(r)
        except requests.exceptions.Timeout:
            return name, "TIMEOUT"
        except Exception as exc:
            return name, f"FALHA: {exc}"

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_check, name, tpl): name
                   for name, tpl in GOOGLE_ENDPOINTS}
        for future in as_completed(futures):
            name, status = future.result()
            results[name] = status

    vuln = [n for n, s in results.items() if s == "VULNERÁVEL"]
    if vuln:
        logger.warning("[GOOGLE KEY] %s → vulnerável em: %s", key, ", ".join(vuln))
    else:
        logger.info("[GOOGLE KEY] %s → sem endpoints acessíveis", key)

    return results


def save_google_report(key_results: dict, cfg: dict, logger: logging.Logger) -> None:
    lines = []
    for key, results in key_results.items():
        vuln = [n for n, s in results.items() if s == "VULNERÁVEL"]
        lines.append(f"KEY: {key}")
        lines.append(f"Vulneráveis: {len(vuln)}/{len(results)}")
        for name, status in sorted(results.items()):
            lines.append(f"  [{status}] {name}")
        lines.append("-" * 60)

    cfg["google_report_file"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Relatório Google Keys → %s", cfg["google_report_file"])


def validate_all_google_keys(google_keys: set, cfg: dict, logger: logging.Logger) -> None:
    if not google_keys:
        logger.info("Nenhuma Google API Key encontrada para validar.")
        return

    cfg["google_keys_file"].write_text(
        "\n".join(sorted(google_keys)) + "\n", encoding="utf-8"
    )
    logger.info("Google API Keys encontradas: %d → %s", len(google_keys), cfg["google_keys_file"])
    logger.info("Validando endpoints Google para cada chave…")

    key_results = {}
    for key in sorted(google_keys):
        key_results[key] = validate_google_key(key, cfg, logger)

    save_google_report(key_results, cfg, logger)


# ── Etapa 5: Análise de JS ────────────────────────────────────────────────────

def is_valid_js(resp: requests.Response, content: str) -> bool:
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct:
        return True
    stripped = content.strip()
    return stripped.startswith(("var ", "let ", "const ", "function", "!function", "(function"))


def analyze_js_content(
    content: str,
    url: str,
    cfg: dict,
    logger: logging.Logger,
    google_keys_found: set,
) -> int:
    found = 0
    lines = content.splitlines()

    # Monta índice linha→número para recuperar contexto ao filtrar
    def _get_context(pos: int) -> str:
        char_count = 0
        for line in lines:
            char_count += len(line) + 1
            if char_count >= pos:
                return line
        return ""

    # Padrões que passam pelo filtro de entropia/blocklist antes de logar
    _credential_patterns = {"password", "senha"}

    with open(cfg["result_file"], "a", encoding="utf-8") as out:
        for name, pattern in cfg["secret_patterns"].items():
            for match in pattern.finditer(content):
                value = match.group(0)

                # Aplica filtro apenas nos padrões genéricos de credencial
                if name in _credential_patterns:
                    context_line = _get_context(match.start())
                    if not is_likely_real_credential(value, context_line):
                        logger.debug("[SKIP placeholder] %s → %s", name, value[:60])
                        continue

                logger.warning("[!!!] %s → %s", name, url)
                out.write(f"[{name}] {url}\n{value}\n" + "-" * 60 + "\n")
                found += 1

                if name == "google_api_key":
                    google_keys_found.add(value)

        # Varredura de strings ofuscadas via char code arrays
        found += scan_charcode_obfuscation(content, url, out, logger)

    return found


def process_js(url: str, cfg: dict, logger: logging.Logger, google_keys_found: set) -> int:
    try:
        resp = requests.get(url, headers=cfg["headers"],
                            timeout=cfg["request_timeout"], verify=False)
    except requests.exceptions.SSLError as exc:
        logger.debug("SSL error em %s: %s", url, exc)
        return 0
    except requests.exceptions.ConnectionError as exc:
        logger.debug("Conexão falhou em %s: %s", url, exc)
        return 0
    except requests.exceptions.Timeout:
        logger.debug("Timeout em %s", url)
        return 0
    except Exception as exc:
        logger.debug("Erro inesperado em %s: %s", url, exc)
        return 0

    if resp.status_code != 200:
        logger.debug("HTTP %d em %s", resp.status_code, url)
        return 0

    content = resp.text
    if not is_valid_js(resp, content):
        logger.debug("Conteúdo não parece JS em %s", url)
        return 0

    return analyze_js_content(content, url, cfg, logger, google_keys_found)


def analyze_all_js(cfg: dict, logger: logging.Logger) -> tuple[int, set]:
    urls = [u.strip() for u in cfg["js_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    total_found = 0
    google_keys_found: set = set()

    logger.info("Analisando %d arquivos JS com %d workers…", len(urls), cfg["js_workers"])

    with ThreadPoolExecutor(max_workers=cfg["js_workers"]) as executor:
        futures = {
            executor.submit(process_js, url, cfg, logger, google_keys_found): url
            for url in urls
        }
        for future in as_completed(futures):
            try:
                total_found += future.result()
            except Exception as exc:
                logger.error("Erro inesperado na thread: %s", exc)

    logger.info("Achados em JS: %d → %s", total_found, cfg["result_file"])
    return total_found, google_keys_found


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    domain = input("Domínio: ").strip()
    if not domain:
        print("Domínio inválido.")
        sys.exit(1)

    cfg = get_config(domain)
    logger = setup_logging(cfg["log_file"])

    logger.info("=" * 60)
    logger.info("Iniciando recon para: %s", domain)
    logger.info("Diretório de saída: %s", cfg["base_dir"])
    logger.info("=" * 60)

    collect_urls(cfg, logger)
    run_gf(cfg, logger)
    extract_sensitive(cfg, logger)
    collect_js(cfg, logger)

    _, google_keys = analyze_all_js(cfg, logger)
    validate_all_google_keys(google_keys, cfg, logger)

    logger.info("=" * 60)
    logger.info("Recon finalizado. Logs completos em: %s", cfg["log_file"])
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
