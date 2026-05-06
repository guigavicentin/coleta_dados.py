#!/usr/bin/env python3
"""
recon.py — Script de reconhecimento web passivo/ativo focado em JS.

Fluxo:
  1. Coleta de URLs  (gau + waybackurls + katana + hakrawler + subfinder + gospider)
  2. Validação de URLs ativas com httpx
  3. Filtragem com GF  (xss, sqli, ssrf, redirect, ssti)
  4. Download e análise de arquivos sensíveis por extensão
  5. Coleta de URLs de JS  (filtro inteligente, sem CDNs)
  6. Análise de segredos em JS  (padrões de alta precisão + detecção de ofuscação)
  7. Validação de Google API Keys
  8. Extração de endpoints de API expostos em JS
  9. Probe de XSS (dalfox) e SSRF/redirect (qsreplace)
 10. Relatório consolidado

Filosofia de saída:
  - Nenhum arquivo é criado se estiver vazio.
  - Sem estrutura de diretórios pré-criada; pastas são geradas sob demanda.
  - Apenas achados reais são persistidos.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import re
import math
import collections
import logging
import sys
import threading
import urllib3
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Constantes de qualidade
# ─────────────────────────────────────────────────────────────────────────────

_MIN_VALUE_LEN  = 8
_MIN_ENTROPY    = 3.2   # bits por caractere (Shannon)
_DECODED_ENTROPY_MIN = 3.5

# Palavras que indicam valor de placeholder / UI / i18n
_PLACEHOLDER_RE = re.compile(
    r'^('
    r'enter|your|change|example|placeholder|sample|dummy|fake|'
    r'test|demo|default|secret|senha|password|passwd|pass|'
    r'my[-_]?pass(word)?|new[-_]?pass(word)?|old[-_]?pass(word)?|'
    r'confirm|repeat|retype|current|'
    r'xxxx+|\*+|\.{3,}|#{3,}|changeme|mustchange|'
    r'123456|abcdef|qwerty|letmein|welcome|admin|'
    r'<[^>]+>|\$\{[^}]+\}|%[a-z_]+%'
    r')',
    re.I,
)

# Contexto de UI / i18n que indica que o valor não é um segredo real
_UI_CONTEXT_RE = re.compile(
    r'(label|placeholder|hint|aria[-_]label|title|description|'
    r'tooltip|helper|message|text|i18n|translate|t\(|'
    r'console\.log|console\.warn|console\.error|comment|//)',
    re.I,
)

# CDNs comuns — URLs de JS vindas desses domínios são descartadas
_CDN_DOMAINS_RE = re.compile(
    r'(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|'
    r'ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|'
    r'maxcdn\.bootstrapcdn\.com|code\.jquery\.com|'
    r'cdn\.datatables\.net|cdn\.polyfill\.io|'
    r'static\.cloudflareinsights\.com)',
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers de regex
# ─────────────────────────────────────────────────────────────────────────────

def _regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


def _ctx_regex(context: str, value_pattern: str,
               flags: int = re.I, window: int = 80) -> re.Pattern:
    """Regex que exige palavra de contexto próxima ao segredo (reduz FP)."""
    return re.compile(
        rf'(?is)(?:{context})' + r'.{0,' + str(window) + r'}(' + value_pattern + r')',
        flags,
    )


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_value(raw_match: str) -> str:
    """Extrai o valor do lado direito de key=value ou key:value."""
    m = re.search(r'[:=]\s*["\']?([^\s"\'`,;]{4,})', raw_match)
    return m.group(1).strip() if m else raw_match.strip()


def is_likely_real_credential(raw_match: str, context_line: str = "") -> bool:
    """
    Filtragem de alta precisão para padrões genéricos (password, token, secret).
    Retorna False se parecer placeholder, i18n ou baixa entropia.
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


# ─────────────────────────────────────────────────────────────────────────────
# Detector de strings ofuscadas via char-code arrays
# ─────────────────────────────────────────────────────────────────────────────

_CHARCODE_ARRAY_RE = re.compile(r'\[\s*(\d{2,3}(?:\s*,\s*\d{2,3}){5,})\s*\]')

_DECODED_SECRET_CHECKS: list[tuple[str, re.Pattern | None]] = [
    ("bcrypt_hash_decoded",  re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}')),
    ("google_key_decoded",   re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("aws_key_decoded",      re.compile(r'AKIA[0-9A-Z]{16}')),
    ("jwt_decoded",          re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),
    ("high_entropy_decoded", None),   # fallback: apenas entropia
]


def _decode_charcode_array(array_str: str) -> str | None:
    try:
        codes = [int(x.strip()) for x in array_str.split(",")]
        if any(c < 32 or c > 126 for c in codes):
            return None
        return "".join(chr(c) for c in codes)
    except ValueError:
        return None


def scan_charcode_obfuscation(content: str, url: str, logger: logging.Logger) -> list[dict]:
    """Varre arrays de char-codes e retorna lista de achados (sem escrever arquivos)."""
    results = []
    for m in _CHARCODE_ARRAY_RE.finditer(content):
        decoded = _decode_charcode_array(m.group(1))
        if not decoded or len(decoded) < 8:
            continue

        matched_label = None
        for label, pattern in _DECODED_SECRET_CHECKS:
            if pattern is None:
                if _shannon_entropy(decoded) >= _DECODED_ENTROPY_MIN:
                    matched_label = label
                break
            if pattern.search(decoded):
                matched_label = label
                break

        if matched_label:
            start   = max(0, m.start() - 60)
            end     = min(len(content), m.end() + 60)
            context = content[start:end].replace("\n", " ")
            logger.warning("[!!!] %s (ofuscado) → %s | decoded: %s", matched_label, url, decoded[:80])
            results.append({
                "type":    matched_label,
                "value":   decoded,
                "context": context,
                "url":     url,
            })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("recon")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────────────────────────────────────
# Configuração
# ─────────────────────────────────────────────────────────────────────────────

def get_config(domain: str) -> dict:
    base = Path(f"recon_{domain}")
    base.mkdir(exist_ok=True)

    return {
        "domain":     domain,
        "base_dir":   base,

        # Arquivos de saída — criados SÓ se tiverem conteúdo
        "urls_file":          base / "urls_raw.txt",
        "urls_alive_file":    base / "urls_alive.txt",
        "js_file":            base / "js_urls.txt",
        "secrets_txt":        base / "secrets.txt",
        "secrets_csv":        base / "secrets.csv",
        "secrets_jsonl":      base / "secrets.jsonl",
        "google_keys_file":   base / "google_keys.txt",
        "google_report_file": base / "google_keys_report.txt",
        "log_file":           base / "recon.log",
        "gf_dir":             base / "gf",
        "sensitive_urls_file":base / "sensitive_urls.txt",
        "sensitive_dir":      base / "sensitive_downloads",
        "sensitive_report":   base / "sensitive_report.txt",
        "api_endpoints_file": base / "api_endpoints.txt",
        "summary_file":       base / "SUMMARY.txt",

        "gf_patterns": ["xss", "sqli", "ssrf", "redirect", "ssti"],

        # Extensões que interessam para download/análise
        "sensitive_regex": re.compile(
            r'\.(env|log|bak|sql|conf|ini|yml|yaml|pem|key|crt|sh|py)$',
            re.IGNORECASE,
        ),

        # ── Padrões de segredos de ALTA PRECISÃO ─────────────────────────────
        # Cada padrão foi escolhido por ter prefixo fixo ou estrutura única
        # que minimiza falsos positivos. Padrões genéricos (api_key, token,
        # password) só entram com contexto e validação de entropia.
        "secret_patterns": {
            # Google / Firebase / GCP
            "google_api_key":       _regex(r'AIza[0-9A-Za-z\-_]{35}'),
            "google_oauth_client":  _regex(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
            "firebase_url":         _regex(r'https?://[a-z0-9\-]+\.firebaseio\.com', re.I),
            "gcp_service_account":  _regex(r'"type"\s*:\s*"service_account"'),

            # AWS / Cloud
            "aws_access_key":       _regex(r'AKIA[0-9A-Z]{16}'),
            "amazon_mws":           _regex(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            "azure_storage_key":    _regex(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
            "digitalocean_token":   _regex(r'dop_v1_[a-f0-9]{64}'),
            "terraform_cloud":      _regex(r'[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_=]{60,}'),

            # Pagamento
            "stripe_secret":        _regex(r'sk_live_[0-9a-zA-Z]{24,}'),
            "stripe_publishable":   _regex(r'pk_live_[0-9a-zA-Z]{24,}'),
            "stripe_webhook":       _regex(r'whsec_[a-zA-Z0-9]{32,}'),
            "square_access_token":  _regex(r'sq0atp-[0-9A-Za-z\-_]{22}'),
            "square_oauth_secret":  _regex(r'sq0csp-[0-9A-Za-z\-_]{43}'),
            "braintree_token":      _regex(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),

            # Comunicação
            "sendgrid_key":         _regex(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
            "mailgun_api_key":      _regex(r'key-[0-9a-zA-Z]{32}'),
            "mailchimp_api_key":    _regex(r'[0-9a-f]{32}-us[0-9]{1,2}'),
            "twilio_account_sid":   _regex(r'\bAC[a-z0-9]{32}\b'),
            "twilio_auth_token":    _regex(r'\bSK[a-z0-9]{32}\b'),

            # DevOps / CI
            "github_pat":           _regex(r'gh[pousr]_[A-Za-z0-9]{36}'),
            "github_oauth":         _regex(r'gho_[A-Za-z0-9]{36}'),
            "gitlab_pat":           _regex(r'glpat-[A-Za-z0-9\-_]{20}'),
            "gitlab_pipeline":      _regex(r'glptt-[a-f0-9]{40}'),
            "npm_token":            _regex(r'npm_[A-Za-z0-9]{36}'),
            "pypi_token":           _regex(r'pypi-[A-Za-z0-9_\-]{50,}'),
            "dockerhub_pat":        _regex(r'dckr_pat_[A-Za-z0-9_\-]{27}'),
            "hashicorp_vault":      _regex(r'hvs\.[A-Za-z0-9_\-]{90,}'),
            "new_relic_key":        _regex(r'NRAK-[A-Z0-9]{27}'),
            "sentry_dsn":           _regex(r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'),
            "grafana_token":        _regex(r'glc_[A-Za-z0-9+/]{32,}'),

            # OpenAI / Slack
            "openai_key":           _regex(r'sk-[a-zA-Z0-9]{48}'),
            "slack_token":          _regex(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
            "slack_webhook":        _regex(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),

            # DB / Connection strings (exigem user:pass@host)
            "mongodb_dsn":          _regex(r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
            "postgres_dsn":         _regex(r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
            "mysql_dsn":            _regex(r'mysql://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
            "redis_dsn":            _regex(r'redis://:([^@\s]+)@[^\s"\'`]+', re.I),

            # Misc
            "shopify_token":        _regex(r'shp(?:at|ss)_[a-fA-F0-9]{32}'),
            "mapbox_token":         _regex(r'pk\.eyJ1[A-Za-z0-9._\-]{20,}'),
            "notion_token":         _regex(r'secret_[A-Za-z0-9]{43}'),
            "linear_api_key":       _regex(r'lin_api_[A-Za-z0-9]{40}'),

            # Chaves privadas
            "private_key":          _regex(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),

            # JWT (estrutura fixa — baixo FP)
            "jwt":                  _regex(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),

            # Hashes hardcoded com CONTEXTO explícito
            "bcrypt_hash":          _regex(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'),

            # ── Padrões GENÉRICOS — validação extra de entropia obrigatória ──
            # Esses são os que geram mais FP; a validação acontece em analyze_js_content.
            "generic_api_key":      _regex(r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
            "generic_token":        _regex(r'(?:access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I),
            "generic_secret":       _regex(r'(?:client[_-]?secret|app[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{20,})["\']', re.I),
            "bearer_token":         _regex(r'Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.]{20,})', re.I),
            "password_field":       _regex(r'(?:password|passwd|senha)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
        },

        # Padrões genéricos que exigem validação de entropia extra
        "_generic_patterns": {
            "generic_api_key", "generic_token", "generic_secret",
            "bearer_token", "password_field",
        },

        # Endpoints de API internos em JS
        "api_endpoint_patterns": [
            re.compile(r'["\`](/api/v\d[a-zA-Z0-9/_\-]*)["\`]'),
            re.compile(r'["\`](/graphql)["\`\s/]', re.I),
            re.compile(r'["\`](/gql)["\`\s/]', re.I),
            re.compile(r'https?://(?:internal|admin|dev|staging|api)\.[a-z0-9\-]+\.[a-z]+[^\s"\'`]*'),
            re.compile(r'["\`](/v\d+/[a-zA-Z0-9/_\-]{4,})["\`]'),
        ],

        "google_key_regex":  re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "headers":           {"User-Agent": "Mozilla/5.0 recon"},
        "js_workers":        20,
        "request_timeout":   10,

        # Padrões para análise de arquivos .env/.conf baixados
        "sensitive_content_patterns": [
            re.compile(r'(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD)\s*=\s*\S+', re.I),
            re.compile(r'(?:SECRET_KEY|APP_KEY|ENCRYPTION_KEY)\s*=\s*\S+', re.I),
            re.compile(r'(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*=\s*\S+', re.I),
            re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            re.compile(r'(?:MAIL|SMTP)_PASS(?:WORD)?\s*=\s*\S+', re.I),
            re.compile(r'(?:STRIPE|PAYPAL|BRAINTREE)[_-](?:SECRET|KEY|TOKEN)\s*=\s*\S+', re.I),
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Escrita segura de arquivos — só cria se tiver conteúdo
# ─────────────────────────────────────────────────────────────────────────────

def write_if_not_empty(path: Path, lines: list[str], logger: logging.Logger) -> bool:
    """Escreve arquivo somente se houver linhas. Retorna True se escreveu."""
    content = [l for l in lines if l.strip()]
    if not content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content) + "\n", encoding="utf-8")
    logger.debug("Salvo: %s (%d linhas)", path, len(content))
    return True


def append_line_to_file(path: Path, line: str) -> None:
    """Append de uma linha; cria o arquivo (e diretório) se necessário."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Rate-limited requests com retry
# ─────────────────────────────────────────────────────────────────────────────

_request_logger = logging.getLogger("recon.requests")


def _make_retrying_get(cfg: dict):
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
        retry=retry_if_exception_type((
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        )),
        before_sleep=before_sleep_log(_request_logger, logging.DEBUG),
        reraise=True,
    )
    def _get(url: str, **kwargs) -> requests.Response:
        resp = requests.get(
            url,
            headers=cfg["headers"],
            timeout=cfg["request_timeout"],
            verify=False,
            **kwargs,
        )
        if resp.status_code in (429, 503):
            retry_after = int(resp.headers.get("Retry-After", 5))
            time.sleep(retry_after)
            resp.raise_for_status()
        return resp

    return _get


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de subprocesso
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], logger: logging.Logger,
            stdin: str | None = None, timeout: int = 300) -> list[str]:
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.stderr:
            logger.debug("[stderr] %s: %s", cmd[0], result.stderr.strip()[:300])
        return [l for l in result.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        logger.warning("Ferramenta não encontrada: %s — pulando.", cmd[0])
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Timeout: %s", " ".join(cmd))
        return []
    except Exception as exc:
        logger.error("Erro em %s: %s", cmd[0], exc)
        return []


def tool_available(name: str) -> bool:
    """Verifica se uma ferramenta está no PATH usando shutil.which (cross-platform)."""
    return shutil.which(name) is not None


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 1: Coleta de URLs
# ─────────────────────────────────────────────────────────────────────────────

def collect_urls(cfg: dict, logger: logging.Logger) -> int:
    """
    Coleta URLs de múltiplas fontes passivas/ativas.

    Ferramentas e flags validadas contra os --help reais:
      - gau         : --providers wayback,commoncrawl,otx,urlscan  (alienvault não existe no gau)
      - waybackurls : lê APENAS via stdin (sem argumento posicional)
      - katana      : crawler ativo com JS rendering + passive sources
      - hakrawler   : lê stdin; flags: -d, -subs, -u, -t, -timeout (sem -js, sem -plain)
      - gospider    : -s, -c, -d, -a (other-source), -w (include-subs), --subs, -q (quiet)
      - subfinder   : alimenta hakrawler e gospider com subdomínios
    """
    domain = cfg["domain"]
    all_urls: set[str] = set()

    # ── gau ───────────────────────────────────────────────────────────────────
    # Providers válidos: wayback, commoncrawl, otx, urlscan  (alienvault NÃO existe)
    # --retries aceita uint; --threads aceita uint
    if tool_available("gau"):
        logger.info("[gau] coletando…")
        lines = run_cmd([
            "gau",
            "--threads", "5",
            "--subs",
            "--providers", "wayback,commoncrawl,otx,urlscan",
            "--retries", "3",
            domain,
        ], logger, timeout=600)
        all_urls.update(lines)
        logger.info("[gau] %d URLs", len(lines))
    else:
        logger.warning("gau não encontrado — pulando.")

    # ── waybackurls ───────────────────────────────────────────────────────────
    # Lê EXCLUSIVAMENTE via stdin — não existe argumento posicional.
    # Flags úteis: sem --no-subs (queremos subdomínios)
    if tool_available("waybackurls"):
        logger.info("[waybackurls] coletando…")
        lines = run_cmd(
            ["waybackurls"],
            logger,
            stdin=domain + "\n",
            timeout=300,
        )
        all_urls.update(lines)
        logger.info("[waybackurls] %d URLs", len(lines))
    else:
        logger.warning("waybackurls não encontrado — pulando.")

    # ── katana ────────────────────────────────────────────────────────────────
    if tool_available("katana"):
        logger.info("[katana] coletando…")
        lines = run_cmd([
            "katana",
            "-u", f"https://{domain}",
            "-d", "5",
            "-ps",
            "-pss", "waybackarchive,commoncrawl,alienvault",
            "-kf",
            "-jc",
            "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,ico,ttf",
            "-silent",
        ], logger, timeout=600)
        all_urls.update(lines)
        logger.info("[katana] %d URLs", len(lines))
    else:
        logger.warning("katana não encontrado — pulando.")

    # ── hakrawler ─────────────────────────────────────────────────────────────
    # Flags válidas: -d (depth), -subs, -u (unique), -t (threads),
    #                -timeout, -s (show source), -insecure, -json
    # NÃO existe: -js, -plain, -linkfinder, -url
    # Output vai para stdout — cada URL em uma linha
    if tool_available("hakrawler"):
        logger.info("[hakrawler] coletando…")
        lines = run_cmd(
            ["hakrawler", "-d", "3", "-u", "-subs", "-t", "8", "-insecure"],
            logger,
            stdin=f"https://{domain}\n",
            timeout=300,
        )
        all_urls.update(lines)
        logger.info("[hakrawler] %d URLs", len(lines))
    else:
        logger.info("hakrawler não encontrado — instale: go install github.com/hakluke/hakrawler@latest")

    # ── gospider ─────────────────────────────────────────────────────────────
    # Flags válidas: -s (site), -c (concurrent), -d (depth), -a (other-source),
    #                -w (include-subs), --subs, --js, --sitemap, --robots, -q (quiet)
    # NÃO existe: --other-source, --include-subs (são -a e -w respectivamente)
    # Usamos -q para output limpo e depois extraímos URLs com regex
    if tool_available("gospider"):
        logger.info("[gospider] coletando…")
        raw = run_cmd([
            "gospider",
            "-s", f"https://{domain}",
            "-c", "10", "-d", "3",
            "--js", "--sitemap", "--robots",
            "-a",          # other-source: Archive.org, CommonCrawl, VirusTotal, AlienVault
            "-w",          # include-subs de third-party
            "--subs",      # inclui subdomínios no crawl
            "-q",          # quiet: só mostra URLs, sem banner
        ], logger, timeout=600)
        for line in raw:
            m = re.search(r'https?://[^\s"\'<>\]]+', line)
            if m:
                all_urls.add(m.group(0).rstrip('.,;)"\'>]'))
        logger.info("[gospider] %d linhas processadas", len(raw))
    else:
        logger.info("gospider não encontrado — instale: go install github.com/jaeles-project/gospider@latest")

    # ── subfinder → hakrawler + gospider em subdomínios ──────────────────────
    if tool_available("subfinder"):
        logger.info("[subfinder] enumerando subdomínios…")
        subs = run_cmd(["subfinder", "-d", domain, "-silent"], logger, timeout=300)
        logger.info("[subfinder] %d subdomínios encontrados", len(subs))

        if subs:
            # hakrawler: passa todos os subdomínios via stdin de uma vez
            if tool_available("hakrawler"):
                logger.info("[hakrawler] crawling em %d subdomínios…", len(subs))
                sub_input = "\n".join(f"https://{s}" for s in subs) + "\n"
                lines = run_cmd(
                    ["hakrawler", "-d", "2", "-u", "-t", "8",
                     "-timeout", "10", "-insecure"],
                    logger,
                    stdin=sub_input,
                    timeout=max(60, len(subs) * 3),
                )
                all_urls.update(lines)
                logger.info("[hakrawler/subs] %d URLs", len(lines))

            # gospider em subdomínios (limita a 50 para não demorar demais)
            if tool_available("gospider"):
                logger.info("[gospider] crawling em subdomínios…")
                for sub in subs[:50]:
                    raw = run_cmd([
                        "gospider", "-s", f"https://{sub}",
                        "-c", "5", "-d", "2", "--js", "-q",
                    ], logger, timeout=60)
                    for line in raw:
                        m = re.search(r'https?://[^\s"\'<>\]]+', line)
                        if m:
                            all_urls.add(m.group(0).rstrip('.,;)"\'>]'))
    else:
        logger.info("subfinder não encontrado — instale: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    urls = sorted(all_urls)
    wrote = write_if_not_empty(cfg["urls_file"], urls, logger)
    logger.info("URLs coletadas: %d%s", len(urls), f" → {cfg['urls_file']}" if wrote else " (nenhuma)")
    return len(urls)


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 2: Validação com httpx
# ─────────────────────────────────────────────────────────────────────────────

def validate_alive_urls(cfg: dict, logger: logging.Logger) -> int:
    if not cfg["urls_file"].exists():
        logger.warning("Arquivo de URLs não encontrado — pulando httpx.")
        cfg["_active_urls_file"] = cfg["urls_file"]
        return 0

    logger.info("Validando URLs ativas com httpx…")
    if not tool_available("httpx"):
        logger.warning("httpx não encontrado — usando todas as URLs.")
        cfg["_active_urls_file"] = cfg["urls_file"]
        return sum(1 for _ in cfg["urls_file"].read_text(encoding="utf-8").splitlines() if _.strip())

    try:
        result = subprocess.run(
            ["httpx", "-l", str(cfg["urls_file"]),
             "-silent", "-mc", "200,201,204,301,302,307,308,403",
             "-threads", "50", "-timeout", "10"],
            capture_output=True, text=True, timeout=600,
        )
        alive = [u.strip() for u in result.stdout.splitlines() if u.strip()]
    except subprocess.TimeoutExpired:
        logger.warning("Timeout no httpx — usando todas as URLs.")
        alive = [u.strip() for u in cfg["urls_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    except Exception as exc:
        logger.error("Erro no httpx: %s", exc)
        alive = []

    wrote = write_if_not_empty(cfg["urls_alive_file"], alive, logger)
    logger.info("URLs ativas: %d%s", len(alive), f" → {cfg['urls_alive_file']}" if wrote else "")
    cfg["_active_urls_file"] = cfg["urls_alive_file"] if wrote else cfg["urls_file"]
    return len(alive)


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 3: GF
# ─────────────────────────────────────────────────────────────────────────────

def run_gf(cfg: dict, logger: logging.Logger) -> None:
    if not tool_available("gf"):
        logger.warning("gf não encontrado — pulando filtragem de padrões.")
        return

    source = cfg.get("_active_urls_file", cfg["urls_file"])
    if not source.exists():
        return

    # Lê todas as URLs uma vez e passa via stdin ao gf (sem shell=True)
    source_text = source.read_text(encoding="utf-8")

    cfg["gf_dir"].mkdir(parents=True, exist_ok=True)
    for pattern in cfg["gf_patterns"]:
        output = cfg["gf_dir"] / f"gf_{pattern}.txt"
        try:
            result = subprocess.run(
                ["gf", pattern],
                input=source_text,
                capture_output=True,
                text=True,
                timeout=120,
            )
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            if lines:
                write_if_not_empty(output, lines, logger)
                logger.info("GF [%s]: %d URLs → %s", pattern, len(lines), output)
            else:
                logger.info("GF [%s]: nenhuma URL encontrada.", pattern)
        except Exception as exc:
            logger.error("Erro no gf %s: %s", pattern, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 3b: Probes XSS e SSRF
# ─────────────────────────────────────────────────────────────────────────────

def probe_xss(cfg: dict, logger: logging.Logger) -> int:
    xss_file = cfg["gf_dir"] / "gf_xss.txt"
    if not xss_file.exists() or xss_file.stat().st_size == 0:
        logger.info("Sem URLs para XSS probe.")
        return 0
    if not tool_available("dalfox"):
        logger.warning("dalfox não encontrado — pulando XSS probe.")
        return 0

    out_file = cfg["gf_dir"] / "dalfox_results.txt"
    logger.info("Rodando dalfox…")
    try:
        subprocess.run(
            ["dalfox", "file", str(xss_file),
             "--silence", "--output", str(out_file),
             "--worker", "10", "--timeout", "10"],
            capture_output=True, text=True, timeout=600,
        )
        hits = out_file.read_text(encoding="utf-8").count("[V]") if out_file.exists() else 0
        if hits:
            logger.warning("[!!!] dalfox: %d XSS confirmados → %s", hits, out_file)
        else:
            # Apaga arquivo vazio
            if out_file.exists():
                out_file.unlink()
            logger.info("dalfox: nenhum XSS confirmado.")
        return hits
    except Exception as exc:
        logger.error("Erro no dalfox: %s", exc)
        return 0


def probe_ssrf_redirect(cfg: dict, logger: logging.Logger) -> int:
    found = 0
    probes = {
        "ssrf":     (cfg["gf_dir"] / "gf_ssrf.txt",     "http://169.254.169.254/latest/meta-data/"),
        "redirect": (cfg["gf_dir"] / "gf_redirect.txt", "https://evil.com"),
    }

    if not tool_available("qsreplace"):
        logger.warning("qsreplace não encontrado — pulando probes SSRF/redirect.")
        return 0

    for kind, (gf_file, payload) in probes.items():
        if not gf_file.exists() or gf_file.stat().st_size == 0:
            continue

        logger.info("Probe %s…", kind.upper())
        try:
            qsr = subprocess.run(
                ["qsreplace", payload],
                input=gf_file.read_text(encoding="utf-8"),
                capture_output=True, text=True, timeout=60,
            )
            probe_urls = [u.strip() for u in qsr.stdout.splitlines() if u.strip()]
        except Exception as exc:
            logger.error("qsreplace (%s): %s", kind, exc)
            continue

        hits = []
        for url in probe_urls[:200]:
            try:
                r = subprocess.run(
                    ["curl", "-sk", "-o", "/dev/null",
                     "-w", "%{http_code} %{redirect_url}", url],
                    capture_output=True, text=True, timeout=10,
                )
                output = r.stdout.strip()
                code = output.split()[0] if output else "0"
                if kind == "redirect" and code in ("301", "302", "307", "308") and "evil.com" in output:
                    hits.append(url)
                elif kind == "ssrf" and code == "200":
                    hits.append(url)
            except Exception:
                pass

        if hits:
            write_if_not_empty(cfg["gf_dir"] / f"{kind}_hits.txt", hits, logger)
            logger.warning("[!!!] %s: %d hits", kind.upper(), len(hits))
            found += len(hits)
        else:
            logger.info("%s probe: nenhum hit.", kind.upper())

    return found


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 4: Arquivos sensíveis
# ─────────────────────────────────────────────────────────────────────────────

def extract_sensitive_urls(cfg: dict, logger: logging.Logger) -> int:
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    if not source.exists():
        return 0

    regex   = cfg["sensitive_regex"]
    matches = [l.strip() for l in source.read_text(encoding="utf-8").splitlines()
               if l.strip() and regex.search(l.strip())]

    wrote = write_if_not_empty(cfg["sensitive_urls_file"], matches, logger)
    logger.info("URLs de arquivos sensíveis: %d%s", len(matches),
                f" → {cfg['sensitive_urls_file']}" if wrote else "")
    return len(matches)


def download_and_analyze_sensitive(cfg: dict, logger: logging.Logger) -> int:
    if not cfg["sensitive_urls_file"].exists():
        return 0

    urls = [u.strip() for u in cfg["sensitive_urls_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    if not urls:
        return 0

    get      = _make_retrying_get(cfg)
    findings = 0
    report_lines: list[str] = []

    logger.info("Baixando %d arquivos sensíveis…", len(urls))
    for url in urls[:500]:
        try:
            resp = get(url)
        except Exception:
            continue

        if resp.status_code != 200:
            continue
        content = resp.text
        if len(content) > 2_000_000:
            continue

        local_hits: list[str] = []
        for pattern in cfg["sensitive_content_patterns"]:
            for m in pattern.finditer(content):
                local_hits.append(m.group(0))

        if local_hits:
            # Salva cópia local apenas se tiver achados
            cfg["sensitive_dir"].mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r'[^\w\-.]', '_', url)[:120]
            (cfg["sensitive_dir"] / safe_name).write_text(content, encoding="utf-8", errors="replace")
            for hit in local_hits:
                logger.warning("[!!!] Segredo em arquivo sensível → %s", url)
                report_lines.append(f"URL: {url}\nACHADO: {hit}\n" + "-" * 60)
                findings += 1

    if report_lines:
        write_if_not_empty(cfg["sensitive_report"], report_lines, logger)

    logger.info("Achados em arquivos sensíveis: %d", findings)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 5: Coleta de JS
# ─────────────────────────────────────────────────────────────────────────────

def collect_js(cfg: dict, logger: logging.Logger) -> int:
    """
    Filtra URLs de JS com cuidado:
      - Exige extensão .js ou padrão de bundle (/static/js/, /chunks/, etc.)
      - Descarta CDNs conhecidos
      - Descarta source maps (.js.map)
      - Descarta miniaturas e fallbacks de imagem com .js na query string
    """
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    if not source.exists():
        logger.warning("Arquivo de URLs não encontrado — pulando coleta de JS.")
        return 0

    js_re = re.compile(
        r'(?:'
        r'\.js(?:\?[^\s]*)?$'           # termina em .js ou .js?...
        r'|/(?:static|assets|dist|build|chunks|bundles)/[^\s]*\.js'  # padrão de build
        r')',
        re.I,
    )

    js_urls: set[str] = set()
    for line in source.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url:
            continue
        if _CDN_DOMAINS_RE.search(url):
            continue
        if url.endswith(".js.map"):
            continue
        if js_re.search(url):
            js_urls.add(url)

    wrote = write_if_not_empty(cfg["js_file"], sorted(js_urls), logger)
    logger.info("Arquivos JS únicos: %d%s", len(js_urls),
                f" → {cfg['js_file']}" if wrote else " (nenhum)")
    return len(js_urls)


# ─────────────────────────────────────────────────────────────────────────────
# Google API Key — validação de endpoints
# ─────────────────────────────────────────────────────────────────────────────

GOOGLE_ENDPOINTS = [
    ("Geocoding",           "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={key}"),
    ("Directions",          "https://maps.googleapis.com/maps/api/directions/json?origin=A&destination=B&key={key}"),
    ("Distance Matrix",     "https://maps.googleapis.com/maps/api/distancematrix/json?origins=0,0&destinations=1,1&key={key}"),
    ("Find Place",          "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&fields=name&key={key}"),
    ("Autocomplete",        "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key={key}"),
    ("Elevation",           "https://maps.googleapis.com/maps/api/elevation/json?locations=39.74,-104.98&key={key}"),
    ("Timezone",            "https://maps.googleapis.com/maps/api/timezone/json?location=39.60,-119.68&timestamp=1331161200&key={key}"),
    ("YouTube Data",        "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={key}"),
    ("Custom Search",       "https://www.googleapis.com/customsearch/v1?q=test&key={key}"),
    ("Cloud Translation",   "https://translation.googleapis.com/language/translate/v2?q=hello&target=pt&key={key}"),
    ("Generative Language", "https://generativelanguage.googleapis.com/v1beta/models?key={key}"),
]


def _classify_google(r: requests.Response) -> str:
    text = r.text
    if "API key not valid" in text:
        return "CHAVE_INVALIDA"
    if "REQUEST_DENIED" in text:
        return "NEGADO"
    if "PERMISSION_DENIED" in text or r.status_code == 403:
        return "SEM_PERMISSAO"
    if r.status_code == 200:
        return "VULNERAVEL"
    return f"HTTP_{r.status_code}"


def validate_google_key(key: str, cfg: dict, logger: logging.Logger) -> dict:
    results: dict[str, str] = {}
    get = _make_retrying_get(cfg)

    def _check(name: str, url_tpl: str) -> tuple[str, str]:
        url = url_tpl.format(key=key)
        try:
            return name, _classify_google(get(url))
        except requests.exceptions.Timeout:
            return name, "TIMEOUT"
        except Exception as exc:
            return name, f"FALHA:{exc}"

    with ThreadPoolExecutor(max_workers=8) as ex:
        for fut in as_completed({ex.submit(_check, n, t): n for n, t in GOOGLE_ENDPOINTS}):
            n, s = fut.result()
            results[n] = s

    vuln = [n for n, s in results.items() if s == "VULNERAVEL"]
    if vuln:
        logger.warning("[GOOGLE KEY] %s → vulnerável: %s", key, ", ".join(vuln))
    return results


def validate_all_google_keys(google_keys: set, cfg: dict, logger: logging.Logger) -> None:
    if not google_keys:
        return

    write_if_not_empty(cfg["google_keys_file"], sorted(google_keys), logger)
    logger.info("Validando %d Google API Key(s)…", len(google_keys))

    report_lines: list[str] = []
    for key in sorted(google_keys):
        results = validate_google_key(key, cfg, logger)
        vuln    = [n for n, s in results.items() if s == "VULNERAVEL"]
        report_lines.append(f"KEY: {key}")
        report_lines.append(f"Vulneráveis: {len(vuln)}/{len(results)}")
        for name, status in sorted(results.items()):
            report_lines.append(f"  [{status}] {name}")
        report_lines.append("-" * 60)

    if report_lines:
        write_if_not_empty(cfg["google_report_file"], report_lines, logger)
        logger.info("Relatório Google Keys → %s", cfg["google_report_file"])


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 6: Análise de JS
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_js(resp: requests.Response, content: str) -> bool:
    """
    Aceita o conteúdo como JS se:
      - Content-Type indica JavaScript/ECMAScript, OU
      - Não começa com HTML/XML/JSON puro
    Bundles modernos (Webpack/Vite/esbuild) IIFEs e arrow functions são aceitos.
    """
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct or "ecmascript" in ct:
        return True

    stripped = content.strip()
    if stripped.startswith(("<html", "<HTML", "<!DOCTYPE", "<!doctype", "<?xml")):
        return False
    # JSON puro na raiz sem código JS visível
    if re.match(r'^\s*[{\[]', stripped) and not re.search(
            r'(?:var |let |const |function|=>|\bif\b|\bfor\b)', stripped[:500]):
        return False
    return True


def _secret_context(content: str, start: int, end: int, radius: int = 90) -> str:
    left  = max(0, start - radius)
    right = min(len(content), end + radius)
    return content[left:right].replace("\r", " ").replace("\n", " ").strip()


# Lock global para escrita nos arquivos de segredos (threads paralelas)
_secret_write_lock = threading.Lock()


def _append_secret(finding: dict, cfg: dict) -> None:
    """
    Persiste um achado em:
      - secrets.txt   (legível)
      - secrets.csv
      - secrets.jsonl
    Cria cabeçalho do CSV apenas na primeira linha.
    """
    with _secret_write_lock:
        # TXT
        append_line_to_file(
            cfg["secrets_txt"],
            f"[{finding['type']}] {finding['url']}\n"
            f"VALUE  : {finding['value']}\n"
            f"CONTEXT: {finding['context'][:300]}\n"
            + "-" * 60
        )
        # CSV
        csv_new = not cfg["secrets_csv"].exists()
        cfg["secrets_csv"].parent.mkdir(parents=True, exist_ok=True)
        with open(cfg["secrets_csv"], "a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["type", "url", "value", "context"])
            if csv_new:
                w.writeheader()
            w.writerow({
                "type":    finding["type"],
                "url":     finding["url"],
                "value":   finding["value"],
                "context": finding["context"][:300],
            })
        # JSONL
        append_line_to_file(
            cfg["secrets_jsonl"],
            json.dumps({
                "type":    finding["type"],
                "url":     finding["url"],
                "value":   finding["value"],
                "context": finding["context"][:300],
            }, ensure_ascii=False)
        )


def analyze_js_content(
    content: str,
    url: str,
    cfg: dict,
    logger: logging.Logger,
    google_keys_found: set,
    google_keys_lock: threading.Lock,
) -> int:
    found       = 0
    lines       = content.splitlines()
    generic_set = cfg["_generic_patterns"]

    def _line_at(pos: int) -> str:
        char_count = 0
        for line in lines:
            char_count += len(line) + 1
            if char_count >= pos:
                return line
        return ""

    for name, pattern in cfg["secret_patterns"].items():
        for match in pattern.finditer(content):
            raw_value = match.group(0)

            # Para padrões genéricos, extrai o grupo capturado se existir
            value = match.group(1) if match.lastindex and match.lastindex >= 1 else raw_value

            # Filtragem extra para padrões genéricos
            if name in generic_set:
                context_line = _line_at(match.start())
                if not is_likely_real_credential(value, context_line):
                    logger.debug("[SKIP FP] %s → %s", name, value[:60])
                    continue

            context = _secret_context(content, match.start(), match.end())
            logger.warning("[!!!] %s → %s | %s", name, value[:80], url)

            finding = {"type": name, "value": value, "url": url, "context": context}
            _append_secret(finding, cfg)
            found += 1

            if name == "google_api_key":
                with google_keys_lock:
                    google_keys_found.add(value)

    # Detecção de ofuscação por char-codes
    for obf in scan_charcode_obfuscation(content, url, logger):
        _append_secret(obf, cfg)
        found += 1

    # Endpoints de API
    endpoints: set[str] = set()
    for pattern in cfg["api_endpoint_patterns"]:
        for m in pattern.finditer(content):
            endpoints.add(m.group(0).strip('"\'`'))
    if endpoints:
        with _secret_write_lock:
            for ep in sorted(endpoints):
                append_line_to_file(cfg["api_endpoints_file"], f"{ep}  ←  {url}")

    return found


def process_js(
    url: str,
    cfg: dict,
    logger: logging.Logger,
    google_keys_found: set,
    google_keys_lock: threading.Lock,
    get_fn,
) -> int:
    try:
        resp = get_fn(url)
    except requests.exceptions.SSLError as exc:
        logger.debug("SSL error em %s: %s", url, exc)
        return 0
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        logger.debug("Conexão falhou/timeout em %s", url)
        return 0
    except Exception as exc:
        logger.debug("Erro em %s: %s", url, exc)
        return 0

    if resp.status_code != 200:
        return 0

    content = resp.text
    if not is_valid_js(resp, content):
        logger.debug("Não é JS: %s", url)
        return 0

    return analyze_js_content(content, url, cfg, logger, google_keys_found, google_keys_lock)


def analyze_all_js(cfg: dict, logger: logging.Logger) -> tuple[int, set]:
    if not cfg["js_file"].exists():
        logger.warning("Nenhum arquivo JS para analisar.")
        return 0, set()

    urls = [u.strip() for u in cfg["js_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    if not urls:
        return 0, set()

    total_found:      int  = 0
    google_keys_found: set = set()
    google_keys_lock       = threading.Lock()
    get_fn                 = _make_retrying_get(cfg)

    logger.info("Analisando %d arquivos JS com %d workers…", len(urls), cfg["js_workers"])

    with ThreadPoolExecutor(max_workers=cfg["js_workers"]) as executor:
        futures = {
            executor.submit(
                process_js, url, cfg, logger,
                google_keys_found, google_keys_lock, get_fn
            ): url for url in urls
        }
        for future in as_completed(futures):
            try:
                total_found += future.result()
            except Exception as exc:
                logger.error("Thread error: %s", exc)

    if total_found:
        logger.info("Segredos encontrados em JS: %d → %s", total_found, cfg["secrets_txt"])
    else:
        logger.info("Nenhum segredo encontrado em JS.")

    return total_found, google_keys_found


# ─────────────────────────────────────────────────────────────────────────────
# Etapa extra: Análise por subdomínio
# ─────────────────────────────────────────────────────────────────────────────

def _probe_alive_urls(urls: list[str], timeout: int, logger: logging.Logger) -> list[str]:
    """Valida quais URLs respondem usando httpx. Retorna lista de URLs vivas."""
    if not urls:
        return []
    if not tool_available("httpx"):
        logger.warning("httpx não encontrado — usando todos os subdomínios sem validação.")
        return urls

    input_text = "\n".join(urls) + "\n"
    try:
        result = subprocess.run(
            ["httpx", "-silent",
             "-mc", "200,201,204,301,302,307,308,403",
             "-threads", "50",
             "-timeout", str(timeout)],
            input=input_text,
            capture_output=True, text=True, timeout=300,
        )
        return [u.strip() for u in result.stdout.splitlines() if u.strip()]
    except Exception as exc:
        logger.error("httpx (subs): %s", exc)
        return urls


def _collect_js_from_sub(
    sub_url: str,
    cfg: dict,
    logger: logging.Logger,
) -> set[str]:
    """
    Coleta URLs de JS de um subdomínio específico usando hakrawler e gospider.
    Retorna conjunto de URLs de JS filtradas (sem CDN, sem .map).
    """
    all_urls: set[str] = set()

    js_re = re.compile(
        r'(?:\.js(?:\?[^\s]*)?$'
        r'|/(?:static|assets|dist|build|chunks|bundles)/[^\s]*\.js)',
        re.I,
    )

    # hakrawler via stdin
    if tool_available("hakrawler"):
        lines = run_cmd(
            ["hakrawler", "-d", "2", "-u", "-t", "8", "-insecure"],
            logger,
            stdin=sub_url + "\n",
            timeout=60,
        )
        all_urls.update(lines)

    # gospider
    if tool_available("gospider"):
        raw = run_cmd([
            "gospider", "-s", sub_url,
            "-c", "5", "-d", "2", "--js", "-q",
        ], logger, timeout=60)
        for line in raw:
            m = re.search(r'https?://[^\s"\'<>\]]+', line)
            if m:
                all_urls.add(m.group(0).rstrip('.,;)"\'>]'))

    # Filtra apenas JS, sem CDN, sem source maps
    js_urls: set[str] = set()
    for url in all_urls:
        if _CDN_DOMAINS_RE.search(url):
            continue
        if url.endswith(".js.map"):
            continue
        if js_re.search(url):
            js_urls.add(url)

    return js_urls


def analyze_subdomains(
    root_domain: str,
    args: argparse.Namespace,
    cfg: dict,
    logger: logging.Logger,
    all_google_keys: set,
    google_keys_lock: threading.Lock,
) -> dict:
    """
    Enumera subdomínios do domínio raiz, valida quais estão vivos e
    executa análise completa de JS em cada um separadamente.

    Retorna dict com estatísticas agregadas por subdomínio.
    """
    banner_sub = "=" * 60
    logger.info(banner_sub)
    logger.info("ANÁLISE DE SUBDOMÍNIOS — %s", root_domain)
    logger.info(banner_sub)

    # ── 1. Enumeração ─────────────────────────────────────────────────────────
    subs: set[str] = set()

    if tool_available("subfinder"):
        logger.info("[subfinder] enumerando subdomínios de %s…", root_domain)
        lines = run_cmd(["subfinder", "-d", root_domain, "-silent"], logger, timeout=300)
        subs.update(lines)
        logger.info("[subfinder] %d subdomínios", len(lines))
    else:
        logger.warning("subfinder não encontrado — pulando enumeração de subdomínios.")
        return {}

    # Filtra subdomínios válidos (descarta wildcards e o próprio root)
    subs_clean = sorted({
        s.strip().lower() for s in subs
        if s.strip()
        and "*" not in s
        and s.strip().lower() != root_domain
        and root_domain in s
    })

    if not subs_clean:
        logger.info("Nenhum subdomínio encontrado para %s.", root_domain)
        return {}

    logger.info("Subdomínios únicos: %d", len(subs_clean))

    # ── 2. Validação de hosts vivos ───────────────────────────────────────────
    sub_urls = [f"https://{s}" for s in subs_clean]
    alive_urls = _probe_alive_urls(sub_urls, cfg["request_timeout"], logger)

    # Tenta http se https não respondeu
    https_alive = set(alive_urls)
    http_candidates = [
        f"http://{s}" for s in subs_clean
        if f"https://{s}" not in https_alive
    ]
    if http_candidates:
        http_alive = _probe_alive_urls(http_candidates, cfg["request_timeout"], logger)
        alive_urls.extend(http_alive)

    alive_urls = sorted(set(alive_urls))
    logger.info("Subdomínios vivos: %d / %d", len(alive_urls), len(subs_clean))

    if not alive_urls:
        logger.info("Nenhum subdomínio vivo encontrado.")
        return {}

    # Salva lista de subdomínios vivos na pasta do domínio raiz
    write_if_not_empty(
        cfg["base_dir"] / "subdomains_alive.txt",
        alive_urls, logger,
    )

    # ── 3. Análise de JS por subdomínio ───────────────────────────────────────
    sub_stats: dict[str, dict] = {}
    get_fn = _make_retrying_get(cfg)

    # Arquivo consolidado de segredos de subdomínios (mesmo formato do root)
    # Os achados também vão para cfg["secrets_*"] do root para aparecer no sumário

    for sub_url in alive_urls:
        sub_host = re.sub(r'^https?://', '', sub_url).rstrip('/')
        logger.info("─── Analisando subdomínio: %s", sub_host)

        # Pasta de saída específica deste subdomínio
        safe_sub  = re.sub(r'[^\w\-.]', '_', sub_host)
        sub_dir   = cfg["base_dir"] / "subdomains" / safe_sub
        sub_dir.mkdir(parents=True, exist_ok=True)

        # Coleta JS específico do subdomínio
        js_urls = _collect_js_from_sub(sub_url, cfg, logger)
        logger.info("  JS encontrado: %d arquivos", len(js_urls))

        if not js_urls:
            sub_stats[sub_host] = {"js": 0, "secrets": 0}
            continue

        # Salva lista de JS do subdomínio
        write_if_not_empty(sub_dir / "js_urls.txt", sorted(js_urls), logger)

        # Analisa cada arquivo JS
        sub_findings = 0
        for js_url in js_urls:
            try:
                resp = get_fn(js_url)
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            content = resp.text
            if not is_valid_js(resp, content):
                continue

            # analyze_js_content usa cfg["secrets_*"] do root → achados consolidados
            n = analyze_js_content(
                content, js_url, cfg, logger,
                all_google_keys, google_keys_lock,
            )
            sub_findings += n

        sub_stats[sub_host] = {
            "js":      len(js_urls),
            "secrets": sub_findings,
        }

        if sub_findings:
            logger.warning("  [!!!] %d segredo(s) em %s", sub_findings, sub_host)
        else:
            logger.info("  Nenhum segredo em %s", sub_host)

    # ── 4. Sumário de subdomínios ─────────────────────────────────────────────
    total_subs_secrets = sum(v["secrets"] for v in sub_stats.values())
    total_subs_js      = sum(v["js"]      for v in sub_stats.values())

    logger.info(banner_sub)
    logger.info("SUBDOMÍNIOS — RESUMO")
    logger.info("  Total analisados : %d", len(sub_stats))
    logger.info("  JS coletados     : %d", total_subs_js)
    logger.info("  Segredos totais  : %d", total_subs_secrets)
    logger.info(banner_sub)

    # Salva relatório de subdomínios
    report_lines = [
        "ANÁLISE POR SUBDOMÍNIO",
        f"Domínio raiz: {root_domain}",
        "=" * 60,
        "",
    ]
    for sub, data in sorted(sub_stats.items(), key=lambda x: -x[1]["secrets"]):
        status = "[!!!]" if data["secrets"] > 0 else "[ ok]"
        report_lines.append(
            f"{status} {sub:<50}  JS: {data['js']:>4}  Segredos: {data['secrets']:>4}"
        )

    write_if_not_empty(
        cfg["base_dir"] / "subdomains_report.txt",
        report_lines, logger,
    )

    return {
        "subs_found":   len(subs_clean),
        "subs_alive":   len(alive_urls),
        "subs_js":      total_subs_js,
        "subs_secrets": total_subs_secrets,
    }



def write_summary(cfg: dict, logger: logging.Logger, stats: dict) -> None:
    def _count(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip())

    # Contagem por tipo a partir do JSONL (se existir)
    type_counts: dict[str, int] = collections.Counter()
    if cfg["secrets_jsonl"].exists():
        for line in cfg["secrets_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                obj = json.loads(line)
                type_counts[obj.get("type", "?")] += 1
            except json.JSONDecodeError:
                pass

    # Chaves Google vulneráveis
    vuln_google = 0
    if cfg["google_report_file"].exists():
        for line in cfg["google_report_file"].read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.search(r'Vulneráveis:\s*(\d+)/', line)
            if m and int(m.group(1)) > 0:
                vuln_google += 1

    def _f(key: str) -> str:
        return str(stats.get(key, 0)).rjust(6)

    lines = [
        "=" * 64,
        "  SUMÁRIO DE RECONHECIMENTO",
        f"  Alvo  : {cfg['domain']}",
        f"  Saída : {cfg['base_dir']}",
        "=" * 64,
        "",
        f"  URLs coletadas           : {_f('urls_total')}",
        f"  URLs ativas (httpx)      : {_f('urls_alive')}",
        f"  Arquivos JS              : {_f('js_total')}",
        f"  URLs sensíveis           : {_f('sensitive_total')}",
        "",
        f"  Segredos encontrados     : {_f('js_findings')}",
    ]

    if type_counts:
        lines.append("")
        lines.append("  Por tipo:")
        for name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"    {name}: {count}")

    lines += [
        "",
        f"  Google Keys encontradas  : {_f('google_keys')}",
        f"  Google Keys vulneráveis  : {str(vuln_google).rjust(6)}",
        "",
        f"  Segredos em .env/.conf   : {_f('sensitive_findings')}",
        f"  XSS confirmados (dalfox) : {_f('xss_hits')}",
        f"  SSRF/Redirect hits       : {_f('ssrf_redirect_hits')}",
        f"  Endpoints de API         : {str(_count(cfg['api_endpoints_file'])).rjust(6)}",
    ]

    # Estatísticas de subdomínios (só aparece se a análise foi executada)
    if stats.get("subs_found", 0) > 0:
        lines += [
            "",
            "── Subdomínios ──────────────────────────────────────────",
            f"  Subdomínios encontrados  : {_f('subs_found')}",
            f"  Subdomínios vivos        : {_f('subs_alive')}",
            f"  JS em subdomínios        : {_f('subs_js')}",
            f"  Segredos em subdomínios  : {_f('subs_secrets')}",
        ]
        sub_report = cfg["base_dir"] / "subdomains_report.txt"
        if sub_report.exists():
            lines.append(f"  Relatório subs           : {sub_report}")

    # Arquivos gerados (só lista os que existem)
    output_files = [
        ("Segredos TXT",    cfg["secrets_txt"]),
        ("Segredos CSV",    cfg["secrets_csv"]),
        ("Segredos JSONL",  cfg["secrets_jsonl"]),
        ("Google Keys",     cfg["google_report_file"]),
        ("API Endpoints",   cfg["api_endpoints_file"]),
        ("Sensíveis",       cfg["sensitive_report"]),
        ("Log completo",    cfg["log_file"]),
    ]
    existing = [(label, path) for label, path in output_files if path.exists()]
    if existing:
        lines += ["", "  Arquivos gerados:"]
        for label, path in existing:
            lines.append(f"    {label}: {path}")

    lines += ["", "=" * 64]

    write_if_not_empty(cfg["summary_file"], lines, logger)
    for line in lines:
        logger.info(line)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reconhecimento web focado em JS: coleta URLs, extrai segredos, valida chaves."
    )
    parser.add_argument("domain",             nargs="?",           help="Domínio alvo. Ex: exemplo.com.br")
    parser.add_argument("--no-dalfox",        action="store_true", help="Pula probe XSS com dalfox")
    parser.add_argument("--no-ssrf-probe",    action="store_true", help="Pula probe SSRF/redirect")
    parser.add_argument("--no-sensitive-dl",  action="store_true", help="Pula download de arquivos sensíveis")
    parser.add_argument("--no-httpx",         action="store_true", help="Usa todas as URLs sem validar com httpx")
    parser.add_argument("--no-google-val",    action="store_true", help="Pula validação de endpoints Google")
    parser.add_argument("--no-subs",          action="store_true", help="Pula análise de subdomínios")
    parser.add_argument("--workers",          type=int, default=20, help="Workers JS (padrão: 20)")
    parser.add_argument("--timeout",          type=int, default=10, help="Timeout de requisições em segundos (padrão: 10)")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args   = parse_args()
    domain = args.domain or input("Domínio: ").strip()
    if not domain:
        print("Domínio inválido.")
        sys.exit(1)

    cfg                     = get_config(domain)
    cfg["js_workers"]       = max(1, args.workers)
    cfg["request_timeout"]  = max(1, args.timeout)
    logger                  = setup_logging(cfg["log_file"])
    stats: dict[str, int]   = {}

    logger.info("=" * 60)
    logger.info("Iniciando recon para: %s", domain)
    logger.info("Diretório de saída : %s", cfg["base_dir"])
    logger.info("=" * 60)

    # 1. Coleta de URLs
    stats["urls_total"] = collect_urls(cfg, logger)

    # 2. Validação de URLs ativas
    if args.no_httpx:
        cfg["_active_urls_file"] = cfg["urls_file"]
        stats["urls_alive"]      = stats["urls_total"]
        logger.info("--no-httpx: usando todas as URLs.")
    else:
        stats["urls_alive"] = validate_alive_urls(cfg, logger)

    # 3. GF + probes
    run_gf(cfg, logger)
    stats["xss_hits"]           = 0 if args.no_dalfox     else probe_xss(cfg, logger)
    stats["ssrf_redirect_hits"] = 0 if args.no_ssrf_probe else probe_ssrf_redirect(cfg, logger)

    # 4. Arquivos sensíveis
    stats["sensitive_total"]    = extract_sensitive_urls(cfg, logger)
    stats["sensitive_findings"] = 0 if args.no_sensitive_dl \
                                    else download_and_analyze_sensitive(cfg, logger)

    # 5. Coleta de JS do domínio raiz
    stats["js_total"] = collect_js(cfg, logger)

    # 6. Análise de JS + Google Keys do domínio raiz
    # Lock compartilhado — será reutilizado na análise de subdomínios
    google_keys_found: set        = set()
    google_keys_lock: threading.Lock = threading.Lock()

    js_findings, gkeys = analyze_all_js(cfg, logger)
    stats["js_findings"] = js_findings
    with google_keys_lock:
        google_keys_found.update(gkeys)

    # 7. Análise de subdomínios (JS + segredos em cada sub vivo)
    if args.no_subs:
        logger.info("--no-subs: análise de subdomínios pulada.")
        stats.update({"subs_found": 0, "subs_alive": 0, "subs_js": 0, "subs_secrets": 0})
    else:
        sub_stats = analyze_subdomains(
            domain, args, cfg, logger,
            google_keys_found, google_keys_lock,
        )
        stats.update(sub_stats)

    stats["google_keys"] = len(google_keys_found)

    # 8. Validação de Google Keys (todas — raiz + subdomínios)
    if args.no_google_val:
        if google_keys_found:
            write_if_not_empty(cfg["google_keys_file"], sorted(google_keys_found), logger)
        logger.info("--no-google-val: validação de endpoints Google pulada.")
    else:
        validate_all_google_keys(google_keys_found, cfg, logger)

    # 9. Sumário
    write_summary(cfg, logger, stats)

    logger.info("=" * 60)
    logger.info("Recon finalizado. Log: %s", cfg["log_file"])
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
