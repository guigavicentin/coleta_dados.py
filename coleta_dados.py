#!/usr/bin/env python3
"""
recon.py — Script de reconhecimento web passivo/ativo.

Etapas:
  1. Coleta de URLs (gau + waybackurls + katana)
  2. Validação de URLs ativas com httpx
  3. Filtragem com GF (xss, sqli, ssrf, redirect, ssti)
  4. Extração de arquivos sensíveis por extensão + download e análise
  5. Coleta de arquivos JS
  6. Análise de segredos em JS — inclui detecção e validação de Google API Keys
  7. Probe de parâmetros vulneráveis (XSS via dalfox, SSRF/redirect via qsreplace)
  8. Extração de endpoints de API expostos em JS
  9. Relatório consolidado final

Melhorias aplicadas em relação à versão anterior:
  - Validação de URLs ativas (httpx) antes do GF e análise JS
  - is_valid_js() tolerante a bundles Webpack/Vite/esbuild modernos
  - secret_patterns expandido: GitHub, OpenAI, SendGrid, Slack, Twilio, RSA keys,
    Amazon MWS, Google OAuth client, e mais
  - Race condition corrigida em google_keys_found com threading.Lock
  - Rate limiting com tenacity (backoff exponencial + respeito a Retry-After)
  - Detecção de endpoints de API internos em JS
  - Download e análise de arquivos sensíveis (.env, .conf, etc.)
  - Probe de XSS (dalfox) e SSRF/open-redirect (qsreplace+curl) nas URLs filtradas pelo GF
  - Sumário consolidado ao final
"""

import argparse
import csv
import json
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

# ── Filtros de qualidade para password/senha ──────────────────────────────────

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

_UI_CONTEXT_RE = re.compile(
    r'(label|placeholder|hint|aria[-_]label|title|description|'
    r'tooltip|helper|message|text|i18n|translate|t\()',
    re.I,
)

_MIN_VALUE_LEN = 8
_MIN_ENTROPY = 3.0


# ── Helpers para padrões com contexto ────────────────────────────────────────

def _regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


def _ctx_regex(context: str, value_pattern: str, flags: int = re.I, window: int = 80) -> re.Pattern:
    """
    Cria regex que exige uma palavra de contexto próxima do segredo.
    Ajuda a reduzir falsos positivos em UUIDs, hex strings e tokens curtos.
    """
    return re.compile(
        rf'(?is)(?:{context})' + r'.{0,' + str(window) + r'}' + rf'({value_pattern})',
        flags,
    )


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_value(raw_match: str) -> str:
    m = re.search(r'[:=]\s*["\']([^"\']*)', raw_match)
    return m.group(1).strip() if m else ""


def is_likely_real_credential(raw_match: str, context_line: str = "") -> bool:
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

_CHARCODE_ARRAY_RE = re.compile(r'\[\s*(\d{2,3}(?:\s*,\s*\d{2,3}){5,})\s*\]')

_DECODED_SECRET_CHECKS: list[tuple[str, re.Pattern]] = [
    ("bcrypt_hash_decoded",   re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}')),
    ("google_key_decoded",    re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("aws_key_decoded",       re.compile(r'AKIA[0-9A-Z]{16}')),
    ("jwt_decoded",           re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),
    ("high_entropy_string",   None),
]

_DECODED_ENTROPY_MIN = 3.5


def _decode_charcode_array(array_str: str) -> str | None:
    try:
        codes = [int(x.strip()) for x in array_str.split(",")]
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
    found = 0
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


# ── Logging ───────────────────────────────────────────────────────────────────

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
    (base / "sensitive_downloads").mkdir(exist_ok=True)
    (base / "secrets").mkdir(exist_ok=True)
    (base / "secrets" / "by_type").mkdir(exist_ok=True)
    (base / "secrets" / "values_only").mkdir(exist_ok=True)

    return {
        "domain": domain,
        "base_dir": base,
        "urls_file":           base / "urls.txt",
        "urls_alive_file":     base / "urls_alive.txt",
        "js_file":             base / "js_urls.txt",
        "result_file":         base / "js_sensiveis.txt",
        "secrets_dir":          base / "secrets",
        "secrets_by_type_dir":  base / "secrets" / "by_type",
        "secrets_values_dir":   base / "secrets" / "values_only",
        "secrets_all_txt":      base / "secrets" / "all_secrets.txt",
        "secrets_all_csv":      base / "secrets" / "all_secrets.csv",
        "secrets_all_jsonl":    base / "secrets" / "all_secrets.jsonl",
        "google_keys_file":    base / "google_keys.txt",
        "google_report_file":  base / "google_keys_report.txt",
        "log_file":            base / "recon.log",
        "gf_dir":              base / "gf",
        "sensitive_file":      base / "urls_analisar.txt",
        "sensitive_dir":       base / "sensitive_downloads",
        "sensitive_analysis":  base / "sensitive_analysis.txt",
        "api_endpoints_file":  base / "api_endpoints.txt",
        "summary_file":        base / "SUMMARY.txt",

        "gf_patterns": ["xss", "sqli", "ssrf", "redirect", "ssti"],

        "sensitive_regex": re.compile(
            r"\.(php|html|xml|zip|gz|env|log|bak|sql|txt|conf|ini|yml|yaml|db|pem|key|crt|sh|py|jsp|asp|aspx)$",
            re.IGNORECASE,
        ),

        # Padrões de segredos EXPANDIDOS
        "secret_patterns": {
            # ── Google / Firebase ─────────────────────────────────────────────
            "google_api_key":         _regex(r'AIza[0-9A-Za-z\-_]{35}'),
            "google_oauth_client":    _regex(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
            "firebase_database":      _regex(r'https?://[a-z0-9\-]+\.firebaseio\.com', re.I),
            "gcp_service_account":    _regex(r'"type"\s*:\s*"service_account"'),

            # ── AWS / Cloud / Infra ──────────────────────────────────────────
            "aws_key":                _regex(r'AKIA[0-9A-Z]{16}'),
            "amazon_mws":             _regex(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            "azure_storage_key":      _regex(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
            "azure_client_secret":    _ctx_regex(r'azure|client[_-]?secret|clientSecret', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            "heroku_api_key":         _ctx_regex(r'heroku', r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
            "digitalocean_token":     _regex(r'dop_v1_[a-f0-9]{64}'),
            "cloudflare_api_key":     _ctx_regex(r'cloudflare|CF_API|CF-|cf[_-]?api', r'[0-9a-f]{37}'),
            "terraform_cloud_token":  _regex(r'[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_=]{60,}'),

            # ── Pagamento / Financeiro ───────────────────────────────────────
            "stripe_secret":          _regex(r'sk_live_[0-9a-zA-Z]{24,}'),
            "stripe_publishable":     _regex(r'pk_live_[0-9a-zA-Z]{24,}'),
            "stripe_webhook":         _regex(r'whsec_[a-zA-Z0-9]{32,}'),
            "paypal_client_id":       _regex(r'\bA[A-Za-z0-9\-_]{79}\b'),
            "braintree_token":        _regex(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),
            "square_access_token":    _regex(r'sq0atp-[0-9A-Za-z\-_]{22}'),
            "square_oauth_secret":    _regex(r'sq0csp-[0-9A-Za-z\-_]{43}'),

            # ── Comunicação / Email / SMS ────────────────────────────────────
            "sendgrid_key":           _regex(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
            "mailgun_api_key":        _regex(r'key-[0-9a-zA-Z]{32}'),
            "mailchimp_api_key":      _regex(r'[0-9a-f]{32}-us[0-9]{1,2}'),
            "postmark_token":         _ctx_regex(r'postmark', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
            "vonage_api_secret":      _ctx_regex(r'nexmo|vonage|api_secret', r'[a-zA-Z0-9]{8}'),
            "messagebird_token":      _ctx_regex(r'messagebird', r'[0-9a-zA-Z]{25}'),
            "pagerduty_token":        _regex(r'u\+[a-zA-Z0-9]{18}'),
            "twilio_account_sid":     _regex(r'AC[a-z0-9]{32}'),
            "twilio_auth_token":      _regex(r'SK[a-z0-9]{32}'),

            # ── Monitoramento / Analytics / DevOps ───────────────────────────
            "datadog_api_key":        _ctx_regex(r'DD_API_KEY|datadog', r'[a-f0-9]{32}'),
            "new_relic_key":          _regex(r'NRAK-[A-Z0-9]{27}'),
            "sentry_dsn":             _regex(r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'),
            "grafana_token":          _regex(r'glc_[A-Za-z0-9+/]{32,}'),
            "circleci_token":         _regex(r'circle-token\s+[a-f0-9]{40}'),
            "travis_token":           _ctx_regex(r'travis', r'[a-zA-Z0-9]{22}'),
            "npm_token":              _regex(r'npm_[A-Za-z0-9]{36}'),
            "pypi_token":             _regex(r'pypi-[A-Za-z0-9_\-]{50,}'),
            "dockerhub_pat":          _regex(r'dckr_pat_[A-Za-z0-9_\-]{27}'),
            "artifactory_key":        _regex(r'AKC[a-zA-Z0-9]{10,}'),

            # ── Repositórios / CI-CD ─────────────────────────────────────────
            "github_pat":             _regex(r'gh[pousr]_[A-Za-z0-9]{36}'),
            "github_oauth":           _regex(r'gho_[A-Za-z0-9]{36}'),
            "gitlab_pat":             _regex(r'glpat-[A-Za-z0-9\-_]{20}'),
            "gitlab_pipeline_token":  _regex(r'glptt-[a-f0-9]{40}'),
            "bitbucket_app_password": _ctx_regex(r'x-token-auth|bitbucket', r'[A-Za-z0-9_\-]{20,}'),
            "hashicorp_vault_token":  _regex(r'hvs\.[A-Za-z0-9_\-]{90,}'),
            "pulumi_token":           _regex(r'pul-[a-f0-9]{40}'),

            # ── Banco de Dados / Connection Strings ──────────────────────────
            "mongodb_atlas_dsn":      _regex(r'mongodb\+srv://[^:\s]+:[^@\s]+@', re.I),
            "postgres_dsn":           _regex(r'postgres(?:ql)?://[^:\s]+:[^@\s]+@', re.I),
            "mysql_dsn":              _regex(r'mysql://[^:\s]+:[^@\s]+@', re.I),
            "redis_password_dsn":     _regex(r'redis://:([^@\s]+)@', re.I),
            "elasticsearch_dsn":      _regex(r'https?://[^:\s]+:[^@\s]+@[^\s"\']*elastic[^\s"\']*', re.I),

            # ── Miscelânea alto valor ────────────────────────────────────────
            "shopify_token":          _regex(r'shp(?:at|ss)_[a-fA-F0-9]{32}'),
            "linear_api_key":         _regex(r'lin_api_[A-Za-z0-9]{40}'),
            "notion_token":           _regex(r'secret_[A-Za-z0-9]{43}'),
            "airtable_key":           _regex(r'key[A-Za-z0-9]{14}'),
            "mapbox_token":           _regex(r'pk\.eyJ1[A-Za-z0-9._\-]+'),
            "rapidapi_key":           _ctx_regex(r'X-RapidAPI-Key|rapidapi', r'[a-zA-Z0-9]{50}'),
            "wpengine_auth":          _ctx_regex(r'wpe_auth|wpengine', r'[A-Za-z0-9_\-]{20,}'),

            # ── OpenAI / Slack ───────────────────────────────────────────────
            "openai_key":             _regex(r'sk-[a-zA-Z0-9]{48}'),
            "slack_token":            _regex(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
            "slack_webhook":          _regex(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),

            # ── Chaves privadas ───────────────────────────────────────────────
            "private_key":            _regex(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),

            # ── Genéricos ─────────────────────────────────────────────────────
            "api_key":                _regex(r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}', re.I),
            "token":                  _regex(r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-.]{16,}', re.I),
            "jwt":                    _regex(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
            "secret":                 _regex(r'secret["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-/+=]{16,}', re.I),
            "authorization":          _regex(r'Bearer\s+[A-Za-z0-9_\-.]{16,}'),
            "password":               _regex(r'password["\']?\s*[:=]\s*["\'][^"\']{8,}', re.I),
            "senha":                  _regex(r'senha["\']?\s*[:=]\s*["\'][^"\']{8,}', re.I),

            # ── Hashes hardcoded ──────────────────────────────────────────────
            "bcrypt_hash":            _regex(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'),
            "md5_hash":               _regex(r'(?:hash|md5|digest)["\']?\s*[:=]\s*["\'][0-9a-f]{32}["\']', re.I),
            "sha_hash":               _regex(r'(?:hash|sha(?:1|256)?|digest)["\']?\s*[:=]\s*["\'][0-9a-f]{40,64}["\']', re.I),
        },

        # Padrões para endpoints de API expostos em JS
        "api_endpoint_patterns": [
            re.compile(r'["\`](/api/v\d[a-zA-Z0-9/_\-]*)["\`]'),
            re.compile(r'["\`](/graphql)["\`\s/]', re.I),
            re.compile(r'["\`](/gql)["\`\s/]', re.I),
            re.compile(r'https?://(?:internal|admin|dev|staging|api)\.[a-z0-9\-]+\.[a-z]+[^\s"\'`]*'),
            re.compile(r'["\`](/v\d+/[a-zA-Z0-9/_\-]{4,})["\`]'),
        ],

        "google_key_regex": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),

        "headers":          {"User-Agent": "Mozilla/5.0 recon"},
        "js_workers":       20,
        "request_timeout":  10,

        # Padrões sensíveis para análise de arquivos baixados (.env, .conf, etc.)
        "sensitive_content_patterns": [
            re.compile(r'(?:DB_PASS|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD)\s*=\s*\S+', re.I),
            re.compile(r'(?:SECRET_KEY|APP_KEY|ENCRYPTION_KEY)\s*=\s*\S+', re.I),
            re.compile(r'(?:AWS_SECRET|AWS_ACCESS_KEY)\s*=\s*\S+', re.I),
            re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            re.compile(r'password\s*=\s*\S+', re.I),
        ],
    }


# ── Rate-limited requests ─────────────────────────────────────────────────────

_request_logger = logging.getLogger("recon.requests")


def _make_retrying_get(cfg: dict):
    """
    Retorna uma função get() com retry + backoff exponencial.
    Respeita o header Retry-After quando presente.
    """
    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=2, max=30),
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
        # Respeita Retry-After (429 / 503)
        if resp.status_code in (429, 503):
            retry_after = int(resp.headers.get("Retry-After", 5))
            _request_logger.debug("Rate-limited em %s — aguardando %ds", url, retry_after)
            time.sleep(retry_after)
            resp.raise_for_status()   # força nova tentativa
        return resp

    return _get


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


# ── Etapa 2: Validação de URLs ativas (httpx) ────────────────────────────────

def validate_alive_urls(cfg: dict, logger: logging.Logger) -> int:
    """
    Filtra apenas URLs que respondem com HTTP 2xx/3xx usando httpx.
    Salva o resultado em urls_alive.txt e atualiza cfg para as etapas seguintes.
    """
    logger.info("Validando URLs ativas com httpx…")
    try:
        result = subprocess.run(
            [
                "httpx",
                "-l", str(cfg["urls_file"]),
                "-silent",
                "-mc", "200,201,204,301,302,307,308,403",
                "-threads", "50",
                "-timeout", "10",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        alive = [u.strip() for u in result.stdout.splitlines() if u.strip()]
        if result.stderr:
            logger.debug("[stderr] httpx: %s", result.stderr.strip()[:200])
    except FileNotFoundError:
        logger.warning("httpx não encontrado — usando todas as URLs sem validação.")
        alive = [u.strip() for u in cfg["urls_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    except subprocess.TimeoutExpired:
        logger.warning("Timeout no httpx — usando todas as URLs.")
        alive = [u.strip() for u in cfg["urls_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    except Exception as exc:
        logger.error("Erro no httpx: %s", exc)
        alive = []

    cfg["urls_alive_file"].write_text("\n".join(alive) + "\n", encoding="utf-8")
    logger.info("URLs ativas: %d → %s", len(alive), cfg["urls_alive_file"])

    # Atualiza a referência principal para as etapas seguintes
    cfg["_active_urls_file"] = cfg["urls_alive_file"]
    return len(alive)


# ── Etapa 3: GF ───────────────────────────────────────────────────────────────

def run_gf(cfg: dict, logger: logging.Logger) -> None:
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    for pattern in cfg["gf_patterns"]:
        output = cfg["gf_dir"] / f"gf_{pattern}.txt"
        logger.info("GF pattern: %s", pattern)
        try:
            with open(output, "w", encoding="utf-8") as out:
                subprocess.run(
                    f"cat {source} | gf {pattern}",
                    shell=True, stdout=out, timeout=120,
                )
        except subprocess.TimeoutExpired:
            logger.warning("Timeout no gf %s", pattern)
        except Exception as exc:
            logger.error("Erro no gf %s: %s", pattern, exc)


# ── Etapa 3b: Probe de parâmetros vulneráveis ────────────────────────────────

def probe_xss(cfg: dict, logger: logging.Logger) -> int:
    """Executa dalfox nos resultados do gf_xss para confirmar XSS exploráveis."""
    xss_file = cfg["gf_dir"] / "gf_xss.txt"
    if not xss_file.exists() or xss_file.stat().st_size == 0:
        logger.info("Nenhuma URL para XSS probe.")
        return 0

    out_file = cfg["gf_dir"] / "dalfox_results.txt"
    logger.info("Rodando dalfox nas URLs de XSS…")
    try:
        result = subprocess.run(
            [
                "dalfox", "file", str(xss_file),
                "--silence",
                "--output", str(out_file),
                "--worker", "10",
                "--timeout", "10",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.stderr:
            logger.debug("[stderr] dalfox: %s", result.stderr.strip()[:200])
        hits = out_file.read_text(encoding="utf-8").count("[V]") if out_file.exists() else 0
        logger.info("dalfox: %d XSS confirmados → %s", hits, out_file)
        return hits
    except FileNotFoundError:
        logger.warning("dalfox não encontrado — pulando probe de XSS.")
        return 0
    except subprocess.TimeoutExpired:
        logger.warning("Timeout no dalfox.")
        return 0
    except Exception as exc:
        logger.error("Erro no dalfox: %s", exc)
        return 0


def probe_ssrf_redirect(cfg: dict, logger: logging.Logger) -> int:
    """
    Substitui parâmetros de URL por um payload SSRF/redirect usando qsreplace,
    depois dispara requisições com curl e verifica respostas.
    """
    found = 0

    probes = {
        "ssrf":     (cfg["gf_dir"] / "gf_ssrf.txt",     "http://169.254.169.254/latest/meta-data/"),
        "redirect": (cfg["gf_dir"] / "gf_redirect.txt", "https://evil.com"),
    }

    for kind, (gf_file, payload) in probes.items():
        if not gf_file.exists() or gf_file.stat().st_size == 0:
            continue

        out_file = cfg["gf_dir"] / f"{kind}_probe_results.txt"
        logger.info("Probe %s com qsreplace…", kind.upper())

        try:
            # Gera URLs com payload substituído
            qsr = subprocess.run(
                ["qsreplace", payload],
                input=gf_file.read_text(encoding="utf-8"),
                capture_output=True, text=True, timeout=60,
            )
            probe_urls = [u.strip() for u in qsr.stdout.splitlines() if u.strip()]
        except FileNotFoundError:
            logger.warning("qsreplace não encontrado — pulando probe %s.", kind.upper())
            continue
        except Exception as exc:
            logger.error("Erro no qsreplace (%s): %s", kind, exc)
            continue

        hits = []
        for url in probe_urls[:200]:   # limita para não demorar demais
            try:
                r = subprocess.run(
                    ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", url],
                    capture_output=True, text=True, timeout=10,
                )
                output = r.stdout.strip()
                code = output.split()[0] if output else "0"

                if kind == "redirect" and code in ("301", "302", "307", "308"):
                    if "evil.com" in output:
                        hits.append(url)
                elif kind == "ssrf" and code == "200":
                    hits.append(url)
            except Exception:
                pass

        if hits:
            out_file.write_text("\n".join(hits) + "\n", encoding="utf-8")
            logger.warning("[!!!] %s probe: %d possíveis hits → %s", kind.upper(), len(hits), out_file)
            found += len(hits)
        else:
            logger.info("%s probe: nenhum hit encontrado.", kind.upper())

    return found


# ── Etapa 4: Arquivos sensíveis ───────────────────────────────────────────────

def extract_sensitive(cfg: dict, logger: logging.Logger) -> int:
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    regex = cfg["sensitive_regex"]
    matches = []
    with open(source, encoding="utf-8") as f:
        for line in f:
            if regex.search(line.strip()):
                matches.append(line)
    cfg["sensitive_file"].write_text("".join(matches), encoding="utf-8")
    logger.info("Arquivos sensíveis: %d → %s", len(matches), cfg["sensitive_file"])
    return len(matches)


def download_and_analyze_sensitive(cfg: dict, logger: logging.Logger) -> int:
    """
    Faz download dos arquivos sensíveis listados e verifica o conteúdo
    em busca de credenciais/segredos expostos.
    """
    urls = [u.strip() for u in cfg["sensitive_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    if not urls:
        logger.info("Nenhum arquivo sensível para baixar.")
        return 0

    get = _make_retrying_get(cfg)
    findings = 0

    logger.info("Baixando e analisando %d arquivos sensíveis…", len(urls))

    with open(cfg["sensitive_analysis"], "w", encoding="utf-8") as report:
        for url in urls[:500]:   # limite de segurança
            try:
                resp = get(url)
            except Exception as exc:
                logger.debug("Falha ao baixar %s: %s", url, exc)
                continue

            if resp.status_code != 200:
                continue

            content = resp.text
            if len(content) > 2_000_000:   # ignora arquivos > 2 MB
                continue

            # Salva uma cópia local
            safe_name = re.sub(r'[^\w\-.]', '_', url)[:120]
            (cfg["sensitive_dir"] / safe_name).write_text(content, encoding="utf-8", errors="replace")

            # Analisa o conteúdo
            for pattern in cfg["sensitive_content_patterns"]:
                for match in pattern.finditer(content):
                    logger.warning("[!!!] Segredo em arquivo sensível → %s", url)
                    report.write(f"[SENSITIVE FILE] {url}\n{match.group(0)}\n" + "-" * 60 + "\n")
                    findings += 1

    logger.info("Achados em arquivos sensíveis: %d → %s", findings, cfg["sensitive_analysis"])
    return findings


# ── Etapa 5: Coleta de JS ─────────────────────────────────────────────────────

def collect_js(cfg: dict, logger: logging.Logger) -> int:
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    js_urls = set()
    with open(source, encoding="utf-8") as f:
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
    get = _make_retrying_get(cfg)

    def _check(name: str, url_tpl: str) -> tuple[str, str]:
        url = url_tpl.format(key=key)
        try:
            r = get(url)
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


# ── Etapa 6: Análise de JS ────────────────────────────────────────────────────

def is_valid_js(resp: requests.Response, content: str) -> bool:
    """
    Valida se o conteúdo parece ser JavaScript.

    Versão melhorada: aceita bundles modernos (Webpack, Vite, esbuild) que
    frequentemente começam com comentários, arrow functions ou IIFEs como
    `(()=>{...})()` — padrões rejeitados pela checagem anterior.

    A lógica agora é de exclusão: descarta apenas conteúdo claramente
    não-JS (HTML, JSON puro, XML).
    """
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct or "ecmascript" in ct:
        return True

    stripped = content.strip()

    # Descarta respostas claramente não-JS
    if stripped.startswith(("<html", "<HTML", "<!DOCTYPE", "<!doctype", "<?xml")):
        return False
    # JSON puro (objeto ou array na raiz) — sem código JS ao redor
    if re.match(r'^\s*[{\[]', stripped) and not re.search(r'(var |let |const |function|=>)', stripped[:500]):
        return False

    # Aceita qualquer outra coisa que não seja HTML/XML/JSON puro
    # (inclui bundles minificados, IIFEs, arrow functions, comentários, etc.)
    return True


def extract_api_endpoints(content: str, url: str, cfg: dict, logger: logging.Logger) -> int:
    """Extrai endpoints de API internos expostos no código JS."""
    found = 0
    endpoints = set()

    for pattern in cfg["api_endpoint_patterns"]:
        for match in pattern.finditer(content):
            endpoints.add(match.group(0).strip('"\'`'))

    if endpoints:
        with open(cfg["api_endpoints_file"], "a", encoding="utf-8") as f:
            for ep in sorted(endpoints):
                f.write(f"{ep}  ← {url}\n")
        logger.info("[API] %d endpoints extraídos de %s", len(endpoints), url)
        found = len(endpoints)

    return found



_secret_write_lock = threading.Lock()


def _safe_secret_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]+', '_', name).strip('_') or 'unknown'


def _secret_context(content: str, start: int, end: int, radius: int = 90) -> str:
    left = max(0, start - radius)
    right = min(len(content), end + radius)
    return content[left:right].replace("\r", " ").replace("\n", " ").strip()


def save_secret_finding(name: str, value: str, url: str, context: str, cfg: dict) -> None:
    """
    Salva TODO segredo encontrado em:
      - secrets/all_secrets.txt
      - secrets/all_secrets.csv
      - secrets/all_secrets.jsonl
      - secrets/by_type/<tipo>.txt
      - secrets/values_only/<tipo>.txt
    """
    safe_name = _safe_secret_filename(name)
    by_type_file = cfg["secrets_by_type_dir"] / f"{safe_name}.txt"
    values_file = cfg["secrets_values_dir"] / f"{safe_name}_values.txt"

    row = {
        "type": name,
        "url": url,
        "value": value,
        "context": context[:500],
    }

    with _secret_write_lock:
        with open(cfg["secrets_all_txt"], "a", encoding="utf-8") as f:
            f.write(f"[{name}] {url}\n{value}\ncontext: {context[:500]}\n" + "-" * 60 + "\n")

        csv_exists = cfg["secrets_all_csv"].exists()
        with open(cfg["secrets_all_csv"], "a", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "url", "value", "context"])
            if not csv_exists:
                writer.writeheader()
            writer.writerow(row)

        with open(cfg["secrets_all_jsonl"], "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

        with open(by_type_file, "a", encoding="utf-8") as f:
            f.write(f"URL: {url}\nVALUE: {value}\nCONTEXT: {context[:500]}\n" + "-" * 60 + "\n")

        with open(values_file, "a", encoding="utf-8") as f:
            f.write(value + "\n")



def initialize_secret_output_files(cfg: dict, logger: logging.Logger | None = None) -> None:
    """
    Cria antecipadamente os arquivos de saída para TODOS os padrões cadastrados.

    Assim, mesmo que um tipo não tenha achado, ele já aparece em:
      - secrets/by_type/<tipo>.txt
      - secrets/values_only/<tipo>_values.txt

    Também cria um índice em secrets/secret_types_index.txt.
    """
    secret_names = sorted(cfg["secret_patterns"].keys())
    index_file = cfg["secrets_dir"] / "secret_types_index.txt"

    with _secret_write_lock:
        for name in secret_names:
            safe_name = _safe_secret_filename(name)
            by_type_file = cfg["secrets_by_type_dir"] / f"{safe_name}.txt"
            values_file = cfg["secrets_values_dir"] / f"{safe_name}_values.txt"

            if not by_type_file.exists():
                by_type_file.write_text(
                    f"# Tipo: {name}\n# Nenhum achado registrado ainda.\n"
                    + "-" * 60 + "\n",
                    encoding="utf-8",
                )

            if not values_file.exists():
                values_file.write_text("", encoding="utf-8")

        index_lines = [
            "# Tipos de segredos monitorados",
            f"# Total: {len(secret_names)}",
            "",
        ]
        index_lines.extend(secret_names)
        index_file.write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    if logger:
        logger.info(
            "Arquivos de saída de segredos inicializados: %d tipos → %s",
            len(secret_names),
            cfg["secrets_by_type_dir"],
        )


def analyze_js_content(
    content: str,
    url: str,
    cfg: dict,
    logger: logging.Logger,
    google_keys_found: set,
    google_keys_lock: threading.Lock,
) -> int:
    found = 0
    lines = content.splitlines()

    def _get_context(pos: int) -> str:
        char_count = 0
        for line in lines:
            char_count += len(line) + 1
            if char_count >= pos:
                return line
        return ""

    _credential_patterns = {"password", "senha"}

    with open(cfg["result_file"], "a", encoding="utf-8") as out:
        for name, pattern in cfg["secret_patterns"].items():
            for match in pattern.finditer(content):
                value = match.group(0)

                if name in _credential_patterns:
                    context_line = _get_context(match.start())
                    if not is_likely_real_credential(value, context_line):
                        logger.debug("[SKIP placeholder] %s → %s", name, value[:60])
                        continue

                context = _secret_context(content, match.start(), match.end())
                logger.warning("[!!!] %s → %s", name, url)
                out.write(f"[{name}] {url}\n{value}\n" + "-" * 60 + "\n")
                save_secret_finding(name, value, url, context, cfg)
                found += 1

                if name == "google_api_key":
                    # ── Correção de race condition: acesso thread-safe ao set ──
                    with google_keys_lock:
                        google_keys_found.add(value)

        found += scan_charcode_obfuscation(content, url, out, logger)

    # Extrai endpoints de API adicionalmente
    extract_api_endpoints(content, url, cfg, logger)

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

    return analyze_js_content(content, url, cfg, logger, google_keys_found, google_keys_lock)


def analyze_all_js(cfg: dict, logger: logging.Logger) -> tuple[int, set]:
    urls = [u.strip() for u in cfg["js_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    total_found = 0
    google_keys_found: set = set()
    google_keys_lock = threading.Lock()          # ← lock para thread-safety

    logger.info("Analisando %d arquivos JS com %d workers…", len(urls), cfg["js_workers"])

    # Cria uma instância de get com retry por worker (cada thread usa a própria sessão implícita)
    get_fn = _make_retrying_get(cfg)

    with ThreadPoolExecutor(max_workers=cfg["js_workers"]) as executor:
        futures = {
            executor.submit(
                process_js, url, cfg, logger, google_keys_found, google_keys_lock, get_fn
            ): url
            for url in urls
        }
        for future in as_completed(futures):
            try:
                total_found += future.result()
            except Exception as exc:
                logger.error("Erro inesperado na thread: %s", exc)

    logger.info("Achados em JS: %d → %s", total_found, cfg["result_file"])
    return total_found, google_keys_found


# ── Sumário consolidado ───────────────────────────────────────────────────────

def write_summary(cfg: dict, logger: logging.Logger, stats: dict) -> None:
    """Gera um relatório final consolidado com todos os contadores da execução."""

    def _count_lines(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for _ in path.read_text(encoding="utf-8", errors="ignore").splitlines() if _)

    # Conta achados por tipo em js_sensiveis.txt
    js_breakdown: dict[str, int] = collections.Counter()
    if cfg["result_file"].exists():
        for line in cfg["result_file"].read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r'^\[([^\]]+)\]', line)
            if m:
                js_breakdown[m.group(1)] += 1

    # Conta Google Keys vulneráveis
    vuln_google = 0
    if cfg["google_report_file"].exists():
        report_text = cfg["google_report_file"].read_text(encoding="utf-8", errors="ignore")
        for line in report_text.splitlines():
            m = re.search(r'Vulneráveis:\s*(\d+)/', line)
            if m and int(m.group(1)) > 0:
                vuln_google += 1

    lines = [
        "=" * 64,
        "  SUMÁRIO DE RECONHECIMENTO",
        f"  Alvo  : {cfg['domain']}",
        f"  Saída : {cfg['base_dir']}",
        "=" * 64,
        "",
        "── Coleta ───────────────────────────────────────────────────",
        f"  URLs coletadas           : {stats.get('urls_total', 0):>6}",
        f"  URLs ativas (httpx)      : {stats.get('urls_alive', 0):>6}",
        f"  Arquivos JS              : {stats.get('js_total', 0):>6}",
        f"  Arquivos sensíveis       : {stats.get('sensitive_total', 0):>6}",
        "",
        "── Análise JS ───────────────────────────────────────────────",
        f"  Segredos encontrados     : {stats.get('js_findings', 0):>6}",
    ]

    for name, count in sorted(js_breakdown.items()):
        lines.append(f"    [{name}]: {count}")

    lines += [
        "",
        "── Google API Keys ──────────────────────────────────────────",
        f"  Chaves encontradas       : {stats.get('google_keys', 0):>6}",
        f"  Chaves vulneráveis       : {vuln_google:>6}",
        "",
        "── Arquivos sensíveis ───────────────────────────────────────",
        f"  Segredos em .env/.conf   : {stats.get('sensitive_findings', 0):>6}",
        "",
        "── Probes ───────────────────────────────────────────────────",
        f"  XSS confirmados (dalfox) : {stats.get('xss_hits', 0):>6}",
        f"  SSRF/Redirect hits       : {stats.get('ssrf_redirect_hits', 0):>6}",
        "",
        "── Endpoints de API expostos ────────────────────────────────",
        f"  Endpoints únicos         : {_count_lines(cfg['api_endpoints_file']):>6}",
        "",
        "── Arquivos de saída ────────────────────────────────────────",
        f"  JS segredos    : {cfg['result_file']}",
        f"  Todos segredos : {cfg['secrets_all_txt']}",
        f"  Segredos CSV   : {cfg['secrets_all_csv']}",
        f"  Segredos JSONL : {cfg['secrets_all_jsonl']}",
        f"  Por tipo       : {cfg['secrets_by_type_dir']}",
        f"  Google Keys    : {cfg['google_report_file']}",
        f"  Sensíveis      : {cfg['sensitive_analysis']}",
        f"  API Endpoints  : {cfg['api_endpoints_file']}",
        f"  Log completo   : {cfg['log_file']}",
        "=" * 64,
    ]

    summary_text = "\n".join(lines) + "\n"
    cfg["summary_file"].write_text(summary_text, encoding="utf-8")

    # Também imprime no stdout
    for line in lines:
        logger.info(line)


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recon web com coleta de URLs, análise de JS, segredos e probes opcionais."
    )
    parser.add_argument("domain", nargs="?", help="Domínio alvo. Ex: exemplo.com.br")
    parser.add_argument("--no-dalfox", action="store_true", help="Pula o probe de XSS com dalfox")
    parser.add_argument("--no-ssrf-probe", action="store_true", help="Pula o probe de SSRF/redirect com qsreplace")
    parser.add_argument("--no-sensitive-dl", action="store_true", help="Pula o download/análise de arquivos sensíveis")
    parser.add_argument("--no-httpx", action="store_true", help="Pula validação de URLs ativas com httpx e usa todas as URLs")
    parser.add_argument("--no-google-val", action="store_true", help="Pula validação online de endpoints Google")
    parser.add_argument("--workers", type=int, default=20, help="Número de workers JS. Padrão: 20")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout de requisições em segundos. Padrão: 10")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    domain = args.domain or input("Domínio: ").strip()
    if not domain:
        print("Domínio inválido.")
        sys.exit(1)

    cfg = get_config(domain)
    cfg["js_workers"] = max(1, args.workers)
    cfg["request_timeout"] = max(1, args.timeout)
    logger = setup_logging(cfg["log_file"])
    initialize_secret_output_files(cfg, logger)

    logger.info("=" * 60)
    logger.info("Iniciando recon para: %s", domain)
    logger.info("Diretório de saída: %s", cfg["base_dir"])
    logger.info("=" * 60)

    stats: dict[str, int] = {}

    # 1. Coleta de URLs
    stats["urls_total"] = collect_urls(cfg, logger)

    # 2. Validação de URLs ativas
    if args.no_httpx:
        cfg["_active_urls_file"] = cfg["urls_file"]
        stats["urls_alive"] = stats["urls_total"]
        logger.info("--no-httpx ativo: usando todas as URLs coletadas.")
    else:
        stats["urls_alive"] = validate_alive_urls(cfg, logger)

    # 3. GF + probes de parâmetros
    run_gf(cfg, logger)
    if args.no_dalfox:
        stats["xss_hits"] = 0
        logger.info("--no-dalfox ativo: probe de XSS pulado.")
    else:
        stats["xss_hits"] = probe_xss(cfg, logger)

    if args.no_ssrf_probe:
        stats["ssrf_redirect_hits"] = 0
        logger.info("--no-ssrf-probe ativo: probe de SSRF/redirect pulado.")
    else:
        stats["ssrf_redirect_hits"] = probe_ssrf_redirect(cfg, logger)

    # 4. Arquivos sensíveis
    stats["sensitive_total"] = extract_sensitive(cfg, logger)
    if args.no_sensitive_dl:
        stats["sensitive_findings"] = 0
        logger.info("--no-sensitive-dl ativo: download/análise de arquivos sensíveis pulado.")
    else:
        stats["sensitive_findings"] = download_and_analyze_sensitive(cfg, logger)

    # 5. Coleta de JS
    stats["js_total"] = collect_js(cfg, logger)

    # 6. Análise de JS + Google Keys
    js_findings, google_keys = analyze_all_js(cfg, logger)
    stats["js_findings"] = js_findings
    stats["google_keys"] = len(google_keys)
    if args.no_google_val:
        logger.info("--no-google-val ativo: validação de endpoints Google pulada.")
        if google_keys:
            cfg["google_keys_file"].write_text("\n".join(sorted(google_keys)) + "\n", encoding="utf-8")
    else:
        validate_all_google_keys(google_keys, cfg, logger)

    # 7. Sumário final
    write_summary(cfg, logger, stats)

    logger.info("=" * 60)
    logger.info("Recon finalizado. Logs completos em: %s", cfg["log_file"])
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
