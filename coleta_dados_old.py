#!/usr/bin/env python3
"""
recon.py — Script de reconhecimento web passivo/ativo focado em JS.

Fluxo:
  1. Coleta de URLs  (gau + waybackurls + katana + hakrawler + subfinder + gospider)
  2. Validação de URLs ativas com httpx
  3. Filtragem com GF  (xss, sqli, ssrf, redirect, ssti)
  4. Download e análise de arquivos sensíveis por extensão
  5. Coleta de URLs de JS  (filtro inteligente, sem CDNs, SOMENTE domínio/subdomínios do alvo)
  5b. Análise de inline scripts em HTML
  6. Análise de segredos em JS  (padrões de alta precisão + detecção de ofuscação)
  6b. Extração e análise de source maps (.js.map) — inclui paths de fontes e sourcesContent
  7. Validação de Google API Keys
  8. Extração de endpoints de API expostos em JS
  9. Probe de XSS (dalfox) e SSRF/redirect (qsreplace)
 10. Relatório consolidado (TXT + HTML interativo)

Melhorias integradas (herdadas do jsrecon.py):
  A. Padrões de segredos expandidos
  B. Análise dedicada de chamadas btoa() com decodificação do valor em claro
  C. Extração de endpoints muito mais abrangente (17 padrões com método HTTP)
  D. Persistência de endpoints estruturada (JSONL + TXT com método, URL
     absoluta, query params e fonte JS)
  E. Severidade por tipo de segredo (CRITICAL/HIGH/MEDIUM/LOW)
  F. Deduplicação de segredos por valor normalizado
  G. Rate limiting adaptativo por hostname
  H. Validação estrutural de JWT
  I. Análise de inline scripts em HTML
  J. Cache de JS em disco por hash de URL
  K. Preflight check de ferramentas
  L. SUMMARY.html interativo e filtrável
  M. Coleta e análise de source maps (.js.map) com inspeção de paths e sourcesContent

Filtro de domínio (v2):
  - JS e MAP só são coletados/analisados se o hostname pertence ao domínio-alvo
    ou a um subdomínio direto dele (*.target.com.br).
  - CDNs de terceiros e domínios externos são ignorados automaticamente.
"""

from __future__ import annotations

import argparse
import base64 as _b64
import collections
import csv
import hashlib
import json
import logging
import math
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# CDN — ignorar JS de terceiros
# ─────────────────────────────────────────────────────────────────────────────

_CDN_DOMAINS_RE = re.compile(
    r'(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|'
    r'ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|'
    r'maxcdn\.bootstrapcdn\.com|code\.jquery\.com|'
    r'cdn\.datatables\.net|cdn\.polyfill\.io|'
    r'static\.cloudflareinsights\.com)',
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# Constantes de qualidade / anti-falso-positivo
# ─────────────────────────────────────────────────────────────────────────────

_MIN_VALUE_LEN       = 8
_MIN_ENTROPY         = 3.2
_DECODED_ENTROPY_MIN = 3.5

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
    r'tooltip|helper|message|text|i18n|translate|t\(|'
    r'console\.log|console\.warn|console\.error|comment|//)',
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# Mapa de severidade
# ─────────────────────────────────────────────────────────────────────────────

SECRET_SEVERITY: dict[str, str] = {
    # CRITICAL
    "aws_access_key":           "CRITICAL",
    "private_key":              "CRITICAL",
    "stripe_secret":            "CRITICAL",
    "braintree_token":          "CRITICAL",
    "gcp_service_account":      "CRITICAL",
    "hashicorp_vault":          "CRITICAL",
    "azure_storage_key":        "CRITICAL",
    "js_secret_key":            "CRITICAL",
    # HIGH
    "github_pat":               "HIGH",
    "github_oauth":             "HIGH",
    "gitlab_pat":               "HIGH",
    "openai_key":               "HIGH",
    "sendgrid_key":             "HIGH",
    "slack_token":              "HIGH",
    "supabase_service_role":    "HIGH",
    "mongodb_dsn":              "HIGH",
    "postgres_dsn":             "HIGH",
    "mysql_dsn":                "HIGH",
    "google_api_key":           "HIGH",
    "firebase_url":             "HIGH",
    "twilio_auth_token":        "HIGH",
    "firebase_app_id":          "HIGH",
    "firebase_config_block":    "HIGH",
    "basic_auth_btoa":          "HIGH",
    "btoa_creds":               "HIGH",
    "btoa_decoded":             "HIGH",
    "basic_auth_b64_raw":       "HIGH",
    "hardcoded_credentials":    "HIGH",
    # MEDIUM
    "jwt":                      "MEDIUM",
    "stripe_publishable":       "MEDIUM",
    "slack_webhook":            "MEDIUM",
    "sentry_dsn":               "MEDIUM",
    "mapbox_token":             "MEDIUM",
    "supabase_anon_key":        "MEDIUM",
    "mailgun_api_key":          "MEDIUM",
    "firebase_sender_id":       "MEDIUM",
    "auth_header_hardcoded":    "MEDIUM",
    "firebase_measurement_id":  "LOW",
    # LOW
    "generic_api_key":          "LOW",
    "generic_token":            "LOW",
    "generic_secret":           "LOW",
    "bearer_token":             "LOW",
    "password_field":           "LOW",
    "bcrypt_hash":              "LOW",
    # SOURCE MAP específicos
    "sourcemap_internal_path":  "LOW",
    "sourcemap_env_path":       "MEDIUM",
    "sourcemap_secret_in_src":  "HIGH",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def get_severity(secret_type: str) -> str:
    return SECRET_SEVERITY.get(secret_type, "UNKNOWN")


# ─────────────────────────────────────────────────────────────────────────────
# Normalização de valor para deduplicação
# ─────────────────────────────────────────────────────────────────────────────

_CASE_SENSITIVE_TYPES = frozenset({
    "aws_access_key", "github_pat", "github_oauth", "gitlab_pat",
    "npm_token", "stripe_secret", "stripe_publishable", "openai_key",
    "jwt", "bcrypt_hash", "private_key", "supabase_anon_key",
})


def _normalize_secret_value(type_name: str, value: str) -> str:
    v = value.strip().strip("'\"`")
    if type_name not in _CASE_SENSITIVE_TYPES:
        v = v.lower()
    if "://" in v:
        v = v.split("?")[0].rstrip("/")
    return v


# ─────────────────────────────────────────────────────────────────────────────
# Helpers gerais
# ─────────────────────────────────────────────────────────────────────────────

def _regex(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq  = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_value(raw_match: str) -> str:
    m = re.search(r'[:=]\s*["\']?([^\s"\'`,;]{4,})', raw_match)
    return m.group(1).strip() if m else raw_match.strip()


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


# ─────────────────────────────────────────────────────────────────────────────
# Filtro de domínio — NOVO
# Retorna True se a URL pertence ao domínio-alvo ou a um subdomínio direto.
# ─────────────────────────────────────────────────────────────────────────────

def _belongs_to_target(url: str, root_domain: str) -> bool:
    """
    Aceita apenas URLs cujo hostname é exatamente root_domain
    ou termina com .root_domain  (qualquer nível de subdomínio).
    URLs sem scheme (caminhos relativos) são sempre aceitas — o contexto
    de onde vieram já garante o domínio correto.
    """
    if not url.startswith(("http://", "https://")):
        return True  # caminho relativo; aceitar
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return False
    rd = root_domain.lower()
    return host == rd or host.endswith("." + rd)


# ─────────────────────────────────────────────────────────────────────────────
# Validação estrutural de JWT
# ─────────────────────────────────────────────────────────────────────────────

def _is_real_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    for part in parts[:2]:
        padded = part + "=" * (-len(part) % 4)
        try:
            obj = json.loads(_b64.urlsafe_b64decode(padded))
            if not isinstance(obj, dict):
                return False
        except Exception:
            return False
    try:
        header_raw  = parts[0] + "=" * (-len(parts[0]) % 4)
        header_dict = json.loads(_b64.urlsafe_b64decode(header_raw))
        if "alg" not in header_dict:
            return False
    except Exception:
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
    ("high_entropy_decoded", None),
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
            ctx = content[max(0, m.start()-60):min(len(content), m.end()+60)].replace("\n", " ")
            logger.warning("[!!!] %s (ofuscado) → %s | decoded: %s", matched_label, url, decoded[:80])
            results.append({"type": matched_label, "value": decoded, "context": ctx, "url": url})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Padrões de segredos
# ─────────────────────────────────────────────────────────────────────────────

def _build_secret_patterns() -> dict[str, re.Pattern]:
    return {
        # ── Google / Firebase / GCP ──────────────────────────────────────────
        "google_api_key":           _regex(r'AIza[0-9A-Za-z\-_]{35}'),
        "google_oauth_client":      _regex(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        "firebase_url":             _regex(r'https?://[a-z0-9\-]+\.firebaseio\.com', re.I),
        "gcp_service_account":      _regex(r'"type"\s*:\s*"service_account"'),
        "js_secret_key":            _regex(r'secrete?[Kk]ey\s*[:=]\s*["\']([^"\']{6,})["\']', re.I),
        "firebase_app_id":          _regex(r'appId\s*[:=]\s*["\'](\d+:\d+:\w+:[a-f0-9]{16,})["\']', re.I),
        "firebase_sender_id":       _regex(r'messagingSenderId\s*[:=]\s*["\'](\d{8,})["\']', re.I),
        "firebase_measurement_id":  _regex(r'measurementId\s*[:=]\s*["\']([A-Z0-9\-]{8,})["\']', re.I),
        "firebase_config_block":    _regex(r'apiKey\s*:\s*["\']([^"\']{20,})["\'][^}]{0,200}authDomain\s*:\s*["\']([^"\']+)["\']', re.I | re.DOTALL),
        "env_config_key":           _regex(r'(?:apiUrl|baseUrl|endpointUrl|serviceUrl|backendUrl)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),

        # ── AWS / Cloud ───────────────────────────────────────────────────────
        "aws_access_key":           _regex(r'AKIA[0-9A-Z]{16}'),
        "amazon_mws":               _regex(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
        "azure_storage_key":        _regex(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
        "digitalocean_token":       _regex(r'dop_v1_[a-f0-9]{64}'),
        "terraform_cloud":          _regex(r'[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_=]{60,}'),

        # ── Pagamento ─────────────────────────────────────────────────────────
        "stripe_secret":            _regex(r'sk_live_[0-9a-zA-Z]{24,}'),
        "stripe_publishable":       _regex(r'pk_live_[0-9a-zA-Z]{24,}'),
        "stripe_webhook":           _regex(r'whsec_[a-zA-Z0-9]{32,}'),
        "square_access_token":      _regex(r'sq0atp-[0-9A-Za-z\-_]{22}'),
        "square_oauth_secret":      _regex(r'sq0csp-[0-9A-Za-z\-_]{43}'),
        "braintree_token":          _regex(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),

        # ── Comunicação ───────────────────────────────────────────────────────
        "sendgrid_key":             _regex(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
        "mailgun_api_key":          _regex(r'key-[0-9a-zA-Z]{32}'),
        "mailchimp_api_key":        _regex(r'[0-9a-f]{32}-us[0-9]{1,2}'),
        "twilio_account_sid":       _regex(r'\bAC[a-z0-9]{32}\b'),
        "twilio_auth_token":        _regex(r'\bSK[a-z0-9]{32}\b'),

        # ── DevOps / CI ───────────────────────────────────────────────────────
        "github_pat":               _regex(r'gh[pousr]_[A-Za-z0-9]{36}'),
        "github_oauth":             _regex(r'gho_[A-Za-z0-9]{36}'),
        "gitlab_pat":               _regex(r'glpat-[A-Za-z0-9\-_]{20}'),
        "gitlab_pipeline":          _regex(r'glptt-[a-f0-9]{40}'),
        "npm_token":                _regex(r'npm_[A-Za-z0-9]{36}'),
        "pypi_token":               _regex(r'pypi-[A-Za-z0-9_\-]{50,}'),
        "dockerhub_pat":            _regex(r'dckr_pat_[A-Za-z0-9_\-]{27}'),
        "hashicorp_vault":          _regex(r'hvs\.[A-Za-z0-9_\-]{90,}'),
        "new_relic_key":            _regex(r'NRAK-[A-Z0-9]{27}'),
        "sentry_dsn":               _regex(r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'),
        "grafana_token":            _regex(r'glc_[A-Za-z0-9+/]{32,}'),

        # ── OpenAI / Slack ────────────────────────────────────────────────────
        "openai_key":               _regex(r'sk-[a-zA-Z0-9]{48}'),
        "slack_token":              _regex(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
        "slack_webhook":            _regex(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),

        # ── DB / Connection strings ───────────────────────────────────────────
        "mongodb_dsn":              _regex(r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "postgres_dsn":             _regex(r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "mysql_dsn":                _regex(r'mysql://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "redis_dsn":                _regex(r'redis://:([^@\s]+)@[^\s"\'`]+', re.I),

        # ── Misc ──────────────────────────────────────────────────────────────
        "shopify_token":            _regex(r'shp(?:at|ss)_[a-fA-F0-9]{32}'),
        "mapbox_token":             _regex(r'pk\.eyJ1[A-Za-z0-9._\-]{20,}'),
        "notion_token":             _regex(r'secret_[A-Za-z0-9]{43}'),
        "linear_api_key":           _regex(r'lin_api_[A-Za-z0-9]{40}'),

        # ── Supabase ──────────────────────────────────────────────────────────
        "supabase_url":             _regex(r'https://[a-z0-9]{20}\.supabase\.co', re.I),
        "supabase_anon_key":        _regex(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{43}'),
        "supabase_service_role":    _regex(r'(?:SUPABASE_SERVICE_ROLE_KEY|service_role)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{100,})["\']', re.I),
        "supabase_env":             _regex(r'SUPABASE_(?:URL|ANON_KEY|SERVICE_ROLE_KEY)\s*[=:]\s*\S+', re.I),

        # ── Chaves / Hashes ───────────────────────────────────────────────────
        "private_key":              _regex(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "jwt":                      _regex(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
        "bcrypt_hash":              _regex(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'),

        # ── Basic Auth / credenciais hardcoded ────────────────────────────────
        "basic_auth_btoa":          _regex(r'Basic\s*["\']?\s*\+\s*btoa\s*\(\s*["\']([^"\']{3,100})["\']\s*\)', re.I),
        "btoa_creds":               _regex(r'\bbtoa\s*\(\s*["\']([^"\']{2,100})["\']\s*\)', re.I),
        "basic_auth_b64_raw":       _regex(r'(?:Authorization|authorization)\s*[:\s=]+["\']?\s*Basic\s+([A-Za-z0-9+/]{8,}={0,2})', re.I),
        "hardcoded_credentials":    _regex(r'(?:username|user|login|usr)\s*[:=]\s*["\']([^"\']{2,50})["\']\s{0,5}.{0,80}(?:password|passwd|pass|pwd|senha)\s*[:=]\s*["\']([^"\']{2,})["\']', re.I),
        "auth_header_hardcoded":    _regex(r'["\']Authorization["\']\s*:\s*["\']Basic\s+([A-Za-z0-9+/]{8,}={0,2})["\']', re.I),

        # ── Padrões genéricos — validação extra de entropia obrigatória ───────
        "generic_api_key":          _regex(r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
        "generic_token":            _regex(r'(?:access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I),
        "generic_secret":           _regex(r'(?:client[_-]?secret|app[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{20,})["\']', re.I),
        "bearer_token":             _regex(r'Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.]{20,})', re.I),
        "password_field":           _regex(r'(?:password|passwd|senha)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
    }


_GENERIC_PATTERNS = frozenset({
    "generic_api_key", "generic_token", "generic_secret",
    "bearer_token", "password_field", "auth_header_hardcoded",
})

# ─────────────────────────────────────────────────────────────────────────────
# Padrões de endpoints
# ─────────────────────────────────────────────────────────────────────────────

def _build_endpoint_patterns() -> list[tuple[str, re.Pattern, str]]:
    return [
        ("api_versioned",
         _regex(r'["\`](/api/v\d+[a-zA-Z0-9/_\-]*(?:\?[^\s"\'`]*)?)["\`]'), "ANY"),
        ("graphql",
         _regex(r'["\`]((?:/graphql|/gql)(?:\?[^\s"\'`]*)?)["\`\s/]', re.I), "POST"),
        ("versioned_path",
         _regex(r'["\`](/v\d+/[a-zA-Z0-9/_\-]{4,}(?:\?[^\s"\'`]*)?)["\`]'), "ANY"),
        ("internal_subdomain",
         _regex(r'(https?://(?:internal|admin|dev|staging|api)\.[a-z0-9\-]+\.[a-z]+[^\s"\'`]*)'), "ANY"),
        ("fetch_get",
         _regex(r'(?:fetch|axios\.get|http\.get|request\.get|this\.\$http\.get)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "GET"),
        ("fetch_post",
         _regex(r'(?:fetch|axios\.post|http\.post|request\.post|this\.\$http\.post)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "POST"),
        ("fetch_put",
         _regex(r'(?:axios\.put|http\.put|request\.put)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "PUT"),
        ("fetch_delete",
         _regex(r'(?:axios\.delete|http\.delete|request\.delete)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "DELETE"),
        ("fetch_patch",
         _regex(r'(?:axios\.patch|http\.patch|request\.patch)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "PATCH"),
        ("fetch_dynamic",
         _regex(r'fetch\s*\(\s*["\`]([^"\'`\s]{4,})["\`]\s*,\s*\{[^}]*method\s*:\s*["\'](\w+)["\']', re.I), "DYNAMIC"),
        ("query_string_get",
         _regex(r'(?:new\s+URLSearchParams|qs\.stringify|querystring\.stringify)\s*\([^)]*\).*?["\`](/[a-zA-Z0-9/_\-]{2,})["\`]', re.I | re.DOTALL), "GET"),
        ("json_body_post",
         _regex(r'body\s*:\s*JSON\.stringify\s*\([^)]*\).*?["\`](/[a-zA-Z0-9/_\-]{2,})["\`]', re.I | re.DOTALL), "POST"),
        ("formdata_post",
         _regex(r'new\s+FormData\s*\([^)]*\).*?(?:fetch|axios\.post)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I | re.DOTALL), "POST"),
        ("router_path",
         _regex(r'(?:path|route|to)\s*:\s*["\`](/[a-zA-Z0-9/_\-:]{3,}(?:\?[^\s"\'`]*)?)["\`]', re.I), "GET"),
        ("href_path",
         _regex(r'(?:href|src|action)\s*[=:]\s*["\`](/[a-zA-Z0-9/_\-\.]{4,}(?:\?[^\s"\'`]*)?)["\`]', re.I), "GET"),
        ("url_with_query",
         _regex(r'["\`]((?:https?://[^\s"\'`]+)?/[a-zA-Z0-9/_\-]{2,}\?(?:[a-zA-Z0-9_\-]+=\w+&?)+)["\`]', re.I), "GET"),
        ("websocket",
         _regex(r'new\s+WebSocket\s*\(\s*["\`](wss?://[^\s"\'`]+)["\`]', re.I), "WS"),
    ]


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
        "domain":   domain,
        "base_dir": base,

        "urls_file":            base / "urls_raw.txt",
        "urls_alive_file":      base / "urls_alive.txt",
        "js_file":              base / "js_urls.txt",
        "secrets_txt":          base / "secrets.txt",
        "secrets_csv":          base / "secrets.csv",
        "secrets_jsonl":        base / "secrets.jsonl",
        "endpoints_txt":        base / "endpoints.txt",
        "endpoints_jsonl":      base / "endpoints.jsonl",
        "google_keys_file":     base / "google_keys.txt",
        "google_report_file":   base / "google_keys_report.txt",
        "log_file":             base / "recon.log",
        "gf_dir":               base / "gf",
        "sensitive_urls_file":  base / "sensitive_urls.txt",
        "sensitive_dir":        base / "sensitive_downloads",
        "sensitive_report":     base / "sensitive_report.txt",
        "summary_file":         base / "SUMMARY.txt",
        "summary_html":         base / "SUMMARY.html",

        "gf_patterns": ["xss", "sqli", "ssrf", "redirect", "ssti"],

        "sensitive_regex": re.compile(
            r'\.(env|log|bak|sql|conf|ini|yml|yaml|pem|key|crt|sh|py)$',
            re.IGNORECASE,
        ),

        "secret_patterns":   _build_secret_patterns(),
        "_generic_patterns": _GENERIC_PATTERNS,
        "endpoint_patterns": _build_endpoint_patterns(),

        "sensitive_content_patterns": [
            re.compile(r'(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD)\s*=\s*\S+', re.I),
            re.compile(r'(?:SECRET_KEY|APP_KEY|ENCRYPTION_KEY)\s*=\s*\S+', re.I),
            re.compile(r'(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*=\s*\S+', re.I),
            re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            re.compile(r'(?:MAIL|SMTP)_PASS(?:WORD)?\s*=\s*\S+', re.I),
            re.compile(r'(?:STRIPE|PAYPAL|BRAINTREE)[_-](?:SECRET|KEY|TOKEN)\s*=\s*\S+', re.I),
            re.compile(r'SUPABASE_(?:URL|ANON_KEY|SERVICE_ROLE_KEY)\s*=\s*\S+', re.I),
            re.compile(r'createClient\s*\(\s*["\']https://[a-z0-9]+\.supabase\.co["\']', re.I),
        ],

        "google_key_regex":  re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "headers":           {"User-Agent": "Mozilla/5.0 recon"},
        "js_workers":        20,
        "request_timeout":   10,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Preflight check de ferramentas
# ─────────────────────────────────────────────────────────────────────────────

_TOOL_META: dict[str, dict] = {
    "gau":         {"install": "go install github.com/lc/gau/v2/cmd/gau@latest",                                   "impact": "coleta passiva de URLs"},
    "waybackurls": {"install": "go install github.com/tomnomnom/waybackurls@latest",                               "impact": "coleta passiva via Wayback Machine"},
    "katana":      {"install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",                  "impact": "crawling ativo com suporte a JS"},
    "hakrawler":   {"install": "go install github.com/hakluke/hakrawler@latest",                                   "impact": "crawling de subdomínios"},
    "gospider":    {"install": "go install github.com/jaeles-project/gospider@latest",                             "impact": "crawling com suporte a sitemap/robots"},
    "httpx":       {"install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",                    "impact": "validação de URLs ativas"},
    "subfinder":   {"install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",         "impact": "enumeração de subdomínios"},
    "gf":          {"install": "go install github.com/tomnomnom/gf@latest",                                        "impact": "filtragem XSS/SQLi/SSRF/redirect"},
    "dalfox":      {"install": "go install github.com/hahwul/dalfox/v2@latest",                                    "impact": "probe XSS ativo"},
    "qsreplace":   {"install": "go install github.com/tomnomnom/qsreplace@latest",                                 "impact": "probe SSRF/redirect"},
    "curl":        {"install": "apt install curl / brew install curl",                                              "impact": "validação de redirect hits"},
}

_CRITICAL_TOOLS = {"httpx"}


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def preflight_check(logger: logging.Logger, args: argparse.Namespace) -> bool:
    missing: list[tuple[str, str, str]] = []
    present: list[str]                  = []
    for tool, meta in _TOOL_META.items():
        if tool_available(tool):
            present.append(tool)
        else:
            missing.append((tool, meta["install"], meta["impact"]))

    logger.info("─── Preflight check ─────────────────────────────────────────")
    logger.info("Ferramentas disponíveis (%d): %s", len(present), ", ".join(sorted(present)))
    if missing:
        logger.warning("Ferramentas ausentes (%d):", len(missing))
        for tool, install_cmd, impact in sorted(missing):
            level = logging.ERROR if tool in _CRITICAL_TOOLS else logging.WARNING
            logger.log(level, "  ✗ %-15s | impacto: %-45s | instalar: %s",
                       tool, impact, install_cmd)

    critical_missing = [t for t, _, _ in missing if t in _CRITICAL_TOOLS]
    if "httpx" in critical_missing and getattr(args, "no_httpx", False):
        critical_missing.remove("httpx")
    if critical_missing:
        logger.error("Ferramentas críticas ausentes: %s — abortando.", ", ".join(critical_missing))
        return False
    logger.info("─────────────────────────────────────────────────────────────")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Escrita segura de arquivos
# ─────────────────────────────────────────────────────────────────────────────

def write_if_not_empty(path: Path, lines: list[str], logger: logging.Logger) -> bool:
    content = [l for l in lines if l.strip()]
    if not content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content) + "\n", encoding="utf-8")
    logger.debug("Salvo: %s (%d linhas)", path, len(content))
    return True


def append_line_to_file(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting adaptativo por hostname
# ─────────────────────────────────────────────────────────────────────────────

_host_semaphores: dict[str, threading.Semaphore] = {}
_host_sem_lock   = threading.Lock()
_MAX_PER_HOST    = 4
_request_logger  = logging.getLogger("recon.requests")


def _get_host_semaphore(url: str) -> threading.Semaphore:
    host = urllib.parse.urlparse(url).netloc
    with _host_sem_lock:
        if host not in _host_semaphores:
            _host_semaphores[host] = threading.Semaphore(_MAX_PER_HOST)
        return _host_semaphores[host]


def _make_retrying_get(cfg: dict):
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        )),
        before_sleep=before_sleep_log(_request_logger, logging.DEBUG),
        reraise=True,
    )
    def _get(url: str, **kwargs) -> requests.Response:
        sem = _get_host_semaphore(url)
        with sem:
            resp = requests.get(
                url,
                headers=cfg["headers"],
                timeout=cfg["request_timeout"],
                verify=False,
                allow_redirects=True,
                **kwargs,
            )
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 10))
                time.sleep(min(retry_after, 60))
                resp.raise_for_status()
            elif resp.status_code == 503:
                time.sleep(5)
                resp.raise_for_status()
            return resp
    return _get


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de subprocesso
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], logger: logging.Logger,
            stdin: str | None = None, timeout: int = 300) -> list[str]:
    try:
        result = subprocess.run(cmd, input=stdin, capture_output=True,
                                text=True, timeout=timeout)
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


# ─────────────────────────────────────────────────────────────────────────────
# Fontes passivas via API HTTP direta
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_wayback_api(domain: str, logger: logging.Logger) -> set[str]:
    urls: set[str] = set()
    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}/*", "output": "text", "fl": "original",
                    "collapse": "urlkey", "limit": "100000", "filter": "statuscode:200"},
            timeout=900, headers={"User-Agent": "Mozilla/5.0 recon"},
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    urls.add(line)
    except Exception as exc:
        logger.debug("[wayback-api] erro: %s", exc)
    return urls


def _fetch_commoncrawl_api(domain: str, logger: logging.Logger) -> set[str]:
    urls: set[str] = set()
    try:
        idx_resp = requests.get(
            "https://index.commoncrawl.org/collinfo.json",
            timeout=90, headers={"User-Agent": "Mozilla/5.0 recon"},
        )
        if idx_resp.status_code != 200:
            return urls
        recent = [i["cdx-api"] for i in idx_resp.json()[:3]]
    except Exception as exc:
        logger.debug("[commoncrawl-api] erro ao buscar índices: %s", exc)
        return urls
    for api_url in recent:
        try:
            resp = requests.get(
                api_url,
                params={"url": f"*.{domain}", "output": "text",
                        "fl": "url", "collapse": "urlkey", "limit": "50000"},
                timeout=90, headers={"User-Agent": "Mozilla/5.0 recon"},
            )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.add(line)
        except Exception as exc:
            logger.debug("[commoncrawl-api] erro em %s: %s", api_url, exc)
    return urls


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 1: Coleta de URLs
# ─────────────────────────────────────────────────────────────────────────────

def collect_urls(cfg: dict, logger: logging.Logger) -> int:
    domain   = cfg["domain"]
    all_urls: set[str] = set()

    if tool_available("gau"):
        logger.info("[gau] coletando…")
        lines = run_cmd(["gau", "--threads", "5", "--subs",
                         "--providers", "wayback,commoncrawl,otx,urlscan",
                         "--retries", "2", "--timeout", "90", domain], logger, timeout=900)
        all_urls.update(lines)
        logger.info("[gau] %d URLs", len(lines))
    else:
        logger.warning("gau não encontrado — pulando.")

    if tool_available("waybackurls"):
        logger.info("[waybackurls] coletando…")
        lines = run_cmd(["waybackurls", domain], logger, timeout=900)
        all_urls.update(lines)
        logger.info("[waybackurls] %d URLs", len(lines))
    else:
        logger.warning("waybackurls não encontrado — pulando.")

    logger.info("[wayback-api] consultando CDX API…")
    wayback_urls = _fetch_wayback_api(domain, logger)
    all_urls.update(wayback_urls)
    logger.info("[wayback-api] %d URLs", len(wayback_urls))

    logger.info("[commoncrawl-api] consultando…")
    cc_urls = _fetch_commoncrawl_api(domain, logger)
    all_urls.update(cc_urls)
    logger.info("[commoncrawl-api] %d URLs", len(cc_urls))

    if tool_available("katana"):
        logger.info("[katana] coletando…")
        lines = run_cmd([
            "katana", "-u", f"https://{domain}", "-d", "5",
            "-ps", "-pss", "waybackarchive,commoncrawl,alienvault",
            "-kf", "-jc",
            "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,ico,ttf",
            "-silent",
        ], logger, timeout=900)
        all_urls.update(lines)
        logger.info("[katana] %d URLs", len(lines))
    else:
        logger.warning("katana não encontrado — pulando.")

    if tool_available("hakrawler"):
        logger.info("[hakrawler] coletando…")
        lines = run_cmd(
            ["hakrawler", "-d", "3", "-u", "-subs", "-t", "8", "-insecure"],
            logger, stdin=f"https://{domain}\n", timeout=600,
        )
        all_urls.update(lines)
        logger.info("[hakrawler] %d URLs", len(lines))

    if tool_available("gospider"):
        logger.info("[gospider] coletando…")
        try:
            proc = subprocess.Popen(
                ["gospider", "-s", f"https://{domain}",
                 "-c", "10", "-d", "3",
                 "--js", "--sitemap", "--robots",
                 "-a", "-w", "--subs", "-q",
                 "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            gospider_lines: list[str] = []
            try:
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    m = re.search(r'https?://[^\s"\'<>\]]+', line)
                    if m:
                        all_urls.add(m.group(0).rstrip('.,;)"\'>]'))
                    gospider_lines.append(line)
            finally:
                proc.wait()
            logger.info("[gospider] %d linhas processadas", len(gospider_lines))
        except Exception as exc:
            logger.error("[gospider] erro: %s", exc)

    if tool_available("subfinder"):
        logger.info("[subfinder] enumerando subdomínios…")
        subs = run_cmd(["subfinder", "-d", domain, "-silent"], logger, timeout=300)
        logger.info("[subfinder] %d subdomínios encontrados", len(subs))
        if subs:
            if tool_available("hakrawler"):
                sub_input = "\n".join(f"https://{s}" for s in subs) + "\n"
                lines = run_cmd(
                    ["hakrawler", "-d", "2", "-u", "-t", "8", "-timeout", "10", "-insecure"],
                    logger, stdin=sub_input,
                    timeout=max(60, len(subs) * 3),
                )
                all_urls.update(lines)
            if tool_available("gospider"):
                for sub in subs[:50]:
                    try:
                        proc = subprocess.Popen(
                            ["gospider", "-s", f"https://{sub}",
                             "-c", "5", "-d", "2", "--js", "-q",
                             "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        )
                        try:
                            for line in proc.stdout:
                                line = line.strip()
                                if not line:
                                    continue
                                m = re.search(r'https?://[^\s"\'<>\]]+', line)
                                if m:
                                    all_urls.add(m.group(0).rstrip('.,;)"\'>]'))
                        finally:
                            proc.wait()
                    except Exception as exc:
                        logger.error("[gospider/subs] %s: %s", sub, exc)

    urls  = sorted(all_urls)
    wrote = write_if_not_empty(cfg["urls_file"], urls, logger)
    logger.info("URLs coletadas: %d%s", len(urls),
                f" → {cfg['urls_file']}" if wrote else " (nenhuma)")
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
    logger.info("URLs ativas: %d%s", len(alive),
                f" → {cfg['urls_alive_file']}" if wrote else "")
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
    source_text = source.read_text(encoding="utf-8")
    cfg["gf_dir"].mkdir(parents=True, exist_ok=True)
    for pattern in cfg["gf_patterns"]:
        output = cfg["gf_dir"] / f"gf_{pattern}.txt"
        try:
            result = subprocess.run(
                ["gf", pattern], input=source_text,
                capture_output=True, text=True, timeout=120,
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
        proc = subprocess.Popen(
            ["dalfox", "file", str(xss_file),
             "--silence", "--output", str(out_file),
             "--worker", "10", "--timeout", "10",
             "--header", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        hits   = 0
        killer = threading.Timer(3600, lambda: proc.kill())
        killer.start()
        try:
            for line in proc.stdout:
                line = line.strip()
                if "[V]" in line:
                    hits += 1
                    logger.warning("[!!!] dalfox XSS confirmado: %s", line)
        finally:
            killer.cancel()
            proc.wait(timeout=15)
        if hits == 0 and out_file.exists():
            hits = out_file.read_text(encoding="utf-8").count("[V]")
        if hits:
            logger.warning("[!!!] dalfox: %d XSS confirmados → %s", hits, out_file)
        else:
            if out_file.exists():
                out_file.unlink()
            logger.info("dalfox: nenhum XSS confirmado.")
        return hits
    except Exception as exc:
        logger.error("Erro no dalfox: %s", exc)
        return 0


def probe_ssrf_redirect(cfg: dict, logger: logging.Logger) -> int:
    found  = 0
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
                code   = output.split()[0] if output else "0"
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
    get          = _make_retrying_get(cfg)
    findings     = 0
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
# Etapa 5: Coleta de JS — FILTRADO POR DOMÍNIO DO ALVO
# ─────────────────────────────────────────────────────────────────────────────

def collect_js(cfg: dict, logger: logging.Logger) -> int:
    """
    Coleta URLs de JS que:
      1. Pertencem ao domínio-alvo ou a um subdomínio direto (*.target.com.br)
      2. Não são CDN de terceiros
      3. Não são source maps (.js.map)
    URLs de terceiros são contadas e logadas para transparência, mas descartadas.
    """
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    if not source.exists():
        logger.warning("Arquivo de URLs não encontrado — pulando coleta de JS.")
        return 0

    domain = cfg["domain"]
    js_re  = re.compile(
        r'(?:\.js(?:\?[^\s]*)?$|/(?:static|assets|dist|build|chunks|bundles)/[^\s]*\.js)', re.I,
    )

    js_urls: set[str]      = set()
    skipped_cdn:    int    = 0
    skipped_domain: int    = 0

    for line in source.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url:
            continue
        if url.endswith(".js.map"):
            continue  # source maps tratados separadamente
        if not js_re.search(url):
            continue
        if _CDN_DOMAINS_RE.search(url):
            skipped_cdn += 1
            continue
        if not _belongs_to_target(url, domain):
            skipped_domain += 1
            continue
        js_urls.add(url)

    wrote = write_if_not_empty(cfg["js_file"], sorted(js_urls), logger)
    logger.info(
        "Arquivos JS únicos (alvo): %d%s  |  descartados: %d CDN, %d domínios externos",
        len(js_urls),
        f" → {cfg['js_file']}" if wrote else " (nenhum)",
        skipped_cdn,
        skipped_domain,
    )
    return len(js_urls)


# ─────────────────────────────────────────────────────────────────────────────
# Análise de inline scripts em HTML
# ─────────────────────────────────────────────────────────────────────────────

_INLINE_SCRIPT_RE = re.compile(r'<script(?:\s[^>]*)?>(.+?)</script>', re.DOTALL | re.IGNORECASE)
_FRAMEWORK_DATA_RE = re.compile(
    r'(?:__NEXT_DATA__|__NUXT__|__INITIAL_STATE__|__APP_STATE__|'
    r'window\.__config|window\.__env|globalThis\.__env)\s*=\s*(\{.{20,}?\})',
    re.DOTALL,
)
_STATIC_EXT_RE = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|pdf)(\?|$)', re.I,
)


def analyze_inline_scripts(cfg: dict, logger: logging.Logger,
                            google_keys_found: set,
                            google_keys_lock: threading.Lock) -> int:
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    if not source.exists():
        return 0
    domain = cfg["domain"]
    candidate_urls = [
        u.strip() for u in source.read_text(encoding="utf-8").splitlines()
        if u.strip()
        and not _STATIC_EXT_RE.search(u.strip())
        and _belongs_to_target(u.strip(), domain)
    ]
    if not candidate_urls:
        return 0
    get_fn  = _make_retrying_get(cfg)
    total   = 0
    sampled = candidate_urls[:300]
    logger.info("[inline-scripts] analisando %d URLs HTML…", len(sampled))

    def _process_html(url: str) -> int:
        local = 0
        try:
            resp = get_fn(url)
        except Exception:
            return 0
        if resp.status_code != 200:
            return 0
        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct and "text" not in ct:
            return 0
        content = resp.text
        if len(content) > 5_000_000:
            return 0
        scripts = [
            m.group(1) for m in _INLINE_SCRIPT_RE.finditer(content)
            if "src=" not in m.group(0)[:50]
        ]
        for i, script_content in enumerate(scripts):
            if len(script_content.strip()) < 20:
                continue
            virtual_url = f"{url}::inline_script_{i}"
            n = analyze_js_content(script_content, virtual_url, cfg, logger,
                                   google_keys_found, google_keys_lock)
            local += n
            for fm in _FRAMEWORK_DATA_RE.finditer(script_content):
                try:
                    data_obj = json.loads(fm.group(1))
                    n2 = analyze_js_content(json.dumps(data_obj), f"{url}::framework_data",
                                            cfg, logger, google_keys_found, google_keys_lock)
                    local += n2
                except Exception:
                    pass
        return local

    with ThreadPoolExecutor(max_workers=cfg["js_workers"]) as executor:
        futs = {executor.submit(_process_html, u): u for u in sampled}
        for fut in as_completed(futs):
            try:
                total += fut.result()
            except Exception as exc:
                logger.debug("[inline-scripts] erro: %s", exc)
    if total:
        logger.warning("[!!!] Segredos em inline scripts: %d", total)
    else:
        logger.info("[inline-scripts] nenhum segredo encontrado.")
    return total


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
# Estado global thread-safe
# ─────────────────────────────────────────────────────────────────────────────

_analyzed_js_urls: set[str]         = set()
_analyzed_js_lock: threading.Lock   = threading.Lock()
_seen_secrets: set[tuple[str, str]] = set()
_seen_secrets_lock: threading.Lock  = threading.Lock()
_secret_write_lock                  = threading.Lock()
_seen_endpoints: set[tuple]         = set()
_endpoint_write_lock                = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Persistência de segredos
# ─────────────────────────────────────────────────────────────────────────────

def _append_secret(finding: dict, cfg: dict) -> bool:
    finding = {**finding, "severity": get_severity(finding["type"])}
    norm_key = (finding["type"], _normalize_secret_value(finding["type"], finding["value"]))
    with _seen_secrets_lock:
        if norm_key in _seen_secrets:
            return False
        _seen_secrets.add(norm_key)
    with _secret_write_lock:
        append_line_to_file(
            cfg["secrets_txt"],
            f"[{finding['severity']}] [{finding['type']}] {finding['url']}\n"
            f"VALUE  : {finding['value']}\n"
            f"CONTEXT: {finding['context'][:300]}\n" + "-" * 60,
        )
        csv_new = not cfg["secrets_csv"].exists()
        cfg["secrets_csv"].parent.mkdir(parents=True, exist_ok=True)
        with open(cfg["secrets_csv"], "a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["severity", "type", "url", "value", "context"])
            if csv_new:
                w.writeheader()
            w.writerow({
                "severity": finding["severity"],
                "type":     finding["type"],
                "url":      finding["url"],
                "value":    finding["value"],
                "context":  finding["context"][:300],
            })
        append_line_to_file(
            cfg["secrets_jsonl"],
            json.dumps({
                "severity": finding["severity"],
                "type":     finding["type"],
                "url":      finding["url"],
                "value":    finding["value"],
                "context":  finding["context"][:300],
            }, ensure_ascii=False),
        )
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Persistência de endpoints
# ─────────────────────────────────────────────────────────────────────────────

def _abs_url(path: str, js_url: str, domain: str) -> str:
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return path
    base = f"https://{domain}"
    return base + (path if path.startswith("/") else "/" + path)


def _query_params(url_or_path: str) -> str:
    if "?" not in url_or_path:
        return ""
    qs = url_or_path.split("?", 1)[1].split("#")[0]
    try:
        parsed = urllib.parse.parse_qs(qs, keep_blank_values=True)
        return "&".join(f"{k}={v}" for k, vs in parsed.items() for v in vs)
    except Exception:
        return qs


def _save_endpoint(ep: dict, cfg: dict) -> bool:
    method    = ep.get("method", "UNKNOWN").upper()
    path      = ep.get("path", "").strip()
    path_base = path.split("?")[0].rstrip("/") or "/"
    key       = (method if method != "ANY" else "_", path_base)

    with _endpoint_write_lock:
        if key in _seen_endpoints:
            return False
        _seen_endpoints.add(key)

        abs_u = ep.get("absolute_url") or _abs_url(path, ep.get("js_url", ""), cfg["domain"])
        line  = (f"[{method}] {path}\n"
                 f"  → Absoluta : {abs_u}\n"
                 f"  → Fonte JS : {ep.get('js_url','?')}\n")
        if ep.get("query_params"):
            line += f"  → Query    : {ep['query_params']}\n"
        line += "-" * 60
        append_line_to_file(cfg["endpoints_txt"], line)
        append_line_to_file(cfg["endpoints_jsonl"], json.dumps({
            "method":       method,
            "path":         path,
            "absolute_url": abs_u,
            "query_params": ep.get("query_params", ""),
            "js_source":    ep.get("js_url", ""),
        }, ensure_ascii=False))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Cache de JS em disco
# ─────────────────────────────────────────────────────────────────────────────

_JS_CACHE_VERSION = "v1"
_JS_CACHE_TTL     = 86400


def _cache_path(cfg: dict, url: str) -> Path:
    url_hash = hashlib.sha1(url.encode()).hexdigest()[:16]
    return cfg["base_dir"] / ".js_cache" / f"{url_hash}.json"


def _load_cached_js(cfg: dict, url: str) -> str | None:
    if cfg.get("_no_cache"):
        return None
    path = _cache_path(cfg, url)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != _JS_CACHE_VERSION:
            return None
        if time.time() - data.get("ts", 0) > _JS_CACHE_TTL:
            return None
        return data.get("content")
    except Exception:
        return None


def _save_cached_js(cfg: dict, url: str, content: str) -> None:
    if cfg.get("_no_cache"):
        return
    path = _cache_path(cfg, url)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps({"version": _JS_CACHE_VERSION, "ts": time.time(), "content": content},
                       ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Análise de conteúdo JS — núcleo
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_js(resp: requests.Response, content: str) -> bool:
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct or "ecmascript" in ct:
        return True
    stripped = content.strip()
    if stripped.startswith(("<html", "<HTML", "<!DOCTYPE", "<!doctype", "<?xml")):
        return False
    if re.match(r'^\s*[{\[]', stripped) and not re.search(
            r'(?:var |let |const |function|=>|\bif\b|\bfor\b)', stripped[:500]):
        return False
    return True


def _secret_context(content: str, start: int, end: int, radius: int = 90) -> str:
    left  = max(0, start - radius)
    right = min(len(content), end + radius)
    return content[left:right].replace("\r", " ").replace("\n", " ").strip()


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
    domain      = cfg["domain"]

    def _line_at(pos: int) -> str:
        char_count = 0
        for line in lines:
            char_count += len(line) + 1
            if char_count >= pos:
                return line
        return ""

    # ── Segredos ──────────────────────────────────────────────────────────────
    for name, pattern in cfg["secret_patterns"].items():
        for match in pattern.finditer(content):
            raw_value = match.group(0)
            value     = match.group(1) if match.lastindex and match.lastindex >= 1 else raw_value

            if name in generic_set:
                if not is_likely_real_credential(value, _line_at(match.start())):
                    continue

            if name == "jwt" and not _is_real_jwt(value):
                continue

            context = _secret_context(content, match.start(), match.end())
            finding = {"type": name, "value": value, "url": url, "context": context}

            if _append_secret(finding, cfg):
                logger.warning("[!!!] %s → %s | %s", name, value[:80], url)
                found += 1
                if name == "google_api_key":
                    with google_keys_lock:
                        google_keys_found.add(value)

    # ── Ofuscação por char-code arrays ────────────────────────────────────────
    for obf in scan_charcode_obfuscation(content, url, logger):
        if _append_secret(obf, cfg):
            found += 1

    # ── Análise dedicada de btoa() ────────────────────────────────────────────
    _btoa_re = re.compile(r'\bbtoa\s*\(\s*["\'](.*?)["\'\']\s*\)', re.I)
    for bm in _btoa_re.finditer(content):
        raw_val = bm.group(1)
        ctx     = content[max(0, bm.start()-80):min(len(content), bm.end()+80)].replace("\n", " ")
        finding = {"type": "btoa_decoded", "value": raw_val, "url": url, "context": ctx}
        if _append_secret(finding, cfg):
            decoded = ""
            try:
                decoded = _b64.b64decode(raw_val + "==").decode("utf-8", errors="replace")
            except Exception:
                pass
            if decoded and decoded != raw_val:
                logger.warning("[!!!] btoa decoded → '%s' (claro: '%s') | %s", raw_val, decoded, url)
            else:
                logger.warning("[!!!] btoa hardcoded → '%s' | %s", raw_val, url)
            found += 1

    # ── Endpoints ─────────────────────────────────────────────────────────────
    for label, pattern, method_hint in cfg["endpoint_patterns"]:
        for m in pattern.finditer(content):
            path = (m.group(1) or "").strip().strip("\"'`")
            if not path or len(path) < 2:
                continue
            if re.search(r'\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|css)$', path, re.I):
                continue
            method = (m.group(2).upper()
                      if method_hint == "DYNAMIC" and m.lastindex and m.lastindex >= 2
                      else method_hint)
            ep = {
                "method":       method,
                "path":         path,
                "absolute_url": _abs_url(path, url, domain),
                "query_params": _query_params(path),
                "js_url":       url,
            }
            if _save_endpoint(ep, cfg):
                logger.debug("[EP][%s] %s ← %s", method, path, url)

    return found


# ─────────────────────────────────────────────────────────────────────────────
# Análise de JS (workers)
# ─────────────────────────────────────────────────────────────────────────────

def process_js(
    url: str,
    cfg: dict,
    logger: logging.Logger,
    google_keys_found: set,
    google_keys_lock: threading.Lock,
    get_fn,
) -> int:
    url_key = url.split("?")[0]
    with _analyzed_js_lock:
        if url_key in _analyzed_js_urls:
            return 0
        _analyzed_js_urls.add(url_key)

    cached = _load_cached_js(cfg, url_key)
    if cached is not None:
        logger.debug("[disk-cache-hit] %s", url)
        return analyze_js_content(cached, url, cfg, logger, google_keys_found, google_keys_lock)

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
        return 0
    _save_cached_js(cfg, url_key, content)
    return analyze_js_content(content, url, cfg, logger, google_keys_found, google_keys_lock)


def analyze_all_js(cfg: dict, logger: logging.Logger) -> tuple[int, set]:
    if not cfg["js_file"].exists():
        logger.warning("Nenhum arquivo JS para analisar.")
        return 0, set()
    urls = [u.strip() for u in cfg["js_file"].read_text(encoding="utf-8").splitlines() if u.strip()]
    if not urls:
        return 0, set()

    total_found:       int            = 0
    google_keys_found: set            = set()
    google_keys_lock:  threading.Lock = threading.Lock()
    get_fn                            = _make_retrying_get(cfg)

    logger.info("Analisando %d arquivos JS com %d workers…", len(urls), cfg["js_workers"])
    with ThreadPoolExecutor(max_workers=cfg["js_workers"]) as executor:
        futures = {
            executor.submit(process_js, url, cfg, logger,
                            google_keys_found, google_keys_lock, get_fn): url
            for url in urls
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
# Padrões específicos de source maps para alertas estruturais
# ─────────────────────────────────────────────────────────────────────────────

# Paths que indicam exposição de código-fonte interno
_MAP_SENSITIVE_PATH_RE = re.compile(
    r'(?:'
    r'\.env|/env\b|'
    r'config(?:uration)?[/.]|'
    r'secret[s]?[/.]|'
    r'credential[s]?[/.]|'
    r'private[/.]|'
    r'internal[/.]|'
    r'\.git/|'
    r'node_modules/(?!@types)|'  # node_modules mas não @types (definitivo)
    r'src/(?:services?|api|auth|store|redux|vuex|context)|'
    r'\.(pem|key|crt|pfx)$'
    r')',
    re.I,
)

# Paths que valem LOW — apenas para informação
_MAP_INTERNAL_PATH_RE = re.compile(
    r'(?:webpack://|webpack-internal://|/src/|/app/|/pages/|/components/)',
    re.I,
)


def _analyze_sourcemap_structure(
    map_url: str,
    data: dict,
    cfg: dict,
    logger: logging.Logger,
) -> int:
    """
    Analisa a estrutura do JSON do source map em busca de:
      - Paths de fontes sensíveis (campo 'sources')
      - Paths absolutos vazando estrutura do servidor
      - Metadata como 'file' e 'sourceRoot' revelando informações internas
    Registra achados no mesmo pipeline de segredos, com tipos dedicados.
    Retorna o número de achados estruturais novos.
    """
    found = 0

    # ── Campo 'file': path do JS compilado ────────────────────────────────────
    file_field = data.get("file", "")
    if file_field and re.search(r'(?:/home/|/var/|/opt/|/srv/|/root/|[A-Z]:\\)', file_field):
        ctx = f"source map 'file' field: {file_field}"
        finding = {
            "type":    "sourcemap_internal_path",
            "value":   file_field,
            "url":     map_url,
            "context": ctx,
        }
        if _append_secret(finding, cfg):
            logger.warning("[!!!] [sourcemap] path absoluto interno no campo 'file': %s | %s",
                           file_field, map_url)
            found += 1

    # ── Campo 'sourceRoot': raiz do projeto no servidor ───────────────────────
    source_root = data.get("sourceRoot", "")
    if source_root and len(source_root) > 1 and source_root not in ("webpack://", "/"):
        ctx = f"source map 'sourceRoot': {source_root}"
        finding = {
            "type":    "sourcemap_internal_path",
            "value":   source_root,
            "url":     map_url,
            "context": ctx,
        }
        if _append_secret(finding, cfg):
            logger.warning("[!!!] [sourcemap] sourceRoot exposto: %s | %s", source_root, map_url)
            found += 1

    # ── Campo 'sources': lista de paths de código-fonte ──────────────────────
    sources = data.get("sources", [])
    sensitive_paths:  list[str] = []
    interesting_paths: list[str] = []

    for src_path in sources:
        if not src_path or not isinstance(src_path, str):
            continue
        if _MAP_SENSITIVE_PATH_RE.search(src_path):
            sensitive_paths.append(src_path)
        elif _MAP_INTERNAL_PATH_RE.search(src_path):
            interesting_paths.append(src_path)

    if sensitive_paths:
        value = "\n".join(sensitive_paths[:20])
        ctx   = f"Paths sensíveis em sources[] do source map ({len(sensitive_paths)} total)"
        finding = {
            "type":    "sourcemap_env_path",
            "value":   value,
            "url":     map_url,
            "context": ctx,
        }
        if _append_secret(finding, cfg):
            logger.warning(
                "[!!!] [sourcemap] %d paths sensíveis em sources[]: %s | %s",
                len(sensitive_paths), sensitive_paths[:3], map_url,
            )
            found += 1

    if interesting_paths and not sensitive_paths:
        # Apenas loga como informação, não registra como segredo
        logger.info(
            "[sourcemap] %d paths internos expostos (webpack/src) em %s",
            len(interesting_paths), map_url,
        )

    return found


# ─────────────────────────────────────────────────────────────────────────────
# Coleta e análise de source maps (.js.map) — FILTRADO POR DOMÍNIO + análise completa
# ─────────────────────────────────────────────────────────────────────────────

def collect_and_analyze_sourcemaps(cfg: dict, logger: logging.Logger,
                                   google_keys_found: set,
                                   google_keys_lock: threading.Lock) -> int:
    """
    1. Coleta URLs .js.map do arquivo de URLs ativas, FILTRANDO pelo domínio do alvo.
    2. Para cada arquivo JS do alvo, tenta também inferir o .map correspondente.
    3. Para cada map válido:
       a. Analisa a ESTRUTURA do JSON (sources[], sourceRoot, file) — achados estruturais.
       b. Analisa cada entrada de sourcesContent[] com os mesmos padrões de segredos do JS.
       c. Registra tudo no pipeline unificado de segredos.
    """
    source = cfg.get("_active_urls_file", cfg["urls_file"])
    domain = cfg["domain"]

    if not source.exists():
        return 0

    all_urls = [l.strip() for l in source.read_text(encoding="utf-8").splitlines() if l.strip()]
    get_fn   = _make_retrying_get(cfg)
    map_urls: set[str] = set()

    # URLs já identificadas como .js.map — filtrar por domínio
    for url in all_urls:
        if url.endswith(".js.map") and _belongs_to_target(url, domain):
            map_urls.add(url)

    # Para cada JS do alvo, inferir o map candidato
    for url in all_urls:
        if not _belongs_to_target(url, domain):
            continue
        if re.search(r'\.js(\?|$)', url):
            candidate = re.sub(r'\.js(\?.*)?$', '.js.map', url)
            map_urls.add(candidate)

    # Também tentar a partir dos JS já filtrados
    if cfg["js_file"].exists():
        for url in cfg["js_file"].read_text(encoding="utf-8").splitlines():
            url = url.strip()
            if url and _belongs_to_target(url, domain):
                candidate = re.sub(r'\.js(\?.*)?$', '.js.map', url)
                map_urls.add(candidate)

    if not map_urls:
        logger.info("[sourcemaps] nenhuma URL candidata encontrada.")
        return 0

    logger.info("[sourcemaps] tentando %d URLs de source map (alvo: %s)…", len(map_urls), domain)
    sourcemap_dir  = cfg["base_dir"] / "sourcemaps"
    findings       = 0
    confirmed: list[str] = []
    confirmed_lock = threading.Lock()

    def _process_map(map_url: str) -> int:
        local_findings = 0

        # Verificar novamente o domínio (pode ter vindo de inferência)
        if not _belongs_to_target(map_url, domain):
            return 0

        try:
            resp = get_fn(map_url)
        except Exception:
            return 0

        if resp.status_code != 200:
            return 0

        # Detectar HTML falso (CDN/WAF retornando página de erro)
        raw = resp.text
        if "<html" in raw[:200].lower():
            return 0

        try:
            data = resp.json()
        except Exception:
            return 0

        # Verificar se é de fato um source map (campo obrigatório: version ou sources)
        if not isinstance(data, dict):
            return 0
        if "sources" not in data and "mappings" not in data:
            return 0

        sources_content = data.get("sourcesContent", [])
        sources_names   = data.get("sources", [])

        with confirmed_lock:
            confirmed.append(map_url)

        sourcemap_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r'[^\w\-.]', '_', map_url)[:100]

        n_srcs    = len([s for s in sources_content if s])
        n_sources = len(sources_names)
        logger.warning(
            "[!!!] Source map confirmado: %s  |  %d paths em sources[]  |  %d com código-fonte",
            map_url, n_sources, n_srcs,
        )

        # ── a) Análise estrutural do JSON (paths, sourceRoot, file) ───────────
        struct_findings = _analyze_sourcemap_structure(map_url, data, cfg, logger)
        local_findings += struct_findings

        # ── b) Análise de cada sourcesContent[] como JS real ─────────────────
        for i, src_content in enumerate(sources_content):
            if not src_content or not isinstance(src_content, str):
                continue
            src_name    = sources_names[i] if i < len(sources_names) else f"source_{i}"
            virtual_url = f"{map_url}::{src_name}"

            # Salvar o arquivo de fonte em disco para auditoria posterior
            try:
                safe_src = re.sub(r'[^\w\-.]', '_', src_name)[:60]
                (sourcemap_dir / f"{safe}_{i:04d}_{safe_src}").write_text(
                    src_content, encoding="utf-8", errors="replace"
                )
            except Exception:
                pass

            # Rodar análise completa de segredos no conteúdo da fonte
            n = analyze_js_content(
                src_content, virtual_url, cfg, logger,
                google_keys_found, google_keys_lock,
            )
            local_findings += n

        # ── c) Também analisar o JSON inteiro (pode ter segredos fora do sourcesContent) ──
        n_raw = analyze_js_content(
            raw, f"{map_url}::raw_json", cfg, logger,
            google_keys_found, google_keys_lock,
        )
        local_findings += n_raw

        return local_findings

    with ThreadPoolExecutor(max_workers=cfg["js_workers"]) as executor:
        futs = {executor.submit(_process_map, u): u for u in map_urls}
        for fut in as_completed(futs):
            try:
                findings += fut.result()
            except Exception as exc:
                logger.debug("[sourcemaps] erro: %s", exc)

    if confirmed:
        write_if_not_empty(cfg["base_dir"] / "sourcemaps_found.txt", confirmed, logger)
        logger.warning(
            "[!!!] Source maps confirmados: %d  |  segredos/alertas: %d",
            len(confirmed), findings,
        )
    else:
        logger.info("[sourcemaps] nenhum source map público confirmado.")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Análise por subdomínio
# ─────────────────────────────────────────────────────────────────────────────

def _probe_alive_urls(urls: list[str], timeout: int, logger: logging.Logger) -> list[str]:
    if not urls:
        return []
    if not tool_available("httpx"):
        return urls
    try:
        result = subprocess.run(
            ["httpx", "-silent", "-mc", "200,201,204,301,302,307,308,403",
             "-threads", "50", "-timeout", str(timeout)],
            input="\n".join(urls) + "\n",
            capture_output=True, text=True, timeout=300,
        )
        return [u.strip() for u in result.stdout.splitlines() if u.strip()]
    except Exception as exc:
        logger.error("httpx (subs): %s", exc)
        return urls


def _collect_js_from_sub(sub_url: str, cfg: dict, logger: logging.Logger) -> set[str]:
    """Coleta JS de um subdomínio, garantindo que o resultado pertence ao alvo."""
    all_urls: set[str] = set()
    domain = cfg["domain"]
    js_re = re.compile(
        r'(?:\.js(?:\?[^\s]*)?$|/(?:static|assets|dist|build|chunks|bundles)/[^\s]*\.js)', re.I,
    )
    if tool_available("hakrawler"):
        lines = run_cmd(
            ["hakrawler", "-d", "2", "-u", "-t", "8", "-insecure"],
            logger, stdin=sub_url + "\n", timeout=60,
        )
        all_urls.update(lines)
    if tool_available("gospider"):
        raw = run_cmd(
            ["gospider", "-s", sub_url, "-c", "5", "-d", "2", "--js", "-q"],
            logger, timeout=60,
        )
        for line in raw:
            m = re.search(r'https?://[^\s"\'<>\]]+', line)
            if m:
                all_urls.add(m.group(0).rstrip('.,;)"\'>]'))
    return {
        u for u in all_urls
        if not _CDN_DOMAINS_RE.search(u)
        and not u.endswith(".js.map")
        and js_re.search(u)
        and _belongs_to_target(u, domain)
    }


def analyze_subdomains(
    root_domain: str,
    args: argparse.Namespace,
    cfg: dict,
    logger: logging.Logger,
    all_google_keys: set,
    google_keys_lock: threading.Lock,
) -> dict:
    logger.info("=" * 60)
    logger.info("ANÁLISE DE SUBDOMÍNIOS — %s", root_domain)
    logger.info("=" * 60)

    if not tool_available("subfinder"):
        logger.warning("subfinder não encontrado — pulando análise de subdomínios.")
        return {}

    subs: set[str] = set()
    lines = run_cmd(["subfinder", "-d", root_domain, "-silent"], logger, timeout=300)
    subs.update(lines)
    logger.info("[subfinder] %d subdomínios", len(lines))

    subs_clean = sorted({
        s.strip().lower() for s in subs
        if s.strip() and "*" not in s
        and s.strip().lower() != root_domain and root_domain in s
    })
    if not subs_clean:
        logger.info("Nenhum subdomínio encontrado para %s.", root_domain)
        return {}
    logger.info("Subdomínios únicos: %d", len(subs_clean))

    alive_urls = _probe_alive_urls([f"https://{s}" for s in subs_clean], cfg["request_timeout"], logger)
    http_extra = _probe_alive_urls(
        [f"http://{s}" for s in subs_clean if f"https://{s}" not in set(alive_urls)],
        cfg["request_timeout"], logger,
    )
    alive_urls = sorted(set(alive_urls) | set(http_extra))
    logger.info("Subdomínios vivos: %d / %d", len(alive_urls), len(subs_clean))
    if not alive_urls:
        return {}

    write_if_not_empty(cfg["base_dir"] / "subdomains_alive.txt", alive_urls, logger)

    sub_stats: dict[str, dict] = {}
    get_fn = _make_retrying_get(cfg)

    for sub_url in alive_urls:
        sub_host = re.sub(r'^https?://', '', sub_url).rstrip('/')
        logger.info("─── Analisando: %s", sub_host)
        safe_sub = re.sub(r'[^\w\-.]', '_', sub_host)
        sub_dir  = cfg["base_dir"] / "subdomains" / safe_sub
        sub_dir.mkdir(parents=True, exist_ok=True)

        js_urls = _collect_js_from_sub(sub_url, cfg, logger)
        logger.info("  JS encontrado: %d arquivos", len(js_urls))
        if not js_urls:
            sub_stats[sub_host] = {"js": 0, "secrets": 0}
            continue

        write_if_not_empty(sub_dir / "js_urls.txt", sorted(js_urls), logger)
        sub_findings = 0
        for js_url in js_urls:
            url_key = js_url.split("?")[0]
            with _analyzed_js_lock:
                if url_key in _analyzed_js_urls:
                    continue
                _analyzed_js_urls.add(url_key)
            cached = _load_cached_js(cfg, url_key)
            if cached is not None:
                sub_findings += analyze_js_content(cached, js_url, cfg, logger,
                                                   all_google_keys, google_keys_lock)
                continue
            try:
                resp = get_fn(js_url)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            content = resp.text
            if not is_valid_js(resp, content):
                continue
            _save_cached_js(cfg, url_key, content)
            sub_findings += analyze_js_content(content, js_url, cfg, logger,
                                               all_google_keys, google_keys_lock)
        sub_stats[sub_host] = {"js": len(js_urls), "secrets": sub_findings}
        if sub_findings:
            logger.warning("  [!!!] %d segredo(s) em %s", sub_findings, sub_host)
        else:
            logger.info("  Nenhum segredo em %s", sub_host)

    total_subs_secrets = sum(v["secrets"] for v in sub_stats.values())
    total_subs_js      = sum(v["js"]      for v in sub_stats.values())
    logger.info("SUBDOMÍNIOS — %d analisados | %d JS | %d segredos",
                len(sub_stats), total_subs_js, total_subs_secrets)

    report_lines = [
        "ANÁLISE POR SUBDOMÍNIO", f"Domínio raiz: {root_domain}", "=" * 60, "",
    ]
    for sub, data in sorted(sub_stats.items(), key=lambda x: -x[1]["secrets"]):
        status = "[!!!]" if data["secrets"] > 0 else "[ ok]"
        report_lines.append(
            f"{status} {sub:<50}  JS: {data['js']:>4}  Segredos: {data['secrets']:>4}"
        )
    write_if_not_empty(cfg["base_dir"] / "subdomains_report.txt", report_lines, logger)

    return {
        "subs_found":   len(subs_clean),
        "subs_alive":   len(alive_urls),
        "subs_js":      total_subs_js,
        "subs_secrets": total_subs_secrets,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Agrupamento por severidade para o SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def _summary_by_severity(secrets_jsonl: Path) -> list[str]:
    counts: dict[str, int] = collections.Counter()
    sevs:   dict[str, str] = {}
    if not secrets_jsonl.exists():
        return []
    for line in secrets_jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            obj = json.loads(line)
            t   = obj.get("type", "?")
            counts[t] += 1
            sevs[t] = obj.get("severity", "UNKNOWN")
        except json.JSONDecodeError:
            pass
    return [
        f"    [{sevs.get(t,'?')}] {t}: {n}"
        for t, n in sorted(counts.items(),
                           key=lambda x: (_SEVERITY_ORDER.get(sevs.get(x[0], "UNKNOWN"), 4), -x[1]))
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Sumário TXT
# ─────────────────────────────────────────────────────────────────────────────

def write_summary(cfg: dict, logger: logging.Logger, stats: dict) -> None:
    def _count(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip())

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
        "=" * 64, "",
        f"  URLs coletadas           : {_f('urls_total')}",
        f"  URLs ativas (httpx)      : {_f('urls_alive')}",
        f"  Arquivos JS (alvo)       : {_f('js_total')}",
        f"  URLs sensíveis           : {_f('sensitive_total')}",
        "",
        f"  Segredos encontrados     : {_f('js_findings')}",
        f"  ↳ Em source maps         : {_f('sourcemap_findings')}",
        f"  ↳ Em inline scripts      : {_f('inline_findings')}",
    ]

    sev_lines = _summary_by_severity(cfg["secrets_jsonl"])
    if sev_lines:
        lines.append("")
        lines.append("  Por tipo (ordenado por severidade):")
        lines.extend(sev_lines)

    lines += [
        "",
        f"  Endpoints extraídos      : {str(_count(cfg['endpoints_jsonl'])).rjust(6)}",
        f"  Google Keys encontradas  : {_f('google_keys')}",
        f"  Google Keys vulneráveis  : {str(vuln_google).rjust(6)}",
        "",
        f"  Segredos em .env/.conf   : {_f('sensitive_findings')}",
        f"  XSS confirmados (dalfox) : {_f('xss_hits')}",
        f"  SSRF/Redirect hits       : {_f('ssrf_redirect_hits')}",
    ]

    if stats.get("subs_found", 0) > 0:
        lines += [
            "",
            "── Subdomínios ──────────────────────────────────────────",
            f"  Subdomínios encontrados  : {_f('subs_found')}",
            f"  Subdomínios vivos        : {_f('subs_alive')}",
            f"  JS em subdomínios        : {_f('subs_js')}",
            f"  Segredos em subdomínios  : {_f('subs_secrets')}",
        ]

    output_files = [
        ("Segredos TXT",    cfg["secrets_txt"]),
        ("Segredos CSV",    cfg["secrets_csv"]),
        ("Segredos JSONL",  cfg["secrets_jsonl"]),
        ("Endpoints TXT",   cfg["endpoints_txt"]),
        ("Endpoints JSONL", cfg["endpoints_jsonl"]),
        ("Google Keys",     cfg["google_report_file"]),
        ("Sensíveis",       cfg["sensitive_report"]),
        ("SUMMARY HTML",    cfg["summary_html"]),
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
# SUMMARY.html interativo
# ─────────────────────────────────────────────────────────────────────────────

def write_summary_html(cfg: dict, logger: logging.Logger, stats: dict) -> None:
    findings: list[dict] = []
    endpoints: list[dict] = []

    if cfg["secrets_jsonl"].exists():
        for line in cfg["secrets_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                obj = json.loads(line)
                obj.setdefault("severity", get_severity(obj.get("type", "")))
                findings.append(obj)
            except json.JSONDecodeError:
                pass

    if cfg["endpoints_jsonl"].exists():
        for line in cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                endpoints.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    findings.sort(key=lambda x: (_SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 4), x.get("type", "")))

    sev_colors = {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22",
        "MEDIUM":   "#2980b9", "LOW":  "#27ae60", "UNKNOWN": "#7f8c8d",
    }
    meth_colors = {
        "GET": "#27ae60", "POST": "#e67e22", "PUT": "#2980b9",
        "DELETE": "#c0392b", "PATCH": "#8e44ad", "WS": "#16a085",
        "ANY": "#7f8c8d", "UNKNOWN": "#7f8c8d", "DYNAMIC": "#7f8c8d",
    }
    sev_counts = {s: sum(1 for f in findings if f.get("severity") == s)
                  for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    secret_rows = ""
    for f in findings:
        sev   = f.get("severity", "UNKNOWN")
        color = sev_colors.get(sev, "#7f8c8d")
        url   = f.get("url", "")
        val   = _esc(f.get("value", "")[:120])
        ctx   = _esc(f.get("context", "")[:200])
        secret_rows += (
            f'<tr data-sev="{sev}" data-type="{f.get("type","")}">'
            f'<td><span class="badge" style="background:{color}">{sev}</span></td>'
            f'<td><code>{f.get("type","")}</code></td>'
            f'<td class="url-cell"><a href="{url}" target="_blank" rel="noopener">{url[:100]}</a></td>'
            f'<td class="mono">{val}</td>'
            f'<td class="ctx">{ctx}</td></tr>\n'
        )

    ep_rows = ""
    for ep in endpoints:
        m    = ep.get("method", "?")
        mc   = meth_colors.get(m, "#7f8c8d")
        path = _esc(ep.get("path", "")[:120])
        abs_ = ep.get("absolute_url", "")
        qp   = _esc(ep.get("query_params", "")[:80])
        src  = _esc(ep.get("js_source", "")[:80])
        ep_rows += (
            f'<tr><td><span class="badge" style="background:{mc}">{m}</span></td>'
            f'<td class="mono">{path}</td>'
            f'<td class="url-cell"><a href="{abs_}" target="_blank">{abs_[:80]}</a></td>'
            f'<td class="ctx">{qp}</td>'
            f'<td class="ctx">{src}</td></tr>\n'
        )

    types_opts  = "".join(f'<option value="{t}">{t}</option>'
                           for t in sorted(set(f.get("type","") for f in findings)))
    method_opts = "".join(f'<option value="{m}">{m}</option>'
                           for m in sorted(set(ep.get("method","") for ep in endpoints)))
    ts = time.strftime("%Y-%m-%d %H:%M")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>recon — {cfg['domain']}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;font-size:14px}}
a{{color:#60a5fa;text-decoration:none}}a:hover{{text-decoration:underline}}
code{{font-family:'SFMono-Regular',Consolas,monospace;font-size:12px;background:#1e2130;padding:1px 5px;border-radius:3px}}
header{{background:#1a1d2e;border-bottom:1px solid #2d3148;padding:1rem 1.5rem}}
header h1{{font-size:16px;font-weight:600;color:#f1f5f9}}
header p{{font-size:12px;color:#64748b;margin-top:4px}}
.banner{{display:flex;gap:.75rem;padding:.75rem 1.5rem;background:#141620;border-bottom:1px solid #2d3148;flex-wrap:wrap}}
.card{{background:#1a1d2e;border:1px solid #2d3148;border-radius:6px;padding:.5rem .9rem;min-width:90px;text-align:center}}
.card .n{{font-size:22px;font-weight:700;line-height:1.1}}
.card .l{{font-size:11px;color:#64748b;margin-top:2px}}
.tabs{{display:flex;padding:0 1.5rem;background:#141620;border-bottom:1px solid #2d3148}}
.tab{{padding:.6rem 1.2rem;cursor:pointer;font-size:13px;color:#64748b;border-bottom:2px solid transparent}}
.tab.active{{color:#f1f5f9;border-bottom-color:#60a5fa}}
.tab-content{{display:none}}.tab-content.active{{display:block}}
.ctrl{{display:flex;gap:.75rem;padding:.65rem 1.5rem;background:#141620;border-bottom:1px solid #2d3148;flex-wrap:wrap;align-items:center}}
.ctrl select,.ctrl input{{background:#1a1d2e;border:1px solid #2d3148;border-radius:5px;color:#e2e8f0;padding:5px 8px;font-size:13px}}
.ctrl input[type=search]{{width:220px}}
.cnt{{font-size:12px;color:#64748b;margin-left:auto}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}}
table{{width:100%;border-collapse:collapse}}
thead th{{background:#1a1d2e;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:8px 10px;text-align:left;cursor:pointer;border-bottom:1px solid #2d3148;white-space:nowrap;user-select:none}}
thead th:hover{{color:#f1f5f9}}
td{{padding:7px 10px;border-bottom:1px solid #1e2130;vertical-align:top}}
tr:hover td{{background:#1a1d2e}}tr.hidden{{display:none}}
.url-cell{{max-width:260px;word-break:break-all;font-size:12px}}
.mono{{font-family:'SFMono-Regular',Consolas,monospace;font-size:11px;word-break:break-all;max-width:200px;color:#a3e635}}
.ctx{{font-size:11px;color:#64748b;max-width:260px;word-break:break-all}}
footer{{padding:.75rem 1.5rem;font-size:11px;color:#334155;border-top:1px solid #1e2130;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>recon — {cfg['domain']}</h1>
  <p>{ts} · {stats.get('urls_total',0)} URLs · {stats.get('js_total',0)} JS · {len(findings)} segredos · {len(endpoints)} endpoints</p>
</header>
<div class="banner">
  {"".join(f'<div class="card"><div class="n" style="color:{sev_colors[s]}">{sev_counts[s]}</div><div class="l">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])}
  <div class="card"><div class="n" style="color:#60a5fa">{len(endpoints)}</div><div class="l">Endpoints</div></div>
  <div class="card"><div class="n" style="color:#a78bfa">{stats.get('js_total',0)}</div><div class="l">JS</div></div>
  <div class="card"><div class="n" style="color:#34d399">{stats.get('inline_findings',0)}</div><div class="l">Inline scripts</div></div>
  <div class="card"><div class="n" style="color:#f472b6">{stats.get('xss_hits',0)}</div><div class="l">XSS</div></div>
  <div class="card"><div class="n" style="color:#fb923c">{stats.get('ssrf_redirect_hits',0)}</div><div class="l">SSRF/Redir</div></div>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('s',this)">🔑 Segredos ({len(findings)})</div>
  <div class="tab" onclick="switchTab('e',this)">🔗 Endpoints ({len(endpoints)})</div>
</div>

<div id="tab-s" class="tab-content active">
<div class="ctrl">
  <label>Severidade <select id="sf" onchange="fs()"><option value="">Todas</option>
    <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
  </select></label>
  <label>Tipo <select id="tf" onchange="fs()"><option value="">Todos</option>{types_opts}</select></label>
  <input id="ss" type="search" placeholder="Buscar…" oninput="fs()">
  <span id="sc" class="cnt">{len(findings)} de {len(findings)}</span>
</div>
<table id="st"><thead><tr>
  <th onclick="sort('st',0)">Sev ↕</th><th onclick="sort('st',1)">Tipo ↕</th>
  <th onclick="sort('st',2)">URL ↕</th><th>Valor</th><th>Contexto</th>
</tr></thead><tbody>{secret_rows}</tbody></table>
</div>

<div id="tab-e" class="tab-content">
<div class="ctrl">
  <label>Método <select id="mf" onchange="fe()"><option value="">Todos</option>{method_opts}</select></label>
  <input id="es" type="search" placeholder="Buscar…" oninput="fe()">
  <span id="ec" class="cnt">{len(endpoints)} de {len(endpoints)}</span>
</div>
<table id="et"><thead><tr>
  <th onclick="sort('et',0)">Método ↕</th><th onclick="sort('et',1)">Path ↕</th>
  <th onclick="sort('et',2)">URL Absoluta ↕</th><th>Query Params</th><th>JS Fonte</th>
</tr></thead><tbody>{ep_rows}</tbody></table>
</div>

<footer>recon.py · {cfg['domain']} · {len(findings)} segredos · {len(endpoints)} endpoints · {ts}</footer>
<script>
function switchTab(n,el){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');document.getElementById('tab-'+n).classList.add('active');
}}
const sr=Array.from(document.querySelectorAll('#st tbody tr'));
function fs(){{
  const sv=document.getElementById('sf').value,tv=document.getElementById('tf').value,
        q=document.getElementById('ss').value.toLowerCase();
  let v=0;
  sr.forEach(r=>{{const ok=(!sv||r.dataset.sev===sv)&&(!tv||r.dataset.type===tv)&&(!q||r.textContent.toLowerCase().includes(q));r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('sc').textContent=v+' de {len(findings)}';
}}
const er=Array.from(document.querySelectorAll('#et tbody tr'));
function fe(){{
  const mv=document.getElementById('mf').value,q=document.getElementById('es').value.toLowerCase();
  let v=0;
  er.forEach(r=>{{const b=r.cells[0]?.querySelector('.badge')?.textContent||'';
    const ok=(!mv||b===mv)&&(!q||r.textContent.toLowerCase().includes(q));r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('ec').textContent=v+' de {len(endpoints)}';
}}
let sd={{}};
function sort(tid,col){{
  const tbody=document.querySelector('#'+tid+' tbody');
  const rs=Array.from(tbody.querySelectorAll('tr'));
  const k=tid+col;sd[k]=(sd[k]||1)*-1;
  rs.sort((a,b)=>sd[k]*(a.cells[col]?.textContent.trim()||'').localeCompare(b.cells[col]?.textContent.trim()||''));
  rs.forEach(r=>tbody.appendChild(r));
  tid==='st'?fs():fe();
}}
</script>
</body>
</html>"""

    cfg["summary_html"].write_text(html, encoding="utf-8")
    logger.info("SUMMARY HTML → %s", cfg["summary_html"])


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reconhecimento web focado em JS: coleta URLs, extrai segredos e endpoints.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 recon.py exemplo.com.br
  python3 recon.py exemplo.com.br --no-subs --workers 30
  python3 recon.py exemplo.com.br --no-dalfox --no-ssrf-probe
  python3 recon.py exemplo.com.br --no-cache
        """,
    )
    parser.add_argument("domain",              nargs="?",            help="Domínio alvo. Ex: exemplo.com.br")
    parser.add_argument("--no-dalfox",         action="store_true",  help="Pula probe XSS com dalfox")
    parser.add_argument("--no-ssrf-probe",     action="store_true",  help="Pula probe SSRF/redirect")
    parser.add_argument("--no-sensitive-dl",   action="store_true",  help="Pula download de arquivos sensíveis")
    parser.add_argument("--no-httpx",          action="store_true",  help="Usa todas as URLs sem validar com httpx")
    parser.add_argument("--no-google-val",     action="store_true",  help="Pula validação de endpoints Google")
    parser.add_argument("--no-subs",           action="store_true",  help="Pula análise de subdomínios")
    parser.add_argument("--no-sourcemaps",     action="store_true",  help="Pula coleta e análise de source maps")
    parser.add_argument("--no-inline-scripts", action="store_true",  help="Pula análise de inline scripts em HTML")
    parser.add_argument("--no-cache",          action="store_true",  help="Ignora cache de JS em disco")
    parser.add_argument("--workers",           type=int, default=20, help="Workers JS (padrão: 20)")
    parser.add_argument("--timeout",           type=int, default=10, help="Timeout de requisições em segundos (padrão: 10)")
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

    for _pfx in ("https://", "http://"):
        if domain.startswith(_pfx):
            domain = domain[len(_pfx):]
            break
    domain = domain.rstrip("/")

    cfg                    = get_config(domain)
    cfg["js_workers"]      = max(1, args.workers)
    cfg["request_timeout"] = max(1, args.timeout)
    cfg["_no_cache"]       = args.no_cache
    logger                 = setup_logging(cfg["log_file"])
    stats: dict[str, int]  = {}

    logger.info("=" * 60)
    logger.info("Iniciando recon para: %s", domain)
    logger.info("Diretório de saída : %s", cfg["base_dir"])
    logger.info("=" * 60)

    if not preflight_check(logger, args):
        sys.exit(1)

    # ── 1. Coleta de URLs ─────────────────────────────────────────────────────
    stats["urls_total"] = collect_urls(cfg, logger)

    # ── 2. Validação com httpx ────────────────────────────────────────────────
    if args.no_httpx:
        cfg["_active_urls_file"] = cfg["urls_file"]
        stats["urls_alive"]      = stats["urls_total"]
        logger.info("--no-httpx: usando todas as URLs.")
    else:
        stats["urls_alive"] = validate_alive_urls(cfg, logger)

    # ── 3. GF + probes ────────────────────────────────────────────────────────
    run_gf(cfg, logger)
    stats["xss_hits"]           = 0 if args.no_dalfox     else probe_xss(cfg, logger)
    stats["ssrf_redirect_hits"] = 0 if args.no_ssrf_probe else probe_ssrf_redirect(cfg, logger)

    # ── 4. Arquivos sensíveis ─────────────────────────────────────────────────
    stats["sensitive_total"]    = extract_sensitive_urls(cfg, logger)
    stats["sensitive_findings"] = (0 if args.no_sensitive_dl
                                   else download_and_analyze_sensitive(cfg, logger))

    # ── 5. Coleta de JS (filtrada por domínio) ────────────────────────────────
    stats["js_total"] = collect_js(cfg, logger)

    google_keys_found: set            = set()
    google_keys_lock:  threading.Lock = threading.Lock()

    # ── 5b. Inline scripts ────────────────────────────────────────────────────
    if args.no_inline_scripts:
        logger.info("--no-inline-scripts: pulando.")
        stats["inline_findings"] = 0
    else:
        stats["inline_findings"] = analyze_inline_scripts(
            cfg, logger, google_keys_found, google_keys_lock
        )

    # ── 6. Análise de JS externos ─────────────────────────────────────────────
    js_findings, gkeys = analyze_all_js(cfg, logger)
    stats["js_findings"] = js_findings
    with google_keys_lock:
        google_keys_found.update(gkeys)

    # ── 6b. Source maps (filtrados por domínio + análise completa) ────────────
    if args.no_sourcemaps:
        logger.info("--no-sourcemaps: pulando.")
        stats["sourcemap_findings"] = 0
    else:
        sm = collect_and_analyze_sourcemaps(cfg, logger, google_keys_found, google_keys_lock)
        stats["sourcemap_findings"]  = sm
        stats["js_findings"]        += sm

    # ── 7. Subdomínios ────────────────────────────────────────────────────────
    if args.no_subs:
        logger.info("--no-subs: pulando.")
        stats.update({"subs_found": 0, "subs_alive": 0, "subs_js": 0, "subs_secrets": 0})
    else:
        sub_stats = analyze_subdomains(
            domain, args, cfg, logger, google_keys_found, google_keys_lock,
        )
        stats.update(sub_stats)

    # ── 8. Google Keys ────────────────────────────────────────────────────────
    stats["google_keys"] = len(google_keys_found)
    if args.no_google_val:
        if google_keys_found:
            write_if_not_empty(cfg["google_keys_file"], sorted(google_keys_found), logger)
        logger.info("--no-google-val: validação de endpoints Google pulada.")
    else:
        validate_all_google_keys(google_keys_found, cfg, logger)

    # ── 9. Relatórios ─────────────────────────────────────────────────────────
    write_summary(cfg, logger, stats)
    write_summary_html(cfg, logger, stats)

    logger.info("=" * 60)
    logger.info("Recon finalizado. Log: %s", cfg["log_file"])
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
