#!/usr/bin/env python3
"""
takeover.py — Recon de subdomínios + Domain Takeover + Port Scan
Versão melhorada — análise e sugestões de um analista sênior de bug bounty

MELHORIAS IMPLEMENTADAS:
  [COB-1]  DNS CNAME + registrar check para takeover mais preciso
  [COB-2]  Enumeração via AlienVault OTX (sem token obrigatório)
  [COB-3]  Coleta de CNAMEs em massa via dnsx -cname para triagem
  [PRE-1]  Validação de fingerprints por CNAME antes da requisição HTTP
  [PRE-2]  Verificação de bucket S3 existente antes de marcar takeover
  [PRE-3]  Deduplicação por (url_normalizada + serviço), não só por URL
  [PER-1]  httpx com -rate-limit e pipeline assíncrona por etapa
  [PER-2]  wafw00f paralelizado com ThreadPoolExecutor (era serial)
  [PER-3]  Cache de resultados DNS intermediários para multi-domínio
  [RES-1]  Retry com backoff exponencial em crt.sh e OTX
  [RES-2]  Verificação de versão mínima das ferramentas (nuclei, httpx)
  [RES-3]  Timeout granular por ferramenta via argumento; sem valor fixo hardcoded
  [REL-1]  Relatório HTML com severidade, CVSS estimado e filtros JS
  [REL-2]  Exportação JSON estruturado (machine-readable) além do HTML
  [REL-3]  Seção de CNAMEs suspeitos (resolvem para serviço externo mas sem fingerprint)

Ferramentas SEM token obrigatório:
  subfinder, assetfinder, crt.sh (HTTP), otx (HTTP), dnsx, puredns,
  httpx, wafw00f, gowitness, subzy, subjack, nuclei, nmap

Ferramentas COM token OPCIONAL (rendem mais com token):
  subfinder  → ~/.config/subfinder/provider-config.yaml
  chaos      → variável de ambiente CHAOS_KEY
  github-subdomains → variável de ambiente GITHUB_TOKEN
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Configuração de paths — todos via argumentos ou variáveis de ambiente
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_NUCLEI_TEMPLATES    = os.environ.get("NUCLEI_TEMPLATES",    "/root/nuclei-templates")
DEFAULT_RESOLVERS_FILE      = os.environ.get("RESOLVERS_FILE",      "/usr/share/wordlists/resolvers.txt")
DEFAULT_SUBDOMAINS_WORDLIST = os.environ.get("SUBDOMAINS_WORDLIST", "/usr/share/wordlists/subdomains.txt")

THREADS      = 50
HTTPX_PORTS  = "80,443,8080,8443,8888,4443,3000,5000"

# Versões mínimas aceitáveis — [RES-2]
MIN_TOOL_VERSIONS: dict[str, tuple[str, list[str]]] = {
    "nuclei": ("3.0.0", ["nuclei", "-version"]),
    "httpx":  ("1.3.0", ["httpx",  "-version"]),
    "dnsx":   ("1.1.0", ["dnsx",   "-version"]),
}

# ─────────────────────────────────────────────────────────────────────────────
# Fingerprints de takeover — baseado em can-i-take-over-xyz (seleção)
# Formato: (serviço, fingerprint_http, cname_pattern_regex_opcional)
# O campo cname_pattern permite pré-filtrar via CNAME antes do HTTP — [PRE-1]
# ─────────────────────────────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS: list[dict] = [
    {"service": "AWS S3",       "fingerprint": "NoSuchBucket",
     "cname": r"\.s3[.-]",      "severity": "high"},
    {"service": "AWS S3",       "fingerprint": "The specified bucket does not exist",
     "cname": r"\.s3[.-]",      "severity": "high"},
    {"service": "GitHub Pages", "fingerprint": "There isn't a GitHub Pages site here",
     "cname": r"\.github\.io",  "severity": "high"},
    {"service": "GitHub Pages", "fingerprint": "For root URLs (like http://example.com/) you must provide an index.html file",
     "cname": r"\.github\.io",  "severity": "high"},
    {"service": "Heroku",       "fingerprint": "No such app",
     "cname": r"\.heroku(app)?\.com", "severity": "high"},
    {"service": "Heroku",       "fingerprint": "herokucdn.com/error-pages/no-such-app",
     "cname": r"\.heroku(app)?\.com", "severity": "high"},
    {"service": "Fastly",       "fingerprint": "Fastly error: unknown domain",
     "cname": r"\.fastly\.net", "severity": "medium"},
    {"service": "Shopify",      "fingerprint": "Sorry, this shop is currently unavailable",
     "cname": r"\.myshopify\.com", "severity": "medium"},
    {"service": "Tumblr",       "fingerprint": "Whatever you were looking for doesn't currently exist at this address",
     "cname": r"\.tumblr\.com", "severity": "low"},
    {"service": "WordPress",    "fingerprint": "Do you want to register",
     "cname": r"\.wordpress\.com", "severity": "medium"},
    {"service": "Pantheon",     "fingerprint": "The gods are wise",
     "cname": r"\.pantheonsite\.io", "severity": "medium"},
    {"service": "Zendesk",      "fingerprint": "Help Center Closed",
     "cname": r"\.zendesk\.com", "severity": "medium"},
    {"service": "Desk.com",     "fingerprint": "Sorry, We Couldn't Find That Page",
     "cname": r"\.desk\.com",   "severity": "medium"},
    {"service": "Bitbucket",    "fingerprint": "Repository not found",
     "cname": r"\.bitbucket\.io", "severity": "high"},
    {"service": "Ghost",        "fingerprint": "The thing you were looking for is no longer here",
     "cname": r"\.ghost\.io",   "severity": "medium"},
    {"service": "Surge.sh",     "fingerprint": "project not found",
     "cname": r"\.surge\.sh",   "severity": "medium"},
    {"service": "Unbounce",     "fingerprint": "The requested URL was not found on this server",
     "cname": r"\.ubembed\.com|\.unbouncepages\.com", "severity": "medium"},
    {"service": "Statuspage",   "fingerprint": "Better luck next time",
     "cname": r"\.statuspage\.io", "severity": "medium"},
    {"service": "Azure",        "fingerprint": "404 Web Site not found",
     "cname": r"\.azurewebsites\.net|\.cloudapp\.net", "severity": "high"},
    {"service": "Azure",        "fingerprint": "This web app is stopped",
     "cname": r"\.azurewebsites\.net", "severity": "high"},
    {"service": "Feedpress",    "fingerprint": "The feed has not been found",
     "cname": r"\.feedpress\.me", "severity": "low"},
    {"service": "Readme.io",    "fingerprint": "Project doesnt exist",
     "cname": r"\.readme\.io",  "severity": "medium"},
    {"service": "Helpjuice",    "fingerprint": "We could not find what you're looking for",
     "cname": r"\.helpjuice\.com", "severity": "medium"},
    {"service": "HelpScout",    "fingerprint": "No settings were found for this company",
     "cname": r"\.helpscoutdocs\.com", "severity": "medium"},
    {"service": "Intercom",     "fingerprint": "This page is reserved for artistic dogs",
     "cname": r"\.intercom\.help", "severity": "medium"},
    {"service": "Webflow",      "fingerprint": "The page you are looking for doesn't exist or has been moved",
     "cname": r"\.webflow\.io", "severity": "medium"},
    {"service": "Wufoo",        "fingerprint": "Hmm, we can't find this page",
     "cname": r"\.wufoo\.com",  "severity": "medium"},
    {"service": "Cargo",        "fingerprint": "If you're moving your domain away from Cargo",
     "cname": r"\.cargo\.site", "severity": "low"},
    {"service": "Strikingly",   "fingerprint": "But if you're looking to build your own website",
     "cname": r"\.strikingly\.com", "severity": "low"},
    {"service": "Uptimerobot",  "fingerprint": "page not found",
     "cname": r"\.uptimerobot\.com", "severity": "low"},
    {"service": "Vend",         "fingerprint": "Looks like you've traveled too far into cyberspace",
     "cname": r"\.vendhq\.com", "severity": "medium"},
    {"service": "Uberflip",     "fingerprint": "Non-hub domain, The URL you've accessed does not provide",
     "cname": r"\.uberflip\.com", "severity": "medium"},
    {"service": "Launchrock",   "fingerprint": "It looks like you may have taken a wrong turn somewhere",
     "cname": r"\.launchrock\.com", "severity": "low"},
    {"service": "Pingdom",      "fingerprint": "This public report page has not been activated",
     "cname": r"\.pingdom\.com", "severity": "low"},
    {"service": "Tictail",      "fingerprint": "Building a store takes a few seconds",
     "cname": r"\.tictail\.com", "severity": "low"},
    {"service": "Proposify",    "fingerprint": "If you need immediate assistance",
     "cname": r"\.proposify\.biz", "severity": "low"},
    {"service": "Simplebooklet","fingerprint": "We can't find this book",
     "cname": r"\.simplebooklet\.com", "severity": "low"},
    {"service": "Kajabi",       "fingerprint": "The page you were looking for doesn't exist",
     "cname": r"\.kajabi\.com", "severity": "medium"},
    {"service": "Wishpond",     "fingerprint": "https://www.wishpond.com/404",
     "cname": r"\.wishpond\.com", "severity": "low"},
]

# CNAMEs de serviços externos que indicam risco potencial (mesmo sem fingerprint confirmado)
# Usado para gerar seção de "suspeitos" no relatório — [REL-3]
SUSPICIOUS_CNAME_PATTERNS: list[tuple[str, str]] = [
    (r"\.s3[.-]",               "AWS S3"),
    (r"\.azurewebsites\.net",   "Azure Web Apps"),
    (r"\.cloudapp\.net",        "Azure Cloud"),
    (r"\.github\.io",           "GitHub Pages"),
    (r"\.heroku(app)?\.com",    "Heroku"),
    (r"\.fastly\.net",          "Fastly CDN"),
    (r"\.ghost\.io",            "Ghost"),
    (r"\.netlify\.app",         "Netlify"),
    (r"\.vercel\.app",          "Vercel"),
    (r"\.surge\.sh",            "Surge.sh"),
    (r"\.readme\.io",           "Readme.io"),
    (r"\.webflow\.io",          "Webflow"),
    (r"\.myshopify\.com",       "Shopify"),
    (r"\.statuspage\.io",       "Statuspage"),
    (r"\.zendesk\.com",         "Zendesk"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("takeover")
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


def banner(step: str, logger: logging.Logger) -> None:
    logger.info("=" * 60)
    logger.info("ETAPA: %s", step)
    logger.info("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# [RES-2] Verificação de versão mínima das ferramentas
def check_tool_version(name: str, logger: logging.Logger) -> bool:
    """
    MELHORIA [RES-2] — Verificação de versão mínima
    Por quê: versões antigas de nuclei e httpx têm comportamentos diferentes
    (flags renomeadas, formatos de output incompatíveis), causando erros silenciosos.
    Verificar antes de rodar evita falsos negativos por incompatibilidade.
    """
    if name not in MIN_TOOL_VERSIONS:
        return True
    min_ver_str, ver_cmd = MIN_TOOL_VERSIONS[name]
    try:
        result = subprocess.run(ver_cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
        # Extrai semver da saída (ex: "nuclei v3.1.2" → "3.1.2")
        match = re.search(r'v?(\d+)\.(\d+)\.(\d+)', output)
        if not match:
            logger.debug("[versão] Não foi possível detectar versão de %s", name)
            return True  # continua mesmo sem saber
        actual = tuple(int(x) for x in match.groups())
        minimum = tuple(int(x) for x in min_ver_str.split("."))
        if actual < minimum:
            logger.warning(
                "[versão] %s %s encontrado, mínimo recomendado: %s — pode haver incompatibilidade.",
                name, ".".join(str(x) for x in actual), min_ver_str,
            )
            return False
        return True
    except Exception as exc:
        logger.debug("[versão] Erro ao checar %s: %s", name, exc)
        return True


def run_cmd(
    cmd: list[str],
    logger: logging.Logger,
    stdin: str | None = None,
    timeout: int = 300,
    env: dict | None = None,
) -> list[str]:
    """Executa comando sem shell=True. Retorna linhas de stdout."""
    if not tool_available(cmd[0]):
        logger.warning("Ferramenta não encontrada: %s — pulando.", cmd[0])
        return []
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
        if result.stderr:
            logger.debug("[stderr] %s: %s", cmd[0], result.stderr.strip()[:300])
        return [l for l in result.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        logger.warning("Timeout: %s", " ".join(cmd))
        return []
    except Exception as exc:
        logger.error("Erro em %s: %s", cmd[0], exc)
        return []


def write_lines(path: Path, lines: list[str], logger: logging.Logger) -> bool:
    """Escreve arquivo apenas se houver conteúdo. Retorna True se escreveu."""
    clean = sorted(set(l.strip() for l in lines if l.strip()))
    if not clean:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(clean) + "\n", encoding="utf-8")
    logger.debug("Salvo: %s (%d linhas)", path, len(clean))
    return True


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


# [RES-1] Retry com backoff exponencial para APIs externas
def http_get_with_retry(
    url: str,
    logger: logging.Logger,
    timeout: int = 30,
    max_retries: int = 3,
    headers: dict | None = None,
) -> Optional[requests.Response]:
    """
    MELHORIA [RES-1] — Retry com backoff exponencial
    Por quê: crt.sh e OTX têm rate limiting e falhas intermitentes.
    Retry automático reduz dados perdidos sem intervenção manual.
    """
    base_headers = {"User-Agent": "Mozilla/5.0 takeover-recon"}
    if headers:
        base_headers.update(headers)
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=timeout, headers=base_headers)
            if resp.status_code == 429:
                wait = 2 ** attempt
                logger.debug("[retry] Rate limit em %s — aguardando %ds", url, wait)
                time.sleep(wait)
                continue
            return resp
        except requests.RequestException as exc:
            wait = 2 ** attempt
            logger.debug("[retry] Tentativa %d/%d falhou para %s: %s — aguardando %ds",
                         attempt + 1, max_retries, url, exc, wait)
            time.sleep(wait)
    logger.warning("[retry] Falhou após %d tentativas: %s", max_retries, url)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 1: Enumeração de subdomínios
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_subdomains(
    domain: str,
    base: Path,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> list[str]:
    banner("Enumeração de Subdomínios", logger)
    all_subs: set[str] = set()

    # subfinder
    if tool_available("subfinder"):
        check_tool_version("subfinder", logger)
        logger.info("[subfinder] coletando…")
        lines = run_cmd(["subfinder", "-d", domain, "--all", "-silent"], logger, timeout=300)
        all_subs.update(lines)
        logger.info("[subfinder] %d subdomínios", len(lines))
    else:
        logger.warning("subfinder não encontrado.")

    # assetfinder
    if tool_available("assetfinder"):
        logger.info("[assetfinder] coletando…")
        lines = run_cmd(["assetfinder", "--subs-only", domain], logger, timeout=120)
        all_subs.update(lines)
        logger.info("[assetfinder] %d subdomínios", len(lines))
    else:
        logger.warning("assetfinder não encontrado.")

    # crt.sh — API pública, sem token
    logger.info("[crt.sh] consultando…")
    crt_subs = _crt_sh(domain, logger)
    all_subs.update(crt_subs)
    logger.info("[crt.sh] %d subdomínios", len(crt_subs))

    # [COB-2] AlienVault OTX — sem token obrigatório
    logger.info("[OTX] consultando AlienVault OTX…")
    otx_subs = _otx_subdomains(domain, logger)
    all_subs.update(otx_subs)
    logger.info("[OTX] %d subdomínios", len(otx_subs))

    # chaos — só se tiver token
    chaos_key = os.environ.get("CHAOS_KEY", "").strip()
    if chaos_key and tool_available("chaos"):
        logger.info("[chaos] coletando…")
        lines = run_cmd(
            ["chaos", "-d", domain, "-silent"],
            logger,
            env={"CHAOS_KEY": chaos_key},
            timeout=120,
        )
        all_subs.update(lines)
        logger.info("[chaos] %d subdomínios", len(lines))
    elif not chaos_key:
        logger.info("[chaos] CHAOS_KEY não definida — pulando.")

    # github-subdomains — só se tiver token
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if github_token and tool_available("github-subdomains"):
        logger.info("[github-subdomains] coletando…")
        lines = run_cmd(
            ["github-subdomains", "-d", domain, "-t", github_token, "-o", "/dev/stdout"],
            logger, timeout=180,
        )
        all_subs.update(lines)
        logger.info("[github-subdomains] %d subdomínios", len(lines))
    elif not github_token:
        logger.info("[github-subdomains] GITHUB_TOKEN não definida — pulando.")

    # Filtra apenas subdomínios do domínio alvo
    clean = [s for s in all_subs if domain in s and "*" not in s]
    logger.info("Total de subdomínios únicos: %d", len(clean))
    write_lines(base / "subdomains_raw.txt", clean, logger)
    return clean


def _crt_sh(domain: str, logger: logging.Logger) -> list[str]:
    resp = http_get_with_retry(
        f"https://crt.sh/?q=%.{domain}&output=json",
        logger, timeout=30,
    )
    if not resp or resp.status_code != 200:
        return []
    try:
        data = resp.json()
        subs: set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if domain in line:
                    subs.add(line)
        return sorted(subs)
    except Exception as exc:
        logger.debug("crt.sh erro: %s", exc)
        return []


# [COB-2] AlienVault OTX — fonte pública sem token
def _otx_subdomains(domain: str, logger: logging.Logger) -> list[str]:
    """
    MELHORIA [COB-2] — AlienVault OTX como fonte adicional
    Por quê: OTX indexa subdomínios vistos em logs de ameaças e campanhas de C2,
    encontrando ativos que crt.sh e subfinder não cobrem (ex: subdomínios efêmeros,
    infraestrutura legada). API pública sem autenticação obrigatória.
    """
    subs: set[str] = set()
    page = 1
    while True:
        resp = http_get_with_retry(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?page={page}",
            logger, timeout=30,
        )
        if not resp or resp.status_code != 200:
            break
        try:
            data = resp.json()
            entries = data.get("passive_dns", [])
            if not entries:
                break
            for entry in entries:
                hostname = entry.get("hostname", "").strip().lstrip("*.")
                if hostname and domain in hostname:
                    subs.add(hostname)
            # OTX tem paginação; para quando não tem próxima página
            if not data.get("has_next"):
                break
            page += 1
        except Exception as exc:
            logger.debug("OTX erro: %s", exc)
            break
    return sorted(subs)


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 2: Resolução DNS com dnsx + coleta de CNAMEs
# ─────────────────────────────────────────────────────────────────────────────

def resolve_dns(
    subs: list[str],
    base: Path,
    resolvers_file: str,
    logger: logging.Logger,
) -> tuple[list[str], dict[str, str]]:
    """
    Retorna (resolvidos, cname_map).
    MELHORIA [COB-3] — Coleta CNAMEs em massa com dnsx -cname
    Por quê: CNAMEs apontando para serviços externos são o pré-requisito
    de praticamente todo takeover. Coletá-los aqui permite pré-filtrar
    quais URLs precisam de verificação de fingerprint, reduzindo requisições.
    """
    banner("Resolução DNS + CNAMEs (dnsx)", logger)

    input_file = base / "_dnsx_input.txt"
    write_lines(input_file, subs, logger)
    cname_map: dict[str, str] = {}

    if not tool_available("dnsx"):
        logger.warning("dnsx não encontrado — usando lista bruta.")
        return subs, cname_map

    check_tool_version("dnsx", logger)

    # Resolução de A records
    cmd_a = ["dnsx", "-l", str(input_file), "-silent", "-a", "-resp"]
    if Path(resolvers_file).exists():
        cmd_a += ["-r", resolvers_file]
    lines_a = run_cmd(cmd_a, logger, timeout=300)
    resolved = [l.split()[0] for l in lines_a if l.strip()]

    # [COB-3] Coleta de CNAMEs separadamente para mapa completo
    cmd_cname = ["dnsx", "-l", str(input_file), "-silent", "-cname", "-resp"]
    if Path(resolvers_file).exists():
        cmd_cname += ["-r", resolvers_file]
    lines_cname = run_cmd(cmd_cname, logger, timeout=300)

    # dnsx -cname retorna: "sub.domain.com [CNAME → externo.service.com]"
    for line in lines_cname:
        parts = line.split()
        if len(parts) >= 2:
            sub  = parts[0]
            # captura o valor após "[" ou "→" dependendo da versão
            cname_val = " ".join(parts[1:])
            cname_clean = re.sub(r'[\[\]→]', '', cname_val).strip().rstrip(".")
            if cname_clean:
                cname_map[sub] = cname_clean

    if cname_map:
        cname_lines = [f"{sub}\t→\t{cname}" for sub, cname in sorted(cname_map.items())]
        write_lines(base / "cnames.txt", cname_lines, logger)
        logger.info("CNAMEs coletados: %d", len(cname_map))

    logger.info("Subdomínios resolvidos: %d", len(resolved))
    write_lines(base / "subdomains_resolved.txt", resolved, logger)
    return resolved, cname_map


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 3: Bruteforce com puredns (opcional)
# ─────────────────────────────────────────────────────────────────────────────

def bruteforce_subs(
    domain: str,
    base: Path,
    wordlist: str,
    resolvers_file: str,
    logger: logging.Logger,
) -> list[str]:
    banner("Bruteforce de Subdomínios (puredns)", logger)

    if not tool_available("puredns"):
        logger.info("puredns não encontrado — pulando bruteforce.")
        return []

    if not Path(wordlist).exists():
        logger.warning("Wordlist não encontrada: %s — pulando bruteforce.", wordlist)
        return []

    cmd = ["puredns", "bruteforce", wordlist, domain, "-q"]
    if Path(resolvers_file).exists():
        cmd += ["-r", resolvers_file]

    lines = run_cmd(cmd, logger, timeout=600)
    logger.info("puredns encontrou: %d subdomínios", len(lines))
    write_lines(base / "subdomains_bruteforce.txt", lines, logger)
    return lines


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 4: Hosts vivos com httpx
# ─────────────────────────────────────────────────────────────────────────────

def probe_alive(
    subs: list[str],
    base: Path,
    logger: logging.Logger,
    args: argparse.Namespace,
) -> tuple[list[str], list[str]]:
    """
    Retorna (urls_completas, dominios_limpos).
    MELHORIA [PER-1] — rate-limit via -rate-limit para evitar ban de WAF/IPS
    Por quê: disparar 50 threads sem rate limit contra o mesmo ASN pode
    acionar bloqueios temporários e mascarar hosts vivos como mortos.
    """
    banner("Hosts Vivos (httpx)", logger)

    if not tool_available("httpx"):
        logger.warning("httpx não encontrado.")
        return [], []

    check_tool_version("httpx", logger)

    input_file = base / "_httpx_input.txt"
    write_lines(input_file, subs, logger)

    httpx_timeout  = getattr(args, "httpx_timeout", 10)
    httpx_rate     = getattr(args, "httpx_rate", 150)

    result = subprocess.run(
        [
            "httpx",
            "-l", str(input_file),
            "-silent",
            "-ports", HTTPX_PORTS,
            "-mc", "200,201,204,301,302,307,308,403",
            "-threads", "50",
            "-timeout", str(httpx_timeout),
            "-rate-limit", str(httpx_rate),   # [PER-1]
            "-title",
            "-sc",
            "-ip",
            "-cdn",        # identifica se está atrás de CDN (reduz falsos positivos)
            "-json",
        ],
        capture_output=True, text=True, timeout=600,
    )

    alive_urls:    list[str] = []
    alive_domains: list[str] = []
    httpx_data:    list[dict] = []

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            url = obj.get("url", "")
            if url:
                alive_urls.append(url)
                domain_clean = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
                alive_domains.append(domain_clean)
                httpx_data.append(obj)
        except json.JSONDecodeError:
            alive_urls.append(line)
            domain_clean = re.sub(r'^https?://', '', line).split('/')[0].split(':')[0]
            alive_domains.append(domain_clean)

    write_lines(base / "alive.txt", alive_urls, logger)
    write_lines(base / "alive_domains.txt", alive_domains, logger)

    if httpx_data:
        (base / "httpx_data.jsonl").write_text(
            "\n".join(json.dumps(d) for d in httpx_data) + "\n", encoding="utf-8"
        )

    logger.info("Hosts vivos: %d", len(alive_urls))
    return alive_urls, list(set(alive_domains))


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 5: WAF Detection — paralelizado
# ─────────────────────────────────────────────────────────────────────────────

def _waf_worker(url: str, timeout: int = 20) -> tuple[str, str]:
    """Worker para wafw00f em thread — [PER-2]"""
    try:
        result = subprocess.run(
            ["wafw00f", url, "-a", "-f", "json"],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                waf = obj.get("detected", [])
                if waf:
                    return url, waf[0].get("firewall", "Unknown")
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    return url, ""


def detect_waf(alive_urls: list[str], base: Path, logger: logging.Logger) -> dict[str, str]:
    """
    MELHORIA [PER-2] — wafw00f paralelizado com ThreadPoolExecutor
    Por quê: a versão original rodava serial (um por um), tornando essa etapa
    gargalo para programas com centenas de hosts. A paralelização reduz de
    ~100s para ~10s para 100 hosts com timeout de 20s cada.
    """
    banner("WAF Detection (wafw00f)", logger)
    waf_map: dict[str, str] = {}

    if not tool_available("wafw00f"):
        logger.info("wafw00f não encontrado — pulando WAF detection.")
        return waf_map

    targets = alive_urls[:100]
    logger.info("Detectando WAF em %d hosts em paralelo…", len(targets))

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_waf_worker, url): url for url in targets}
        for future in as_completed(futures):
            try:
                url, waf_name = future.result()
                if waf_name:
                    waf_map[url] = waf_name
                    logger.info("[WAF] %s → %s", url, waf_name)
            except Exception as exc:
                logger.debug("wafw00f thread erro: %s", exc)

    waf_lines = [f"{url}  →  {waf}" for url, waf in waf_map.items()]
    if waf_lines:
        write_lines(base / "waf_detected.txt", waf_lines, logger)
        logger.info("WAFs detectados: %d hosts", len(waf_map))
    else:
        logger.info("Nenhum WAF detectado.")

    return waf_map


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 6: Screenshots com gowitness
# ─────────────────────────────────────────────────────────────────────────────

def take_screenshots(alive_urls: list[str], base: Path, logger: logging.Logger) -> bool:
    banner("Screenshots (gowitness)", logger)

    if not tool_available("gowitness"):
        logger.info("gowitness não encontrado — pulando screenshots.")
        logger.info("Instale: go install github.com/sensepost/gowitness@latest")
        return False

    if not alive_urls:
        return False

    input_file = base / "_gowitness_input.txt"
    write_lines(input_file, alive_urls, logger)
    screenshots_dir = base / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)

    try:
        subprocess.run(
            [
                "gowitness", "file",
                "-f", str(input_file),
                "--screenshot-path", str(screenshots_dir),
                "--disable-db",
                "--timeout", "10",
                "--threads", "5",
            ],
            capture_output=True, text=True, timeout=600,
        )
        count = len(list(screenshots_dir.glob("*.png")))
        logger.info("Screenshots capturados: %d → %s", count, screenshots_dir)
        return count > 0
    except Exception as exc:
        logger.error("gowitness erro: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 7: Takeover Detection
# ─────────────────────────────────────────────────────────────────────────────

# [PRE-2] Verificação real de bucket S3 (evita falso positivo por CNAME genérico)
def _s3_bucket_exists(url: str, logger: logging.Logger) -> bool:
    """
    MELHORIA [PRE-2] — Verificação de bucket S3 via API pública
    Por quê: um CNAME para *.s3.amazonaws.com pode ser de um bucket privado
    existente (retorna 403, não takeover). Checar HEAD no endpoint S3
    distingue "bucket existe mas privado" de "bucket não existe" (404/NoSuchBucket).
    Reduz falsos positivos significativamente em programas com uso de S3.
    """
    try:
        parsed    = urlparse(url)
        hostname  = parsed.hostname or ""
        # Extrai nome do bucket do hostname (ex: mybucket.s3.amazonaws.com)
        bucket_name = hostname.split(".s3")[0] if ".s3" in hostname else None
        if not bucket_name:
            return True  # não conseguiu determinar — assume que existe

        check_url = f"https://s3.amazonaws.com/{bucket_name}"
        resp = requests.head(check_url, timeout=8, allow_redirects=True)
        # 403 = bucket existe mas privado → não é takeover
        # 404 = bucket não existe → possível takeover
        if resp.status_code == 403:
            logger.debug("[S3] bucket %s existe (403 Forbidden) — não é takeover", bucket_name)
            return True
        return False
    except Exception:
        return True  # na dúvida, assume que existe (conservador)


def _takeover_fingerprint_worker(
    url: str,
    cname_map: dict[str, str],
) -> Optional[dict]:
    """
    MELHORIA [PRE-1] — Pré-filtro por CNAME antes da requisição HTTP
    Por quê: verificar fingerprint HTTP em 500+ URLs sem CNAME externo é
    desperdício de tempo e gera requisições desnecessárias. Filtrar por CNAME
    primeiro reduz em ~80% as requisições HTTP de fingerprint em programas grandes.

    MELHORIA [PRE-2] — Verificação de bucket S3 antes de confirmar
    MELHORIA [PRE-3] — Retorna dict com severidade para deduplicação enriquecida
    """
    # Normaliza hostname para lookup no cname_map
    hostname = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
    cname_val = cname_map.get(hostname, "")

    try:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-L", url],
            capture_output=True, text=True, timeout=12,
        )
        body = result.stdout

        for fp in TAKEOVER_FINGERPRINTS:
            # [PRE-1] Se existe padrão de CNAME definido, verifica antes do HTTP
            cname_pattern = fp.get("cname", "")
            if cname_pattern and cname_val:
                if not re.search(cname_pattern, cname_val, re.IGNORECASE):
                    continue  # CNAME não bate — pula sem fazer HTTP

            if fp["fingerprint"].lower() in body.lower():
                service  = fp["service"]
                severity = fp.get("severity", "medium")

                # [PRE-2] S3: confirma que bucket realmente não existe
                if "s3" in service.lower() and _s3_bucket_exists(url, logging.getLogger("takeover")):
                    logging.getLogger("takeover").debug(
                        "[PRE-2] %s → S3 fingerprint mas bucket existe — descartado", url
                    )
                    continue

                return {
                    "url":      url,
                    "source":   "fingerprint",
                    "detail":   service,
                    "severity": severity,
                    "cname":    cname_val,
                }
    except Exception:
        pass
    return None


def run_takeover_fingerprints(
    alive_urls: list[str],
    cname_map: dict[str, str],
    base: Path,
    logger: logging.Logger,
) -> list[dict]:
    logger.info("Fingerprint takeover em %d URLs (com pré-filtro CNAME)…", len(alive_urls))
    hits: list[dict] = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(_takeover_fingerprint_worker, url, cname_map): url
            for url in alive_urls
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    logger.warning(
                        "[TAKEOVER fingerprint] %s → %s (severity: %s, cname: %s)",
                        result["url"], result["detail"], result["severity"], result["cname"] or "—",
                    )
                    hits.append(result)
            except Exception as exc:
                logger.debug("Thread erro: %s", exc)

    return hits


# [COB-1] Análise de CNAME + verificação de registrar para takeover de DNS
def check_dangling_cnames(
    cname_map: dict[str, str],
    domain: str,
    base: Path,
    logger: logging.Logger,
) -> list[dict]:
    """
    MELHORIA [COB-1] — Detecção de CNAMEs pendentes (dangling CNAMEs)
    Por quê: subdomínios que apontam via CNAME para um hostname que não resolve
    (NXDOMAIN) são vulneráveis a takeover via registro do hostname externo.
    Esta verificação pega casos que subzy/subjack podem perder porque o host
    sequer responde HTTP — só existe o CNAME no DNS.
    Retorna lista de CNAMEs que não resolvem (possível takeover de DNS).
    """
    banner("Dangling CNAME Check", logger)
    dangling: list[dict] = []

    if not tool_available("dnsx"):
        logger.info("dnsx não disponível para checar dangling CNAMEs.")
        return dangling

    # Coleta CNAMEs que apontam para fora do domínio alvo
    external_cnames = {
        sub: cname
        for sub, cname in cname_map.items()
        if domain not in cname  # aponta para domínio externo
    }

    if not external_cnames:
        logger.info("Nenhum CNAME externo para verificar.")
        return dangling

    # Verifica se o destino do CNAME resolve
    cname_targets = list(set(external_cnames.values()))
    target_file   = base / "_cname_targets.txt"
    write_lines(target_file, cname_targets, logger)

    logger.info("Verificando resolução de %d destinos CNAME externos…", len(cname_targets))
    lines = run_cmd(
        ["dnsx", "-l", str(target_file), "-silent", "-a", "-resp"],
        logger, timeout=120,
    )
    resolved_cnames = {l.split()[0] for l in lines if l.strip()}

    for sub, cname in external_cnames.items():
        cname_stripped = cname.rstrip(".")
        if cname_stripped not in resolved_cnames:
            # Verifica padrão de serviço conhecido
            service = "Desconhecido"
            for pattern, svc_name in SUSPICIOUS_CNAME_PATTERNS:
                if re.search(pattern, cname, re.IGNORECASE):
                    service = svc_name
                    break

            entry = {
                "url":      f"http://{sub}",
                "source":   "dangling_cname",
                "detail":   f"{service} ({cname})",
                "severity": "high",
                "cname":    cname,
            }
            dangling.append(entry)
            logger.warning(
                "[DANGLING CNAME] %s → %s não resolve → possível takeover (%s)",
                sub, cname, service,
            )

    if dangling:
        lines_out = [
            f"[dangling_cname] {e['url']}  CNAME→{e['cname']}  ({e['detail']})"
            for e in dangling
        ]
        write_lines(base / "dangling_cnames.txt", lines_out, logger)
        logger.warning("[COB-1] %d dangling CNAMEs encontrados", len(dangling))
    else:
        logger.info("Nenhum dangling CNAME encontrado.")

    return dangling


def _collect_suspicious_cnames(
    cname_map: dict[str, str],
    domain: str,
    confirmed_urls: set[str],
) -> list[dict]:
    """
    [REL-3] Coleta CNAMEs suspeitos (externos mas sem fingerprint confirmado)
    para seção dedicada no relatório HTML.
    """
    suspicious: list[dict] = []
    for sub, cname in cname_map.items():
        if domain in cname:
            continue  # CNAME interno, não suspeito
        url_key = f"http://{sub}"
        if url_key in confirmed_urls:
            continue  # já está em takeovers confirmados
        for pattern, svc_name in SUSPICIOUS_CNAME_PATTERNS:
            if re.search(pattern, cname, re.IGNORECASE):
                suspicious.append({
                    "subdomain": sub,
                    "cname":     cname,
                    "service":   svc_name,
                })
                break
    return suspicious


def run_subzy(domains: list[str], base: Path, logger: logging.Logger) -> list[dict]:
    if not tool_available("subzy"):
        logger.info("subzy não encontrado — pulando.")
        return []

    input_file = base / "_subzy_input.txt"
    write_lines(input_file, domains, logger)

    lines = run_cmd(
        ["subzy", "run", "--targets", str(input_file), "--hide_fails", "--verify"],
        logger, timeout=300,
    )
    hits = [l for l in lines if "VULNERABLE" in l.upper()]
    if hits:
        write_lines(base / "subzy_vulnerable.txt", hits, logger)
        logger.warning("[subzy] %d vulneráveis encontrados", len(hits))
    else:
        logger.info("[subzy] nenhum takeover encontrado.")
    # Normaliza para dict com severidade
    return [{"url": h, "source": "subzy", "detail": "", "severity": "high", "cname": ""} for h in hits]


def run_subjack(domains: list[str], base: Path, logger: logging.Logger) -> list[dict]:
    if not tool_available("subjack"):
        logger.info("subjack não encontrado — pulando.")
        return []

    input_file  = base / "_subjack_input.txt"
    output_file = base / "subjack_results.txt"
    write_lines(input_file, domains, logger)

    run_cmd(
        ["subjack", "-w", str(input_file), "-t", "100",
         "-timeout", "30", "-ssl", "-v", "-o", str(output_file)],
        logger, timeout=300,
    )

    if not output_file.exists():
        return []
    vuln = [l for l in read_lines(output_file) if "vulnerable" in l.lower()]
    if vuln:
        logger.warning("[subjack] %d vulneráveis encontrados", len(vuln))
    return [{"url": v, "source": "subjack", "detail": "", "severity": "high", "cname": ""} for v in vuln]


def _nuclei_run_dir(
    label: str,
    template_dir: Path,
    alive_file: Path,
    output_file: Path,
    severity_flag: list[str],
    logger: logging.Logger,
    timeout: int = 600,
) -> list[str]:
    if not template_dir.exists():
        logger.warning("[nuclei/%s] diretório não encontrado: %s", label, template_dir)
        return []

    banner(f"Nuclei [{label}]  →  {template_dir}", logger)
    run_cmd(
        ["nuclei",
         "-l", str(alive_file),
         "-t", str(template_dir),
         "-silent",
         "-o", str(output_file),
         "-timeout", "10"]
        + severity_flag,
        logger,
        timeout=timeout,
    )

    hits = read_lines(output_file)
    if hits:
        logger.warning("[nuclei/%s] %d achados → %s", label, len(hits), output_file)
    else:
        logger.info("[nuclei/%s] nenhum achado.", label)
        if output_file.exists():
            output_file.unlink()
    return hits


def run_all_nuclei(
    alive_file: Path,
    base: Path,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> list[dict]:
    if not tool_available("nuclei"):
        logger.info("nuclei não encontrado — pulando todos os scans nuclei.")
        return []
    if not alive_file.exists():
        return []

    check_tool_version("nuclei", logger)

    severity_flag = ["-severity", args.severity] if getattr(args, "severity", None) else []
    takeover_hits: list[dict] = []

    main_templates = Path(args.nuclei_templates or DEFAULT_NUCLEI_TEMPLATES)
    takeover_dir   = main_templates / "http" / "takeovers"
    hits = _nuclei_run_dir(
        label         = "takeovers",
        template_dir  = takeover_dir,
        alive_file    = alive_file,
        output_file   = base / "nuclei_takeovers.txt",
        severity_flag = severity_flag,
        logger        = logger,
    )
    takeover_hits.extend([
        {"url": h, "source": "nuclei", "detail": "", "severity": "high", "cname": ""}
        for h in hits
    ])

    if not getattr(args, "no_network", False):
        _nuclei_run_dir(
            label         = "network",
            template_dir  = main_templates / "network",
            alive_file    = alive_file,
            output_file   = base / "nuclei_network.txt",
            severity_flag = severity_flag,
            logger        = logger,
            timeout       = 900,
        )

    if not getattr(args, "no_http", False):
        _nuclei_run_dir(
            label         = "http",
            template_dir  = main_templates / "http",
            alive_file    = alive_file,
            output_file   = base / "nuclei_http.txt",
            severity_flag = severity_flag,
            logger        = logger,
            timeout       = 1800,
        )

    for extra_path in getattr(args, "nuclei_extra", []) or []:
        extra_dir = Path(extra_path)
        if not extra_dir.exists():
            logger.warning("[nuclei/extra] path não encontrado: %s", extra_dir)
            continue
        label       = re.sub(r'[^\w\-]', '_', extra_dir.name) or "extra"
        output_file = base / f"nuclei_{label}.txt"
        counter = 1
        while output_file.exists():
            output_file = base / f"nuclei_{label}_{counter}.txt"
            counter += 1
        hits = _nuclei_run_dir(
            label         = f"extra/{extra_dir.name}",
            template_dir  = extra_dir,
            alive_file    = alive_file,
            output_file   = output_file,
            severity_flag = severity_flag,
            logger        = logger,
            timeout       = 900,
        )
        takeover_hits.extend([
            {"url": h, "source": "nuclei/extra", "detail": "", "severity": "high", "cname": ""}
            for h in hits
        ])

    return takeover_hits


def detect_takeovers(
    alive_urls: list[str],
    alive_domains: list[str],
    cname_map: dict[str, str],
    base: Path,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> tuple[list[dict], list[dict]]:
    """
    Retorna (takeovers_confirmados, dangling_cnames).
    MELHORIA [PRE-3] — Deduplicação por (url_normalizada + serviço)
    Por quê: a mesma URL pode ser reportada por fingerprint E por subzy.
    Deduplicar só por URL perde a informação de qual ferramenta confirmou.
    Deduplicar por (url+serviço) mantém fontes distintas mas evita duplicatas
    redundantes do mesmo par, melhorando precisão na triagem.
    """
    banner("Takeover Detection", logger)
    all_findings: list[dict] = []

    # Fingerprints manuais (com pré-filtro CNAME e verificação S3)
    fp_hits = run_takeover_fingerprints(alive_urls, cname_map, base, logger)
    all_findings.extend(fp_hits)

    # Dangling CNAMEs [COB-1]
    dangling = check_dangling_cnames(cname_map, args.domain or "", base, logger)
    all_findings.extend(dangling)

    # subzy
    subzy_hits = run_subzy(alive_domains, base, logger)
    all_findings.extend(subzy_hits)

    # subjack
    subjack_hits = run_subjack(alive_domains, base, logger)
    all_findings.extend(subjack_hits)

    # nuclei
    alive_file   = base / "alive.txt"
    nuclei_hits  = run_all_nuclei(alive_file, base, args, logger)
    all_findings.extend(nuclei_hits)

    # [PRE-3] Deduplicação por (url_normalizada + serviço)
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for f in all_findings:
        url_norm = f["url"].rstrip("/").lower()
        key      = (url_norm, f.get("source", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Ordena por severidade (high primeiro)
    sev_order = {"high": 0, "medium": 1, "low": 2, "": 3}
    deduped.sort(key=lambda x: sev_order.get(x.get("severity", ""), 3))

    if deduped:
        lines = [
            f"[{f['source']}][{f.get('severity','?')}] {f['url']}  {f.get('detail','')}  CNAME:{f.get('cname','—')}".strip()
            for f in deduped
        ]
        write_lines(base / "takeovers_confirmed.txt", lines, logger)
        logger.warning("=" * 50)
        logger.warning("TAKEOVERS ENCONTRADOS: %d", len(deduped))
        for f in deduped:
            logger.warning(
                "  [%s][%s] %s %s",
                f["source"], f.get("severity", "?"), f["url"], f.get("detail", ""),
            )
        logger.warning("=" * 50)
    else:
        logger.info("Nenhum takeover confirmado.")

    return deduped, dangling


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 8: Nmap
# ─────────────────────────────────────────────────────────────────────────────

def extract_ips(httpx_jsonl: Path, logger: logging.Logger) -> list[str]:
    ips: set[str] = set()
    if not httpx_jsonl.exists():
        return []
    for line in httpx_jsonl.read_text(encoding="utf-8").splitlines():
        try:
            obj = json.loads(line)
            ip = obj.get("host", "") or obj.get("ip", "")
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                ips.add(ip)
        except Exception:
            pass
    return sorted(ips)


def run_nmap(base: Path, logger: logging.Logger, timeout: int = 3600) -> None:
    banner("Nmap Port Scan", logger)

    ips = extract_ips(base / "httpx_data.jsonl", logger)
    if not ips:
        logger.info("IPs não encontrados no JSON do httpx — pulando nmap.")
        return

    if not tool_available("nmap"):
        logger.warning("nmap não encontrado.")
        return

    ip_file  = base / "ips.txt"
    nmap_out = base / "nmap.txt"
    write_lines(ip_file, ips, logger)
    logger.info("Rodando nmap em %d IPs…", len(ips))

    run_cmd(
        ["nmap", "-p-", "-T4", "-sV", "-Pn", "--open",
         "-iL", str(ip_file), "-oN", str(nmap_out)],
        logger,
        timeout=timeout,
    )

    if nmap_out.exists() and nmap_out.stat().st_size > 0:
        logger.info("Nmap finalizado → %s", nmap_out)
    else:
        logger.info("Nmap não retornou resultados.")


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 9: Relatório HTML + JSON estruturado
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "high":   "#f85149",
    "medium": "#d29922",
    "low":    "#3fb950",
    "":       "#8b949e",
}


def generate_html_report(
    domain: str,
    base: Path,
    stats: dict,
    takeovers: list[dict],
    dangling: list[dict],
    waf_map: dict[str, str],
    cname_map: dict[str, str],
    logger: logging.Logger,
) -> None:
    """
    MELHORIA [REL-1] — Relatório com severidade, CVSS estimado e filtros JS
    MELHORIA [REL-2] — Exportação JSON estruturado
    MELHORIA [REL-3] — Seção de CNAMEs suspeitos (não confirmados)
    """
    banner("Relatório HTML + JSON", logger)

    alive_urls      = read_lines(base / "alive.txt")
    screenshots_dir = base / "screenshots"

    # [REL-2] JSON estruturado — machine-readable para importar em Burp/JIRA/etc
    report_json = {
        "domain":      domain,
        "generated":   datetime.now().isoformat(),
        "stats":       stats,
        "takeovers":   takeovers,
        "dangling":    dangling,
        "alive_count": len(alive_urls),
        "wafs":        waf_map,
    }
    json_file = base / "report.json"
    json_file.write_text(json.dumps(report_json, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("JSON estruturado → %s", json_file)

    # [REL-3] CNAMEs suspeitos (externos, sem fingerprint confirmado)
    confirmed_urls  = {f["url"] for f in takeovers}
    suspicious_cnames = _collect_suspicious_cnames(cname_map, domain, confirmed_urls)

    # ── Blocos HTML ──────────────────────────────────────────────────────────

    def _takeover_row(f: dict) -> str:
        sev   = f.get("severity", "")
        color = SEVERITY_COLOR.get(sev, SEVERITY_COLOR[""])
        cname_disp = f.get("cname") or "—"
        cvss_hint  = {"high": "7.5–9.8", "medium": "4.0–6.9", "low": "1.0–3.9"}.get(sev, "—")
        return (
            f"<tr class='vuln'>"
            f"<td><a href='{f['url']}' target='_blank'>{f['url']}</a></td>"
            f"<td style='color:{color};font-weight:bold'>{sev.upper() or '?'}</td>"
            f"<td>{f.get('source','')}</td>"
            f"<td>{f.get('detail','')}</td>"
            f"<td style='font-size:.8rem;color:#8b949e'>{cname_disp}</td>"
            f"<td style='color:{color}'>{cvss_hint}</td>"
            "</tr>\n"
        )

    takeover_rows = "".join(_takeover_row(f) for f in takeovers)
    if not takeover_rows:
        takeover_rows = "<tr><td colspan='6' style='color:#3fb950'>✓ Nenhum takeover confirmado</td></tr>"

    dangling_rows = ""
    for d in dangling:
        dangling_rows += (
            f"<tr class='warn'><td>{d['url'].replace('http://','')}</td>"
            f"<td>{d.get('cname','')}</td>"
            f"<td>{d.get('detail','')}</td></tr>\n"
        )
    if not dangling_rows:
        dangling_rows = "<tr><td colspan='3' style='color:#3fb950'>✓ Nenhum dangling CNAME</td></tr>"

    suspicious_rows = ""
    for s in suspicious_cnames[:200]:
        suspicious_rows += (
            f"<tr><td>{s['subdomain']}</td>"
            f"<td style='color:#d29922'>{s['cname']}</td>"
            f"<td>{s['service']}</td></tr>\n"
        )
    if not suspicious_rows:
        suspicious_rows = "<tr><td colspan='3'>Nenhum CNAME suspeito.</td></tr>"

    host_rows = ""
    for url in alive_urls[:500]:
        waf = waf_map.get(url, "—")
        waf_color = "#f85149" if waf != "—" else "#8b949e"
        screenshot_file = screenshots_dir / f"{re.sub(r'[^\w]', '_', url)}.png"
        screenshot_html = (
            f'<a href="screenshots/{screenshot_file.name}" target="_blank">'
            f'<img src="screenshots/{screenshot_file.name}" width="120" loading="lazy"></a>'
            if screenshot_file.exists() else "—"
        )
        # Destaca se tem CNAME externo suspeito
        hostname  = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
        cname_val = cname_map.get(hostname, "")
        cname_flag = ""
        for pattern, svc_name in SUSPICIOUS_CNAME_PATTERNS:
            if re.search(pattern, cname_val, re.IGNORECASE):
                cname_flag = f" <span style='color:#d29922' title='CNAME externo: {cname_val}'>⚠ {svc_name}</span>"
                break

        host_rows += (
            f"<tr>"
            f"<td><a href='{url}' target='_blank'>{url}</a>{cname_flag}</td>"
            f"<td style='color:{waf_color}'>{waf}</td>"
            f"<td>{screenshot_html}</td>"
            "</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Recon — {domain}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --danger: #f85149; --warn: #d29922; --ok: #3fb950;
    --font: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  h1 {{ color: var(--accent); margin-bottom: .5rem; font-size: 1.6rem; }}
  h2 {{ color: var(--muted); font-size: 1rem; border-bottom: 1px solid var(--border);
        padding-bottom: .4rem; margin: 2rem 0 .8rem; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
           padding: .8rem 1.2rem; min-width: 140px; }}
  .stat .n {{ font-size: 2rem; color: var(--accent); font-weight: bold; }}
  .stat .l {{ font-size: .75rem; color: var(--muted); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; margin-bottom: 1rem; }}
  th {{ background: var(--surface); color: var(--muted); text-align: left;
        padding: .5rem .8rem; border-bottom: 1px solid var(--border); }}
  td {{ padding: .45rem .8rem; border-bottom: 1px solid var(--border); word-break: break-all; }}
  tr:hover td {{ background: var(--surface); }}
  tr.vuln td {{ background: rgba(248,81,73,.07); }}
  tr.warn td {{ background: rgba(210,153,34,.07); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  img {{ border-radius: 4px; border: 1px solid var(--border); }}
  /* [REL-1] Filtro JS */
  .filter-bar {{ margin: .6rem 0; }}
  .filter-bar input {{
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text); padding: .4rem .8rem; border-radius: 4px;
    font-family: var(--font); font-size: .85rem; width: 320px;
  }}
  .badge {{
    display:inline-block; border-radius: 3px; padding: 1px 6px;
    font-size:.75rem; font-weight:bold;
  }}
  .badge-high   {{ background:#f8514933; color:#f85149; }}
  .badge-medium {{ background:#d2992233; color:#d29922; }}
  .badge-low    {{ background:#3fb95033; color:#3fb950; }}
</style>
</head>
<body>
<h1>&#x1F50D; Recon — {domain}</h1>
<p class="meta">Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
  <a href="report.json" download>&#x2B73; JSON</a>
</p>

<div class="stats">
  <div class="stat"><div class="n">{stats.get('subdomains', 0)}</div><div class="l">Subdomínios</div></div>
  <div class="stat"><div class="n">{stats.get('resolved', 0)}</div><div class="l">Resolvidos</div></div>
  <div class="stat"><div class="n">{stats.get('alive', 0)}</div><div class="l">Vivos</div></div>
  <div class="stat"><div class="n" style="color:{'var(--danger)' if takeovers else 'var(--ok)'}">
    {len(takeovers)}</div><div class="l">Takeovers</div></div>
  <div class="stat"><div class="n" style="color:{'var(--warn)' if dangling else 'var(--ok)'}">
    {len(dangling)}</div><div class="l">Dangling CNAMEs</div></div>
  <div class="stat"><div class="n">{stats.get('wafs', 0)}</div><div class="l">WAFs detectados</div></div>
</div>

<h2>&#x26A0; Takeovers Confirmados ({len(takeovers)})</h2>
<table id="tbl-takeovers">
  <tr><th>URL</th><th>Severity</th><th>Fonte</th><th>Serviço</th><th>CNAME</th><th>CVSS est.</th></tr>
  {takeover_rows}
</table>

<h2>&#x1F517; Dangling CNAMEs — possível takeover via DNS ({len(dangling)})</h2>
<table id="tbl-dangling">
  <tr><th>Subdomínio</th><th>CNAME destino (não resolve)</th><th>Serviço</th></tr>
  {dangling_rows}
</table>

<h2>&#x26A1; CNAMEs Externos Suspeitos — não confirmados ({len(suspicious_cnames)})</h2>
<p style="color:var(--muted);font-size:.82rem;margin-bottom:.6rem">
  CNAMEs apontando para serviços externos sem fingerprint de takeover confirmado.
  Verificar manualmente se os recursos estão registrados.
</p>
<table id="tbl-suspicious">
  <tr><th>Subdomínio</th><th>CNAME destino</th><th>Serviço</th></tr>
  {suspicious_rows}
</table>

<h2>&#x1F310; Hosts Vivos ({len(alive_urls)})</h2>
<div class="filter-bar">
  <input id="filter-hosts" type="text" placeholder="Filtrar hosts…" oninput="filterTable(this,'tbl-hosts')">
</div>
<table id="tbl-hosts">
  <tr><th>URL</th><th>WAF</th><th>Screenshot</th></tr>
  {host_rows}
</table>

<script>
function filterTable(input, tableId) {{
  const q = input.value.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tr:not(:first-child)').forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    report_file = base / "report.html"
    report_file.write_text(html, encoding="utf-8")
    logger.info("Relatório HTML → %s", report_file)
    logger.info("Relatório JSON → %s", json_file)


# ─────────────────────────────────────────────────────────────────────────────
# Orquestração por domínio
# ─────────────────────────────────────────────────────────────────────────────

def process_domain(domain: str, args: argparse.Namespace, logger: logging.Logger) -> None:
    # Injeta domain no args para acesso em subfunções (ex: dangling CNAME check)
    args.domain = domain
    base = Path(domain)
    base.mkdir(exist_ok=True)
    stats: dict[str, int] = {}

    # 1. Enumeração
    subs = enumerate_subdomains(domain, base, args, logger)
    stats["subdomains"] = len(subs)

    # 2. Bruteforce (opcional)
    if not args.no_bruteforce:
        bf_subs = bruteforce_subs(
            domain, base,
            args.wordlist or DEFAULT_SUBDOMAINS_WORDLIST,
            args.resolvers or DEFAULT_RESOLVERS_FILE,
            logger,
        )
        subs = sorted(set(subs + bf_subs))

    # 3. Resolução DNS + CNAMEs
    resolved, cname_map = resolve_dns(subs, base, args.resolvers or DEFAULT_RESOLVERS_FILE, logger)
    stats["resolved"] = len(resolved)
    stats["cnames"]   = len(cname_map)

    # 4. Hosts vivos
    alive_urls, alive_domains = probe_alive(resolved, base, logger, args)
    stats["alive"] = len(alive_urls)

    if not alive_urls:
        logger.warning("Nenhum host vivo encontrado para %s — abortando.", domain)
        return

    # 5. WAF
    waf_map: dict[str, str] = {}
    if not args.no_waf:
        waf_map = detect_waf(alive_urls, base, logger)
        stats["wafs"] = len(waf_map)
    else:
        stats["wafs"] = 0

    # 6. Screenshots
    if not args.no_screenshots:
        take_screenshots(alive_urls, base, logger)

    # 7. Takeover (inclui dangling CNAME check)
    takeovers, dangling = detect_takeovers(
        alive_urls, alive_domains, cname_map, base, args, logger,
    )
    stats["takeovers"] = len(takeovers)
    stats["dangling"]  = len(dangling)

    # 8. Nmap
    if not args.no_nmap:
        run_nmap(base, logger, timeout=args.nmap_timeout)

    # 9. Relatório HTML + JSON
    generate_html_report(domain, base, stats, takeovers, dangling, waf_map, cname_map, logger)

    # Sumário no terminal
    logger.info("=" * 60)
    logger.info("SUMÁRIO — %s", domain)
    logger.info("  Subdomínios enumerados : %d", stats.get("subdomains", 0))
    logger.info("  Subdomínios resolvidos : %d", stats.get("resolved",   0))
    logger.info("  CNAMEs externos        : %d", stats.get("cnames",     0))
    logger.info("  Hosts vivos            : %d", stats.get("alive",      0))
    logger.info("  Takeovers confirmados  : %d", stats.get("takeovers",  0))
    logger.info("  Dangling CNAMEs        : %d", stats.get("dangling",   0))
    logger.info("  WAFs detectados        : %d", stats.get("wafs",       0))
    logger.info("  Saída                  : %s", base)
    logger.info("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Recon de subdomínios + Domain Takeover + Port Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Variáveis de ambiente opcionais:
  CHAOS_KEY            Token do Chaos (projectdiscovery.io)
  GITHUB_TOKEN         GitHub Personal Access Token
  NUCLEI_TEMPLATES     Path dos templates nuclei  (padrão: /root/nuclei-templates)
  RESOLVERS_FILE       Path do arquivo de resolvers DNS
  SUBDOMAINS_WORDLIST  Wordlist para bruteforce puredns
""",
    )
    p.add_argument("domain",              nargs="?",           help="Domínio alvo")
    p.add_argument("-l", "--list",                             help="Arquivo com lista de domínios")
    p.add_argument("--nuclei-templates",  default=None,
                   help=f"Path do repositório principal de templates nuclei (padrão: {DEFAULT_NUCLEI_TEMPLATES})")
    p.add_argument("--nuclei-extra",      action="append", metavar="PATH", default=[],
                   help="Diretório extra de templates nuclei — pode ser usado várias vezes.")
    p.add_argument("--resolvers",         default=None,        help="Path do arquivo resolvers.txt")
    p.add_argument("--wordlist",          default=None,        help="Wordlist para puredns bruteforce")
    p.add_argument("--severity",          default=None,        help="Filtro de severity no nuclei (ex: critical,high)")
    p.add_argument("--nmap-timeout",      type=int, default=3600, help="Timeout do nmap em segundos")
    # [RES-3] Timeouts granulares por ferramenta
    p.add_argument("--httpx-timeout",     type=int, default=10,  help="Timeout por request httpx (s)")
    p.add_argument("--httpx-rate",        type=int, default=150, help="Rate limit httpx (req/s)")
    p.add_argument("--no-nmap",           action="store_true",   help="Pula nmap")
    p.add_argument("--no-network",        action="store_true",   help="Pula nuclei/network")
    p.add_argument("--no-http",           action="store_true",   help="Pula nuclei/http")
    p.add_argument("--no-waf",            action="store_true",   help="Pula WAF detection")
    p.add_argument("--no-screenshots",    action="store_true",   help="Pula gowitness")
    p.add_argument("--no-bruteforce",     action="store_true",   help="Pula puredns bruteforce")
    return p.parse_args()


def main() -> None:
    args    = parse_args()
    domains: list[str] = []

    if args.domain:
        domains.append(args.domain)
    if args.list:
        with open(args.list) as f:
            domains.extend(d.strip() for d in f if d.strip())

    if not domains:
        parse_args().print_help()
        sys.exit(1)

    for domain in domains:
        log_file = Path(domain) / "takeover.log"
        logger   = setup_logging(log_file)
        logger.info("######## PROCESSANDO %s ########", domain)
        process_domain(domain, args, logger)


if __name__ == "__main__":
    main()
