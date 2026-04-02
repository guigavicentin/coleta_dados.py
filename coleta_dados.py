import os
import re
import json
import time
import socket
import tarfile
import zipfile
import hashlib
import subprocess
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ========= CONFIG =========
dominio = input("Informe o dominio (ex: exemplo.com): ").strip().lower()

BASE_DIR = Path(f"coleta_{dominio}")
DOWNLOAD_DIR = BASE_DIR / "downloads"
SENSITIVE_DIR = BASE_DIR / "possivelmente_sensiveis"
EXTRACT_DIR = BASE_DIR / "extraidos"
REPORT_TXT = BASE_DIR / f"relatorio_{dominio}.txt"
REPORT_JSON = BASE_DIR / f"relatorio_{dominio}.json"
URLS_FILE = BASE_DIR / f"urls_{dominio}.txt"

for pasta in [BASE_DIR, DOWNLOAD_DIR, SENSITIVE_DIR, EXTRACT_DIR]:
    pasta.mkdir(parents=True, exist_ok=True)

EXTENSOES_INTERESSE = (
    ".js", ".json", ".map", ".env", ".log", ".bak", ".old", ".zip", ".tar", ".gz",
    ".tgz", ".7z", ".rar", ".conf", ".config", ".ini", ".yaml", ".yml", ".sql",
    ".xml", ".txt", ".pdf", ".doc", ".docx", ".csv", ".pem", ".key", ".crt",
    ".pfx", ".p12", ".db", ".sqlite", ".sqlite3", ".backup", ".swp"
)

EXTENSOES_SENSIVEIS = (
    ".env", ".bak", ".old", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".sql",
    ".pem", ".key", ".pfx", ".p12", ".db", ".sqlite", ".sqlite3", ".backup",
    ".config", ".ini", ".yaml", ".yml", ".conf"
)

EXTENSOES_CRITICAS_POR_SI = (
    ".env", ".sql", ".pem", ".key", ".pfx", ".p12", ".db", ".sqlite", ".sqlite3"
)

MAX_DOWNLOAD_SIZE = 30 * 1024 * 1024  # 30 MB
TIMEOUT_DOWNLOAD = 60
RETRY_DOWNLOAD = 3

PATTERNS = {
    "JWT": {
        "regex": r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b",
        "severity": "high",
    },
    "AWS Access Key": {
        "regex": r"\bAKIA[0-9A-Z]{16}\b",
        "severity": "critical",
    },
    "Google API Key": {
        "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "severity": "high",
    },
    "Stripe Live Key": {
        "regex": r"\bsk_live_[0-9a-zA-Z]{16,}\b",
        "severity": "critical",
    },
    "Bearer Token": {
        "regex": r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b",
        "severity": "high",
    },
    "Basic Auth": {
        "regex": r"\bBasic\s+[A-Za-z0-9+/=]{8,}\b",
        "severity": "medium",
    },
    "Private Key": {
        "regex": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)? ?PRIVATE KEY-----",
        "severity": "critical",
    },
    "Certificate": {
        "regex": r"-----BEGIN CERTIFICATE-----",
        "severity": "medium",
    },
    "Slack Token": {
        "regex": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "severity": "critical",
    },
    "GitHub Token": {
        "regex": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        "severity": "critical",
    },
    "Password Assignment": {
        "regex": r"""(?ix)
        \b(
            password|passwd|pwd|senha|
            db_password|database_password|
            secret_key|client_secret|api_key|
            aws_secret_access_key
        )\b
        \s*[:=]\s*
        ['"]
        (?=.*[A-Za-z])(?=.*\d)[^'"\n]{8,}
        ['"]
        """,
        "severity": "high",
    },
    "Hardcoded Token": {
        "regex": r"""(?ix)
        \b(
            access_token|auth_token|refresh_token|
            bearer_token|jwt_token|token_value
        )\b
        \s*[:=]\s*
        ['"][A-Za-z0-9._\-+=/]{12,}['"]
        """,
        "severity": "high",
    },
    "Hardcoded Secret": {
        "regex": r"""(?ix)
        \b(
            api[_-]?key|client[_-]?secret|secret[_-]?key
        )\b
        \s*[:=]\s*
        ['"][A-Za-z0-9\-_=+/]{10,}['"]
        """,
        "severity": "high",
    },
    "Env File Secret": {
        "regex": r"""(?im)^(DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|TOKEN|ACCESS_TOKEN)\s*=\s*.+$""",
        "severity": "critical",
    },
    "Connection String": {
        "regex": r"""(?i)\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|mssql):\/\/[^\s"']+""",
        "severity": "critical",
    },
    "Email": {
        "regex": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "low",
    },
    "Internal URL": {
        "regex": r"""https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|169\.254\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|localhost)(?::\d+)?[^\s"']*""",
        "severity": "medium",
    },
    "Debug Artifact": {
        "regex": r"(?i)\b(console\.log|debugger|window\.debug)\b",
        "severity": "low",
    },
    "Role / Admin Reference": {
        "regex": r"(?i)\b(admin|superadmin|super admin|impersonate|role_impersonate|isAdmin|isSuperAdmin)\b",
        "severity": "medium",
    },
    "Sentry DSN": {
        "regex": r"https://[a-zA-Z0-9]+@[a-zA-Z0-9.-]+\.ingest\.sentry\.io/\d+",
        "severity": "low",
    },
}

KEYWORDS_JS_RELEVANTES = [
    "Authorization",
    "Bearer ",
    "Basic ",
    "accessToken",
    "refreshToken",
    "idToken",
    "authToken",
    "apiKey",
    "clientSecret",
    "secretKey",
    "privateKey",
    "document.cookie",
    "localStorage.setItem",
    "sessionStorage.setItem",
    "localStorage.getItem",
    "sessionStorage.getItem",
    "axios.",
    "$.ajax",
    "setRequestHeader",
    "impersonate",
    "role_impersonate",
    "isAdmin",
    "isSuperAdmin",
    "permission",
    "scope",
    "/admin",
    "/auth/",
    "/graphql",
]

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ROBOTS_STATUS_INTERESSANTES = {"200", "204", "301", "302", "401", "403"}


def aviso_pip(pacote: str) -> None:
    print(f"\n[!] Biblioteca opcional ausente: {pacote}")
    print("[!] Instale com:")
    print(f"    pip install {pacote}")
    print("[!] Caso o sistema bloqueie instalação gerenciada, tente:")
    print(f"    pip install {pacote} --break-system-packages")
    print("[!] Alternativa recomendada:")
    print("    python3 -m venv venv")
    print("    source venv/bin/activate")
    print(f"    pip install {pacote}\n")


def is_interesting_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        return path.endswith(EXTENSOES_INTERESSE) or path.endswith("/robots.txt") or path == "/robots.txt"
    except Exception:
        return False


def unique_filename(url: str) -> str:
    parsed = urlparse(url)
    base = os.path.basename(parsed.path) or "sem_nome"
    digest = hashlib.md5(url.encode()).hexdigest()[:10]

    if parsed.path.lower().endswith("/robots.txt") or parsed.path.lower() == "/robots.txt":
        base = "robots.txt"

    return f"{digest}_{base}"


def collect_urls(domain: str) -> set[str]:
    print("[+] Coletando URLs com gau e waybackurls...")
    urls = set()

    try:
        gau = subprocess.run(
            ["gau", domain],
            capture_output=True,
            text=True
        )
        for line in gau.stdout.splitlines():
            line = line.strip()
            if line and is_interesting_url(line):
                urls.add(line)
    except Exception as e:
        print(f"[!] Erro ao executar gau: {e}")

    try:
        wayback = subprocess.run(
            ["waybackurls"],
            input=domain,
            capture_output=True,
            text=True
        )
        for line in wayback.stdout.splitlines():
            line = line.strip()
            if line and is_interesting_url(line):
                urls.add(line)
    except Exception as e:
        print(f"[!] Erro ao executar waybackurls: {e}")

    return urls


def should_go_to_sensitive(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(EXTENSOES_SENSIVEIS)


def is_critical_extension(path: Path) -> bool:
    return path.name.lower().endswith(EXTENSOES_CRITICAS_POR_SI)


def is_robots_file(path: Path) -> bool:
    return path.name.lower().endswith("robots.txt")


def download_file(url: str, dest: Path) -> bool:
    headers = {"User-Agent": "Mozilla/5.0"}
    req = Request(url, headers=headers)

    for tentativa in range(1, RETRY_DOWNLOAD + 1):
        try:
            with urlopen(req, timeout=TIMEOUT_DOWNLOAD) as response:
                status = getattr(response, "status", 200)
                if status >= 400:
                    print(f"[!] HTTP {status} ao baixar {url}")
                    return False

                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > MAX_DOWNLOAD_SIZE:
                            print(f"[!] Ignorado por tamanho > {MAX_DOWNLOAD_SIZE // (1024 * 1024)}MB: {url}")
                            return False
                    except ValueError:
                        pass

                data = response.read(MAX_DOWNLOAD_SIZE + 1)
                if len(data) > MAX_DOWNLOAD_SIZE:
                    print(f"[!] Ignorado por tamanho > {MAX_DOWNLOAD_SIZE // (1024 * 1024)}MB: {url}")
                    return False

                dest.write_bytes(data)
                print(f"[+] Baixado: {url}")
                return True

        except socket.timeout:
            print(f"[!] Timeout na tentativa {tentativa}/{RETRY_DOWNLOAD}: {url}")
        except HTTPError as e:
            print(f"[!] HTTPError em {url}: {e.code} - {e.reason}")
            return False
        except URLError as e:
            print(f"[!] URLError em {url}: {e.reason}")
        except Exception as e:
            print(f"[!] Falha na tentativa {tentativa}/{RETRY_DOWNLOAD} em {url}: {e}")

        time.sleep(2)

    return False


def try_decode(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8", "latin-1", "utf-16"):
        try:
            return raw.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def is_binary_file(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:2048]
        return b"\x00" in chunk
    except Exception:
        return True


def extract_if_archive(path: Path, out_dir: Path) -> list[Path]:
    extracted = []
    try:
        lower = path.name.lower()

        if lower.endswith(".zip"):
            with zipfile.ZipFile(path, "r") as zf:
                target = out_dir / path.stem
                target.mkdir(parents=True, exist_ok=True)
                zf.extractall(target)
                extracted.extend([p for p in target.rglob("*") if p.is_file()])

        elif lower.endswith((".tar", ".tgz", ".tar.gz")):
            target = out_dir / path.stem.replace(".tar", "")
            target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(path, "r:*") as tf:
                tf.extractall(target)
                extracted.extend([p for p in target.rglob("*") if p.is_file()])

    except Exception as e:
        print(f"[!] Erro ao extrair {path}: {e}")

    return extracted


def extract_text_from_pdf(path: Path) -> str:
    try:
        import pypdf
        text = []
        with open(path, "rb") as f:
            reader = pypdf.PdfReader(f)
            for page in reader.pages:
                text.append(page.extract_text() or "")
        return "\n".join(text)

    except ModuleNotFoundError:
        aviso_pip("pypdf")
        return ""

    except Exception as e:
        print(f"[!] Erro ao extrair PDF {path}: {e}")
        return ""


def extract_text_from_docx(path: Path) -> str:
    try:
        import zipfile as zf
        import xml.etree.ElementTree as ET

        with zf.ZipFile(path) as docx:
            xml_content = docx.read("word/document.xml")

        root = ET.fromstring(xml_content)
        texts = []

        for node in root.iter():
            if node.tag.endswith("}t") and node.text:
                texts.append(node.text)

        return "\n".join(texts)

    except ModuleNotFoundError:
        aviso_pip("python-docx")
        return ""

    except Exception as e:
        print(f"[!] Erro ao extrair DOCX {path}: {e}")
        return ""


def extract_content(path: Path) -> str:
    lower = path.name.lower()

    if lower.endswith(".pdf"):
        return extract_text_from_pdf(path)

    if lower.endswith(".docx"):
        return extract_text_from_docx(path)

    if is_binary_file(path) and not lower.endswith((
        ".json", ".js", ".map", ".xml", ".txt", ".log", ".sql", ".conf", ".config",
        ".ini", ".yaml", ".yml", ".env", ".csv"
    )):
        return ""

    return try_decode(path)


def get_context(content: str, start: int, end: int, radius: int = 100) -> str:
    left = max(0, start - radius)
    right = min(len(content), end + radius)
    snippet = content[left:right].replace("\n", " ")
    return snippet[:300]


def line_number(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def immediate_alert(finding: dict) -> None:
    sev = finding["severity"].upper()
    print(f"\n[!!!] ACHADO {sev}")
    print(f"      Tipo   : {finding['type']}")
    print(f"      Arquivo: {finding['file']}")
    print(f"      Linha  : {finding['line']}")
    print(f"      Match  : {finding['match'][:150]}")
    print("")


def extract_base_from_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_robots_txt(content: str) -> list[str]:
    paths = set()

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key in ("disallow", "allow") and value and value != "/":
            if value.startswith("http://") or value.startswith("https://"):
                try:
                    parsed = urlparse(value)
                    value = parsed.path or "/"
                    if parsed.query:
                        value += "?" + parsed.query
                except Exception:
                    continue

            if not value.startswith("/"):
                value = "/" + value

            paths.add(value)

    return sorted(paths)


def check_url_with_curl(url: str) -> dict:
    try:
        result = subprocess.run(
            [
                "curl",
                "-k",
                "-L",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}|%{content_type}|%{size_download}",
                "--max-time",
                "20",
                url
            ],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()
        if "|" in output:
            status_code, content_type, size_download = output.split("|", 2)
            return {
                "url": url,
                "status": status_code,
                "content_type": content_type,
                "size": size_download
            }

    except Exception as e:
        print(f"[!] Erro ao testar URL com curl: {url} -> {e}")

    return {
        "url": url,
        "status": "erro",
        "content_type": "",
        "size": ""
    }


def analyze_robots_paths(content: str, source_url: str) -> list[dict]:
    findings = []

    base_url = extract_base_from_url(source_url)
    paths = parse_robots_txt(content)

    if not paths:
        return findings

    print(f"[+] robots.txt encontrado, testando {len(paths)} caminhos...")

    seen = set()
    for path in paths:
        full_url = base_url + path
        if full_url in seen:
            continue
        seen.add(full_url)

        result = check_url_with_curl(full_url)
        status = result["status"]

        if status not in ROBOTS_STATUS_INTERESSANTES:
            continue

        severity = "medium" if status in ("200", "204", "401", "403") else "low"

        findings.append({
            "type": "Robots Path Exposure",
            "severity": severity,
            "file": source_url,
            "line": 0,
            "match": full_url,
            "context": f"status={result['status']} content_type={result['content_type']} size={result['size']}"
        })

        if status in ("200", "204", "401", "403"):
            print(f"[!!!] Caminho do robots acessível: {full_url} -> HTTP {status}")

    return findings


LIBS_RUIDOSAS = (
    "jquery",
    "bootstrap",
    "lottie",
    "anychart",
    "mdb",
    "materialize",
    "emojiarea",
)

def is_translation_file(file_path: Path) -> bool:
    name = file_path.name.lower()
    return any(x in name for x in ("pt_br", "en_us", "i18n", "locale", "lang"))

def is_probably_third_party(file_path: Path, content: str) -> bool:
    name = file_path.name.lower()

    if any(lib in name for lib in LIBS_RUIDOSAS):
        return True

    header = content[:2000].lower()
    sinais = (
        "copyright",
        "license",
        "licensed under",
        "sourcemappingurl",
        "webpack",
        "jquery",
        "bootstrap",
    )
    return any(s in header for s in sinais)


def is_interesting_js_keyword(keyword: str, context: str) -> bool:
    context = context.lower()

    sinais_fortes = (
        "authorization",
        "bearer",
        "basic ",
        "secret",
        "token",
        "cookie",
        "admin",
        "impersonate",
        "role",
        "permission",
    )

    # palavras genéricas precisam de contexto forte
    if keyword.lower() in {
        "permission", "scope", "/admin", "/auth/", "/graphql"
    }:
        return sum(1 for s in sinais_fortes if s in context) >= 2

    return True


def should_skip_finding(name: str, file_path: Path, content: str, context: str) -> bool:
    third_party = is_probably_third_party(file_path, content)
    translation = is_translation_file(file_path)

    # 🔴 ignora keyword sempre (ruído)
    if name == "JS Keyword":
        return True

    # 🔴 ignora lixo de libs
    if third_party and name in {"Email", "Debug Artifact"}:
        return True

    # 🔴 ignora arquivos de tradução
    if translation and name in {
        "Password Assignment",
        "Hardcoded Secret",
        "Hardcoded Token"
    }:
        return True

    return False

def analyze_content(content: str, file_path: Path) -> list[dict]:
    findings = []
    seen = set()

    for name, meta in PATTERNS.items():
        pattern = re.compile(meta["regex"])
        for match in pattern.finditer(content):
            found = match.group(0)
            context = get_context(content, match.start(), match.end())

            if should_skip_finding(name, file_path, content, context):
                continue

            key = (
                name,
                found[:120].lower(),
                file_path.name.lower()
            )
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": name,
                "severity": meta["severity"],
                "file": str(file_path),
                "line": line_number(content, match.start()),
                "match": found[:300],
                "context": context
            })

    # 🔵 JS KEYWORDS (modo inteligente)
    lower_name = file_path.name.lower()
    if lower_name.endswith((".js", ".map", ".json")):

        third_party = is_probably_third_party(file_path, content)

        # 🔴 ignora libs
        if not third_party:
            keyword_seen = set()

            for kw in KEYWORDS_JS_RELEVANTES:
                for m in re.finditer(re.escape(kw), content, re.IGNORECASE):
                    context = get_context(content, m.start(), m.end())

                    if not is_interesting_js_keyword(kw, context):
                        continue

                    k = ("JS Keyword", kw, line_number(content, m.start()))
                    if k in keyword_seen:
                        continue
                    keyword_seen.add(k)

                    findings.append({
                        "type": "JS Keyword",
                        "severity": "low",
                        "file": str(file_path),
                        "line": line_number(content, m.start()),
                        "match": kw,
                        "context": context
                    })

    return findings


def save_reports(findings: list[dict]) -> None:
    findings_sorted = sorted(
        [
            f for f in findings
            if not (f["severity"] == "low" and f["type"] in {"JS Keyword", "Debug Artifact"})
        ],
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 0),
        reverse=True
    )

    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(findings_sorted, f, indent=2, ensure_ascii=False)

    with open(REPORT_TXT, "w", encoding="utf-8") as f:
        f.write(f"Relatório de triagem - {dominio}\n")
        f.write("=" * 80 + "\n\n")

        resumo = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in findings_sorted:
            resumo[item["severity"]] = resumo.get(item["severity"], 0) + 1

        f.write("Resumo:\n")
        for sev in ["critical", "high", "medium", "low"]:
            f.write(f" - {sev}: {resumo.get(sev, 0)}\n")
        f.write("\n")

        for item in findings_sorted:
            f.write(f"[{item['severity'].upper()}] {item['type']}\n")
            f.write(f"Arquivo : {item['file']}\n")
            f.write(f"Linha   : {item['line']}\n")
            f.write(f"Match   : {item['match']}\n")
            f.write(f"Contexto: {item['context']}\n")
            f.write("-" * 80 + "\n")

def main():
    urls = collect_urls(dominio)

    with open(URLS_FILE, "w", encoding="utf-8") as f:
        for url in sorted(urls):
            f.write(url + "\n")

    print(f"[+] {len(urls)} URLs filtradas salvas em {URLS_FILE}")

    downloaded_files = []
    downloaded_map = {}

    print("[+] Baixando arquivos...")
    for url in sorted(urls):
        filename = unique_filename(url)
        destination_dir = SENSITIVE_DIR if should_go_to_sensitive(url) else DOWNLOAD_DIR
        destination = destination_dir / filename

        ok = download_file(url, destination)
        if ok:
            downloaded_files.append(destination)
            downloaded_map[str(destination)] = url

            if is_critical_extension(destination):
                print(f"\n[!!!] ARQUIVO POTENCIALMENTE CRÍTICO BAIXADO: {destination}\n")

    print(f"[+] Arquivos baixados: {len(downloaded_files)}")

    extracted_files = []
    print("[+] Extraindo arquivos compactados...")
    for file_path in downloaded_files:
        extracted = extract_if_archive(file_path, EXTRACT_DIR)
        extracted_files.extend(extracted)

        for extraido in extracted:
            if is_critical_extension(extraido):
                print(f"\n[!!!] ARQUIVO CRÍTICO EXTRAÍDO: {extraido}\n")

    print(f"[+] Arquivos extraídos: {len(extracted_files)}")

    all_files = downloaded_files + extracted_files
    all_findings = []

    print("[+] Analisando arquivos...")
    for file_path in all_files:
        try:
            content = extract_content(file_path)
            if not content.strip():
                continue

            findings = analyze_content(content, file_path)

            source_url = downloaded_map.get(str(file_path), "")
            if is_robots_file(file_path) and source_url:
                findings.extend(analyze_robots_paths(content, source_url))

            for finding in findings:
                all_findings.append(finding)
                if finding["severity"] in ("critical", "high"):
                    immediate_alert(finding)

        except Exception as e:
            print(f"[!] Erro ao analisar {file_path}: {e}")

    save_reports(all_findings)

    print("\n[+] Análise concluída.")
    print(f"[+] Relatório TXT : {REPORT_TXT}")
    print(f"[+] Relatório JSON: {REPORT_JSON}")


if __name__ == "__main__":
    main()
