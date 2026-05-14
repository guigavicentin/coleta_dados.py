# 🕵️ Recon Automation Toolkit

Conjunto de ferramentas para reconhecimento web, análise de superfície de ataque e detecção de vulnerabilidades — voltado para **Bug Bounty**, **Pentest autorizado** e **pesquisa em segurança ofensiva**.

---

## 📦 Ferramentas

| Script | Foco | Entrada |
|---|---|---|
| `recon.py` | Coleta de URLs, análise de JS, extração de endpoints e busca de segredos | domínio via argumento ou interativo |
| `takeover.py` | Enumeração de subdomínios, dangling CNAMEs, takeover, nuclei full scan, port scan | domínio ou lista `-l` |
| `js_live_crawler.py` | Captura arquivos `.js` carregados ao vivo por um browser real (Playwright) | URL única ou arquivo com lista |

---

## 🔍 recon.py — Análise de JS, Segredos & Endpoints

Pipeline completo de reconhecimento focado em JavaScript, arquivos sensíveis e extração de endpoints de API.

### Fluxo

```
Coleta de URLs (gau + waybackurls + wayback-api + commoncrawl + katana + hakrawler + gospider + subfinder)
      ↓
Validação de URLs ativas (httpx)  →  Filtragem por padrão (gf)
      ↓
Probes: XSS (dalfox) · SSRF/Redirect (qsreplace + curl)
      ↓
Arquivos sensíveis → Download & análise de conteúdo
      ↓
Inline scripts HTML → Análise de segredos e endpoints
      ↓
Coleta de JS externos → Cache em disco → Análise paralela
      ↓
Source maps (.js.map) → Extração de código-fonte original
      ↓
Análise de subdomínios → JS por sub → Segredos
      ↓
Validação de Google API Keys → Relatório consolidado (TXT + HTML)
```

### O que detecta

#### Segredos em JavaScript (40+ padrões, com severidade)

| Severidade | Tipos |
|---|---|
| **CRITICAL** | AWS Access Keys, Private Keys, Stripe Secret, Braintree Token, GCP Service Account, HashiCorp Vault, Azure Storage Key, `secretKey` hardcoded |
| **HIGH** | GitHub/GitLab PATs, OpenAI Keys, SendGrid, Slack Tokens, Supabase Service Role, MongoDB/PostgreSQL/MySQL DSN, Google API Key, Firebase Config, `btoa()` com credenciais, Basic Auth hardcoded |
| **MEDIUM** | JWT, Stripe Publishable, Slack Webhook, Sentry DSN, Mapbox Token, Supabase Anon Key, Mailgun, `Authorization` hardcoded |
| **LOW** | Firebase Measurement ID, Generic API Key, Generic Token, Bearer Token, Password Fields, bcrypt Hashes |

#### Detecções avançadas

- **Ofuscação por char-code arrays** — detecta `[72,101,108,108,111]` e decodifica para verificar segredos
- **Análise de `btoa()`** — decodifica valores base64 hardcoded em chamadas `btoa("user:pass")`
- **Validação estrutural de JWT** — verifica header/payload antes de reportar
- **Deduplicação por valor normalizado** — evita falso-positivos duplicados
- **Rate limiting adaptativo por hostname** — até 4 conexões simultâneas por host
- **Cache de JS em disco** (TTL 24h) — evita redownload em re-execuções

#### Endpoints extraídos (17 padrões com método HTTP)

`fetch GET/POST/PUT/DELETE/PATCH` · `fetch dinâmico` · `URLSearchParams` · `JSON.stringify body` · `FormData` · `router path` · `href/src/action` · `URL com query string` · `WebSocket` · `GraphQL` · `/api/vN/` · `/vN/` · subdomínios internos

Cada endpoint é salvo com: **método HTTP**, **path**, **URL absoluta**, **query params** e **JS de origem**.

#### Arquivos sensíveis (histórico Wayback)

`.env` · `.sql` · `.bak` · `.conf` · `.log` · `.pem` · `.key` · `.yml` · `.sh` · `.py` · e outros

#### Pontos de injeção via GF

`XSS` · `SQLi` · `SSRF` · `Open Redirect` · `SSTI`

> **Dica:** Caminhos inativos ainda podem conter arquivos expostos no histórico da Wayback Machine. Sempre valide em: https://web.archive.org

### Uso

```bash
python3 recon.py exemplo.com
```

### Flags disponíveis

| Flag | Descrição |
|---|---|
| `--no-dalfox` | Pula probe XSS (dalfox) |
| `--no-ssrf-probe` | Pula probe SSRF/redirect |
| `--no-sensitive-dl` | Pula download de arquivos sensíveis |
| `--no-httpx` | Usa todas as URLs sem validar com httpx |
| `--no-google-val` | Pula validação de endpoints Google |
| `--no-subs` | Pula análise de subdomínios |
| `--no-sourcemaps` | Pula coleta e análise de source maps (`.js.map`) |
| `--no-inline-scripts` | Pula análise de inline scripts em HTML |
| `--no-cache` | Ignora cache de JS em disco |
| `--workers N` | Workers JS paralelos (padrão: 20) |
| `--timeout N` | Timeout de requisições em segundos (padrão: 10) |

### Outputs gerados

| Arquivo | Conteúdo |
|---|---|
| `urls_raw.txt` | Todas as URLs coletadas |
| `urls_alive.txt` | URLs ativas (httpx) |
| `js_urls.txt` | Arquivos JavaScript únicos |
| `secrets.txt` / `.csv` / `.jsonl` | Segredos encontrados (3 formatos) |
| `endpoints.txt` / `.jsonl` | Endpoints de API extraídos (com método HTTP) |
| `google_keys.txt` | Google API Keys identificadas |
| `google_keys_report.txt` | Validação por endpoint (11 APIs Google) |
| `sensitive_urls.txt` | URLs de arquivos sensíveis |
| `sensitive_report.txt` | Achados em arquivos sensíveis |
| `sourcemaps_found.txt` | Source maps públicos confirmados |
| `sourcemaps/` | Código-fonte extraído dos source maps |
| `subdomains_alive.txt` | Subdomínios vivos |
| `subdomains_report.txt` | Achados por subdomínio |
| `gf/gf_xss.txt` etc. | URLs filtradas por padrão GF |
| `gf/dalfox_results.txt` | XSS confirmados |
| `SUMMARY.txt` | Resumo completo da execução |
| `SUMMARY.html` | Relatório visual interativo e filtrável |
| `recon.log` | Log detalhado |

### Validação de Google API Keys

O script valida automaticamente cada key encontrada contra **11 endpoints** da API Google:

Geocoding · Directions · Distance Matrix · Find Place · Autocomplete · Elevation · Timezone · YouTube Data · Custom Search · Cloud Translation · Generative Language (Gemini)

---

## 🌐 takeover.py — Subdomain Takeover & Recon

Pipeline de reconhecimento de subdomínios com foco em detecção de takeover e mapeamento da superfície externa.

### Fluxo

```
Enumeração (subfinder + assetfinder + crt.sh + OTX + chaos + github-subdomains)
      ↓
Deduplicação → Resolução DNS + coleta de CNAMEs (dnsx)
      ↓
Bruteforce opcional (puredns) → Hosts vivos (httpx com rate-limit)
      ↓
WAF Detection paralela (wafw00f) → Screenshots (gowitness)
      ↓
Takeover: fingerprints com pré-filtro CNAME + subzy + subjack + nuclei full scan
      ↓
Dangling CNAME check (COB-1) → CNAMEs suspeitos não confirmados
      ↓
Nmap port scan → Relatório HTML + JSON estruturado
```

### Fontes de enumeração

| Fonte | Token obrigatório |
|---|---|
| subfinder | Não (rende mais com config) |
| assetfinder | Não |
| crt.sh (API pública) | Não |
| AlienVault OTX | Não |
| chaos | Sim (`CHAOS_KEY`) |
| github-subdomains | Sim (`GITHUB_TOKEN`) |

### Detecção de Takeover

- **35+ fingerprints** com pré-filtro por CNAME antes da requisição HTTP — evita falsos positivos
- **Dangling CNAME check** — identifica CNAMEs que apontam para serviços externos não registrados
- **Verificação real de bucket S3** — confirma se o bucket existe antes de reportar
- **Deduplicação por `(url_normalizada + fonte)`** — sem duplicatas entre ferramentas
- **Validação com subzy e subjack**
- **Nuclei full scan** com todos os templates + templates customizados via `--nuclei-extra`
- **Seção de CNAMEs suspeitos** — externos sem fingerprint confirmado, para revisão manual

Serviços cobertos: AWS S3 · GitHub Pages · Heroku · Fastly · Shopify · Azure · Vercel · Netlify · Ghost · Surge.sh · Statuspage · Zendesk · WordPress · Webflow · Bitbucket · e mais

### Melhorias implementadas

| ID | Melhoria |
|---|---|
| COB-1 | DNS CNAME + check de resolução para detectar dangling CNAMEs |
| COB-2 | Enumeração via AlienVault OTX (sem token obrigatório) |
| COB-3 | Coleta de CNAMEs em massa via `dnsx -cname` |
| PRE-1 | Pré-filtro por CNAME pattern antes da requisição HTTP |
| PRE-2 | Verificação de bucket S3 existente antes de marcar takeover |
| PRE-3 | Deduplicação por `(url_normalizada + serviço)` |
| PER-1 | httpx com `-rate-limit` configurável por argumento |
| PER-2 | wafw00f paralelizado com `ThreadPoolExecutor` |
| RES-1 | Retry com backoff exponencial em crt.sh e OTX |
| RES-2 | Verificação de versão mínima das ferramentas (nuclei ≥3.0, httpx ≥1.3, dnsx ≥1.1) |
| RES-3 | Timeout granular por ferramenta via argumento |
| REL-1 | Relatório HTML com severidade, CVSS estimado e filtros JS |
| REL-2 | Exportação JSON estruturado (machine-readable) |
| REL-3 | Seção de CNAMEs suspeitos não confirmados |

### Uso

```bash
# Domínio único
python3 takeover.py exemplo.com

# Lista de domínios
python3 takeover.py -l dominios.txt
```

### Flags disponíveis

| Flag | Descrição |
|---|---|
| `--nuclei-templates PATH` | Path do repositório principal de templates nuclei |
| `--nuclei-extra PATH` | Diretório extra de templates (pode repetir a flag) |
| `--resolvers PATH` | Arquivo de resolvers DNS |
| `--wordlist PATH` | Wordlist para bruteforce (puredns) |
| `--severity LEVEL` | Filtro de severity no nuclei (padrão: `low,medium,high,critical`) |
| `--httpx-timeout N` | Timeout por request httpx em segundos (padrão: 10) |
| `--httpx-rate N` | Rate limit httpx em req/s (padrão: 150) |
| `--no-nmap` | Pula nmap |
| `--no-waf` | Pula WAF detection |
| `--no-bruteforce` | Pula puredns bruteforce |

### Variáveis de ambiente opcionais

```bash
export CHAOS_KEY="seu_token"
export GITHUB_TOKEN="seu_token"
export NUCLEI_TEMPLATES="/root/nuclei-templates"
export RESOLVERS_FILE="/usr/share/wordlists/resolvers.txt"
export SUBDOMAINS_WORDLIST="/usr/share/wordlists/subdomains.txt"
```

### Outputs gerados

| Arquivo | Conteúdo |
|---|---|
| `subdomains_raw.txt` | Lista consolidada bruta |
| `subdomains_resolved.txt` | Subdomínios com resolução DNS |
| `subdomains_bruteforce.txt` | Resultados do puredns |
| `cnames.txt` | Mapa completo de CNAMEs |
| `dangling_cnames.txt` | CNAMEs que não resolvem (risco de takeover) |
| `alive.txt` | Hosts ativos com URL completa |
| `alive_domains.txt` | Domínios vivos (sem protocolo/porta) |
| `httpx_data.jsonl` | Dados detalhados httpx (JSON por linha) |
| `waf_detected.txt` | WAFs identificados por host |
| `subzy_vulnerable.txt` | Resultados do subzy |
| `subjack_results.txt` | Resultados do subjack |
| `nuclei_full.txt` | Achados do full scan nuclei |
| `takeovers_confirmed.txt` | Merge final de takeovers (ordenado por severidade) |
| `ips.txt` | IPs extraídos dos hosts ativos |
| `nmap.txt` | Resultado do port scan |
| `report.html` | Relatório visual completo com filtros |
| `report.json` | Relatório estruturado machine-readable |
| `takeover.log` | Log detalhado |

---

## 🌐 js_live_crawler.py — Captura de JS ao Vivo (Playwright)

Captura todos os arquivos `.js` carregados **ao vivo** por um site, exatamente como um browser real faria — sem caches históricos, sem Wayback Machine.

Complementa o `recon.py` ao identificar JS dinâmico carregado via SPA, lazy loading ou chamadas assíncronas que ferramentas passivas não capturam.

### Uso

```bash
# URL única
python3 js_live_crawler.py https://example.com

# URL única com saída JSON
python3 js_live_crawler.py https://example.com -w 3 -o result.json

# Arquivo com lista de domínios
python3 js_live_crawler.py -f dominios.txt

# Arquivo com lista + saída JSON acumulada
python3 js_live_crawler.py -f dominios.txt -o result.json

# Abre o browser visível (útil para debug)
python3 js_live_crawler.py https://example.com --no-headless
```

### Flags disponíveis

| Flag | Descrição |
|---|---|
| `-f FILE` / `--file FILE` | Arquivo com domínios/URLs, um por linha (comentários `#` ignorados) |
| `-t N` / `--timeout N` | Timeout de navegação em segundos (padrão: 30) |
| `-w N` / `--wait N` | Segundos extras após networkidle (padrão: 2) |
| `-o FILE` / `--output FILE` | Salvar resultado acumulado em JSON |
| `--no-headless` | Abre o browser visível (útil para debug) |

### Formato do arquivo de domínios

```
# comentários são ignorados
example.com
https://outro.com
http://terceiro.com.br
```

### Output

Cada execução classifica os arquivos JS em:

- **JS do próprio domínio** — alvos prioritários para análise de segredos
- **JS de terceiros** — CDNs, bibliotecas externas, analytics

Com `-o result.json`, os resultados são **acumulados** no mesmo arquivo entre execuções (lista de crawls com timestamp).

---

## ⚙️ Dependências

### Instalação das ferramentas Go

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/LukaSikic/subzy@latest
go install github.com/haccer/subjack@latest
go install github.com/sensepost/gowitness@latest
```

### Instalação das dependências Python

```bash
pip install requests tenacity urllib3

# Para js_live_crawler.py
pip install playwright
playwright install chromium
```

### APT

```bash
sudo apt install nmap wafw00f curl
```

### Versões mínimas verificadas automaticamente

| Ferramenta | Versão mínima |
|---|---|
| nuclei | 3.0.0 |
| httpx | 1.3.0 |
| dnsx | 1.1.0 |

---

## 🎯 Uso recomendado

- Bug Bounty em programas com escopo definido
- Pentest com autorização formal
- Recon inicial de infraestrutura
- Hunting automatizado em laboratórios e CTFs
- Pesquisa e estudos de segurança ofensiva

---

## ⚠️ Aviso Legal

Estas ferramentas são destinadas **exclusivamente** para uso em ambientes autorizados. A execução contra alvos sem permissão prévia é ilegal e de responsabilidade exclusiva do usuário.

**Utilize apenas em programas de bug bounty, contratos de pentest ou ambientes próprios.**
