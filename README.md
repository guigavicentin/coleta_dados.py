# 🕵️ Recon Automation Toolkit

> Conjunto de ferramentas para reconhecimento web, análise de superfície de ataque e detecção de vulnerabilidades — voltado para **Bug Bounty**, **Pentest autorizado** e **pesquisa em segurança ofensiva**.

---

## 📦 Ferramentas

| Script | Foco | Entrada |
|---|---|---|
| `recon.py` | Coleta de URLs, análise de JS e busca de segredos | domínio interativo ou argumento |
| `takeover.py` | Enumeração de subdomínios, takeover e port scan | domínio ou lista `-l` |

---

## 🔍 recon.py — Análise de JS & Secrets

Pipeline completo de reconhecimento focado em JavaScript e arquivos sensíveis.

### Fluxo

```
Coleta de URLs  →  Validação (httpx)  →  Filtragem (gf)  →  Probes (XSS / SSRF)
      ↓
Arquivos sensíveis  →  Download & análise de conteúdo
      ↓
Coleta de JS  →  Análise de segredos  →  Validação de Google API Keys
      ↓
Análise de subdomínios  →  Relatório consolidado
```

### O que ela detecta

**Segredos em JavaScript:**
`Google API Keys` · `AWS Access Keys` · `Stripe / Braintree` · `SendGrid` · `GitHub / GitLab PATs` · `Slack tokens` · `OpenAI keys` · `Supabase` · `JWT` · `Connection strings (MongoDB, PostgreSQL, MySQL, Redis)` · `Private keys` · `bcrypt hashes` · e mais de 40 padrões adicionais

**Arquivos sensíveis no histórico:**
`.env` · `.sql` · `.bak` · `.conf` · `.log` · `.pem` · `.key` · `.yml` e outros

**Pontos de injeção via GF:**
`XSS` · `SQLi` · `SSRF` · `SSTI` · `Open Redirect`

> **Dica:** Caminhos inativos ainda podem conter arquivos expostos no histórico da Wayback Machine. Sempre valide em: https://web.archive.org

### Uso

```bash
python3 recon.py exemplo.com
```

**Flags disponíveis:**

```
--no-dalfox          Pula probe XSS (dalfox)
--no-ssrf-probe      Pula probe SSRF/redirect
--no-sensitive-dl    Pula download de arquivos sensíveis
--no-httpx           Usa todas as URLs sem validar com httpx
--no-google-val      Pula validação de endpoints Google
--no-subs            Pula análise de subdomínios
--workers N          Workers JS paralelos (padrão: 20)
--timeout N          Timeout de requisições em segundos (padrão: 10)
```

### Outputs gerados

| Arquivo | Conteúdo |
|---|---|
| `urls_raw.txt` | Todas as URLs coletadas |
| `urls_alive.txt` | URLs ativas (httpx) |
| `js_urls.txt` | Arquivos JavaScript únicos |
| `secrets.txt / .csv / .jsonl` | Segredos encontrados (3 formatos) |
| `google_keys.txt` | Google API Keys identificadas |
| `google_keys_report.txt` | Validação por endpoint |
| `api_endpoints.txt` | Endpoints de API expostos |
| `sensitive_urls.txt` | URLs de arquivos sensíveis |
| `sensitive_report.txt` | Achados em arquivos sensíveis |
| `gf/gf_xss.txt` etc. | URLs filtradas por padrão |
| `gf/dalfox_results.txt` | XSS confirmados |
| `SUMMARY.txt` | Resumo completo da execução |
| `recon.log` | Log detalhado |

---

## 🌐 takeover.py — Subdomain Takeover & Recon

Pipeline de reconhecimento de subdomínios com foco em detecção de takeover e mapeamento da superfície externa.

### Fluxo

```
Enumeração  →  Deduplicação  →  Resolução DNS (dnsx)
      ↓
Bruteforce opcional (puredns)  →  Hosts vivos (httpx)
      ↓
WAF Detection (wafw00f)  →  Screenshots (gowitness)
      ↓
Takeover: fingerprints + subzy + subjack + nuclei
      ↓
Nmap port scan  →  Relatório HTML consolidado
```

### Fontes de enumeração

`subfinder` · `assetfinder` · `crt.sh (API pública)` · `chaos` *(requer `CHAOS_KEY`)* · `github-subdomains` *(requer `GITHUB_TOKEN`)*

### Detecção de Takeover

- Fingerprints manuais para 35+ serviços (AWS S3, GitHub Pages, Heroku, Shopify, Azure, Fastly, Vercel, etc.)
- Validação com `subzy` e `subjack`
- Scan com `nuclei` — templates de takeover + templates customizados via `--nuclei-extra`

> **Nota sobre nmap:** Use com critério. Prefira rodar com `--no-nmap` na maioria dos casos e habilite apenas em alvos confirmados.

### Uso

```bash
# Domínio único
python3 takeover.py exemplo.com

# Lista de domínios
python3 takeover.py -l dominios.txt
```

**Flags disponíveis:**

```
--nuclei-templates PATH   Path do repositório principal de templates nuclei
--nuclei-extra PATH       Diretório extra de templates (pode repetir a flag)
--resolvers PATH          Arquivo de resolvers DNS
--wordlist PATH           Wordlist para bruteforce (puredns)
--severity LEVEL          Filtro de severity no nuclei (ex: critical,high)
--nmap-timeout N          Timeout do nmap em segundos (padrão: 3600)
--no-nmap                 Pula nmap
--no-network              Pula nuclei/network
--no-http                 Pula nuclei/http
--no-waf                  Pula WAF detection
--no-screenshots          Pula gowitness
--no-bruteforce           Pula puredns bruteforce
```

**Variáveis de ambiente opcionais:**

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
| `alive.txt` | Hosts ativos com URL completa |
| `alive_domains.txt` | Domínios vivos (sem protocolo/porta) |
| `waf_detected.txt` | WAFs identificados por host |
| `subzy_vulnerable.txt` | Resultados do subzy |
| `subjack_results.txt` | Resultados do subjack |
| `nuclei_takeovers.txt` | Achados nuclei (takeovers) |
| `nuclei_network.txt` | Achados nuclei (network) |
| `nuclei_http.txt` | Achados nuclei (http) |
| `takeovers_confirmed.txt` | Merge final de takeovers |
| `ips.txt` | IPs extraídos dos hosts ativos |
| `nmap.txt` | Resultado do port scan |
| `report.html` | Relatório visual completo |
| `screenshots/` | Screenshots dos hosts vivos |
| `takeover.log` | Log detalhado |

---

## ⚙️ Dependências

Instale as ferramentas necessárias conforme o módulo utilizado:

```bash
# Go tools
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

# Python
pip3 install requests tenacity urllib3

# APT
sudo apt install nmap wafw00f
```

---

## 🎯 Uso recomendado

- Bug Bounty em programas com escopo definido
- Pentest com autorização formal
- Recon inicial de infraestrutura
- Hunting automatizado em laboratórios e CTFs
- Pesquisa e estudos de segurança ofensiva

---

## ⚠️ Aviso Legal

Estas ferramentas são destinadas **exclusivamente** para uso em ambientes autorizados. A execução contra alvos sem permissão prévia é **ilegal** e de **responsabilidade exclusiva do usuário**.

```
Utilize apenas em programas de bug bounty, contratos de pentest ou ambientes próprios.
```

---

<div align="center">

Desenvolvido por **Guilherme Vicentin** &nbsp;·&nbsp;
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/guilherme-vicentin-156599202/)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=flat&logo=github&logoColor=white)](https://github.com/guigavicentin)

</div>
