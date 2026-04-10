# 🔎 Recon Automation Toolkit

Conjunto de scripts para **coleta de dados**, **reconhecimento** e **análise automatizada** voltados para **Bug Bounty**, **Pentest** e **estudos de segurança ofensiva**.

---

# 📦 Ferramentas incluídas

## 🧠 coleta_dadado.py

Ferramenta focada em **coleta de URLs**, **análise de parâmetros** e **busca de arquivos sensíveis**.

### 🔍 O que ela faz

* Coleta URLs utilizando:

  * `katana`
  * `gau`
  * `waybackurls`

* Analisa URLs coletadas com:

  * `gf`

* Filtra possíveis pontos de:

  * XSS
  * SQLi
  * SSRF
  * SSTI
  * Redirect
  * Injection em geral

* Coleta arquivos `.js`

* Analisa JavaScript em busca de:

  * Tokens
  * API Keys
  * Secrets
  * Endpoints ocultos

* Busca arquivos sensíveis no histórico:

  * `.env`
  * `.sql`
  * `.bak`
  * `.zip`
  * `.conf`
  * `.log`
  * `.json`
  * etc.

### ⚠️ Observação Importante

Alguns caminhos podem estar **inativos**.
Nestes casos, é altamente recomendado validar manualmente no:

https://web.archive.org/

Muitas vezes arquivos removidos ainda estão disponíveis no histórico.

---

## 🌐 coleta_sub.py

Ferramenta focada em **reconhecimento de subdomínios** e **análise de superfície externa**.

### 🔍 O que ela faz

* Coleta subdomínios utilizando múltiplas ferramentas
* Combina resultados para maior cobertura
* Valida hosts ativos com `httpx`
* Executa varreduras com `nuclei`
* Verifica possíveis **Subdomain Takeover**
* Extrai IPs dos hosts ativos
* Executa `nmap` nos IPs descobertos

### 🧪 Fluxo

1. Enumeração de subdomínios
2. Deduplicação
3. Validação HTTP
4. Scan com nuclei
5. Detecção takeover
6. Extração de IPs
7. Scan Nmap

---

# ⚙️ Dependências

Certifique-se de ter instalado:

```
katana
gau
waybackurls
gf
httpx
nuclei
nmap
subfinder
amass
shodanx
```

---

# 🚀 Uso

### coleta_dadado.py

```
python3 coleta_dadado.py
```

Informe o domínio quando solicitado.

---

### coleta_sub.py

```
python3 coleta_sub.py dominio.com
```

Ou lista:

```
python3 coleta_sub.py -l dominios.txt
```

---
---

# 🎯 Uso recomendado

* Bug Bounty
* Pentest autorizado
* Recon inicial
* Estudos de segurança
* Hunting automatizado

---

# ⚠️ Aviso Legal

Ferramenta destinada exclusivamente para:

* Bug bounty
* Estudos
* Pentests com autorização

❗ Não utilize contra alvos sem permissão.
❗ O uso indevido é de responsabilidade do usuário.

Use com moderação. 🛡️

---

# 👨‍💻 Autor

Guilherme Vicentin
