# 🔎 Recon Automation Toolkit

Conjunto de scripts para coleta de dados, reconhecimento e análise automatizada voltados para Bug Bounty, Pentest e estudos de segurança ofensiva.

📦 Ferramentas incluídas
🧠 coleta_dadado.py

Ferramenta focada em coleta de URLs, análise de parâmetros e busca de arquivos sensíveis.

🔍 O que ela faz

Coleta URLs utilizando:

katana
gau
waybackurls

Analisa URLs coletadas com:

gf

Filtra possíveis pontos de:

XSS
SQLi
SSRF
SSTI
Redirect
Injection em geral
Coleta arquivos .js

Analisa JavaScript em busca de:

Tokens
API Keys
Secrets
Endpoints ocultos

Busca arquivos sensíveis no histórico:

.env
.sql
.bak
.zip
.conf
.log
.json
etc.

# ⚠️ Observação Importante

Alguns caminhos podem estar inativos.
Nestes casos, é altamente recomendado validar manualmente no:

https://web.archive.org/

Muitas vezes arquivos removidos ainda estão disponíveis no histórico.

# 🌐 coleta_sub.py

Ferramenta focada em reconhecimento de subdomínios, análise de superfície externa e detecção de takeover.

🔥 O que ela faz (atualizado)

Coleta subdomínios utilizando múltiplas ferramentas:

subfinder
amass
assetfinder
chaos
shodanx
Deduplicação automática dos resultados

Resolução DNS massiva com:

massdns

Validação de hosts ativos com:

httpx
Detecção de Subdomain Takeover com:
subzy
subjack
análise manual baseada em fingerprint

Varredura com:

nuclei (templates oficiais)
templates customizados (GIT)
Extração de IPs dos hosts ativos

Scan completo com:

nmap - Não recomendado rodar sempre - priorize rodar com --no-nmap - rode o nmap em casos mais acertivos.

🧪 Fluxo atualizado

Enumeração de subdomínios
Deduplicação
Resolução DNS (massdns) 🌐
Scan takeover inicial (subjack + subzy) 💀
Validação HTTP (httpx)
Detecção takeover (thread + fingerprint)
Scan com nuclei (oficial + custom)
Merge de resultados
Extração de IPs
Scan Nmap

📂 Outputs gerados

Arquivo	Descrição

subdomains.txt	lista consolidada
massdns.txt	resolução DNS
alive.txt	hosts ativos
subjack_vuln.txt resultado subjack
subzy_takeovers.txt	resultados subzy
takeover_threaded.txt	análise por fingerprint
takeover_final.txt	merge final
ips.txt	IPs extraídos
nmap.txt	scan de portas

⚙️ Dependências

Certifique-se de ter instalado:

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
assetfinder
massdns
subjack
subzy

🚀 Uso

coleta_dadado.py

python3 coleta_dadado.py

Informe o domínio quando solicitado.

coleta_sub.py

python3 coleta_sub.py dominio.com

Ou lista:

python3 coleta_sub.py -l dominios.txt

🎯 Uso recomendado

Bug Bounty

Pentest autorizado

Recon inicial

Estudos de segurança

Hunting automatizado

# ⚠️ Aviso Legal

Ferramenta destinada exclusivamente para:

Bug bounty
estudos
pentests com autorização

❗ Não utilize contra alvos sem permissão
❗ O uso indevido é de responsabilidade do usuário

Use com moderação. 🛡️

Guilherme Vicentin
