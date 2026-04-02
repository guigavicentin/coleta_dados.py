# 🕵️‍♂️ coleta_dados.py

Ferramenta automatizada para coleta, download e análise de arquivos públicos relacionados a um domínio, com foco na identificação de exposição de dados sensíveis e artefatos úteis para Pentest / Bug Bounty.

# 🚀 Funcionalidades 🔎 Coleta de URLs
Integração com:
- gau
- waybackurls
- Coleta ampla de endpoints históricos e atuais

- 📂 Filtragem inteligente de arquivos

- Busca por extensões sensíveis como:
.js, .json, .map, .env, .log, .bak, .old,
.zip, .tar, .gz, .tgz, .rar, .7z,
.conf, .config, .ini, .yaml, .yml,
.sql, .xml, .txt, .pdf, .docx,
.pem, .key, .pfx, .db, .sqlite

Inclui também:

robots.txt (tratamento especial 🔥)

⬇️ Download robusto

Retry automático em falhas

Timeout configurável

Controle de tamanho de arquivo

Nome único para evitar sobrescrita

📦 Extração de arquivos

- Suporte para:
.zip
.tar
.tar.gz / .tgz

# 🧠 Análise de conteúdo

- Detecta automaticamente:

# 🔐 Credenciais e Segredos

JWT
AWS Keys
Google API Keys
Stripe Keys
Bearer Tokens
Basic Auth
GitHub / Slack tokens
Connection Strings
Secrets em .env

# 🧬 Hardcoded secrets

apiKey
clientSecret
accessToken
secretKey

# 🌐 Infraestrutura interna

URLs internas (RFC1918)
endpoints locais (localhost)

# 🧑‍💻 Código sensível

roles (admin, superadmin, impersonate)
uso de cookies e storage
chamadas HTTP (fetch, axios, XMLHttpRequest)

# 🐞 Debug / vazamento

console.log
debugger
artefatos de desenvolvimento

# 🤖 Análise de robots.txt (🔥 diferencial)

- Quando encontrado:
Extrai:
Disallow
Allow
Monta URLs automaticamente
Testa cada endpoint com curl
Identifica respostas:
200
301/302
401
403

# 👉 Excelente para descobrir:

painéis administrativos
endpoints ocultos
áreas restritas expostas

# 📊 Relatórios

- Geração de:

📄 relatorio.txt (legível)
📦 relatorio.json (estruturado)

- Com:
severidade (low, medium, high, critical)
arquivo origem
linha
contexto do match

# 🚨 Alertas em tempo real

Durante execução:

- exibe imediatamente achados:
HIGH
CRITICAL

# 🛠️ Uso

python3 coleta_dados.py

- Você informará:
Informe o dominio (ex: exemplo.com):

# 📁 Estrutura gerada

coleta_dominio/
├── downloads/
├── possivelmente_sensiveis/
├── extraidos/
├── urls_dominio.txt
├── relatorio_dominio.txt
└── relatorio_dominio.json

# ⚙️ Dependências

Obrigatórias
Python 3
gau
waybackurls
curl
Opcionais

- Para melhorar análise:

pip install pypdf

Se o sistema bloquear instalação:

pip install pypdf --break-system-packages

- Ou (recomendado):

python3 -m venv venv
source venv/bin/activate
pip install pypdf

# 🎯 Casos de uso
Pentest Web
Bug Bounty
Recon (Reconnaissance)
Attack Surface Mapping
Leak Discovery
Auditoria de exposição acidental

# ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida para uso profissional e autorizado em:

testes de segurança
avaliações de segurança (assessments)
programas de Bug Bounty

# ❌ Não utilize sem autorização do proprietário do alvo

O uso indevido pode violar leis locais e internacionais.
