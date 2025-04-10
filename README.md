# coleta_dados.py

🕵️‍♂️ coleta_dados.py

Ferramenta automatizada para coleta e análise de arquivos públicos (.js, .json, .env, etc.) relacionados a um domínio, com o objetivo de identificar possíveis exposições de dados sensíveis.

🚀 Funcionalidades

Coleta URLs públicas usando gau e waybackurls

Filtra arquivos com extensões suspeitas ou sensíveis:

.js, .json, .env, .log, .bak, .old, .zip, .conf, .sql, .xml, .txt

Realiza o download automatizado com wget

Analisa os arquivos localmente em busca de:

🔐 JWTs, chaves de API (AWS, Google, Stripe)

👤 Credenciais e dados pessoais (usuário, senha, CPF, CNPJ, e-mail)

🧭 URLs internas ou endpoints de debug

🐞 Logs de depuração (console.log, debugger, etc.)

Salva os resultados encontrados em um arquivo estruturado

🛠️ Uso

python3 coleta_dados.py

Você informará:

O domínio a ser analisado

A ferramenta então:

Cria uma pasta para os arquivos baixados

Cria um arquivo com as URLs coletadas

Salva os arquivos suspeitos em uma subpasta separada

Gera um relatório com todos os possíveis vazamentos encontrados

⚠️ Aviso Legal
Esta ferramenta foi desenvolvida para uso profissional e autorizado em análises de segurança, assessments, e atividades relacionadas a Pentest e Bug Bounty.
⚠️ Jamais deve ser utilizada para fins maliciosos ou sem a devida autorização do proprietário do domínio.
