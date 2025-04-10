import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

# ==== CONFIGURACOES ====
dominio = input("Informe o dominio (ex: exemplo.com): ").strip()
arquivo_urls = f"urls_{dominio}.txt"
pasta_downloads = Path(f"downloads_{dominio}")
pasta_sensiveis = Path(f"possivelmente_sensiveis_{dominio}")
arquivo_resultados = f"dados_sensiveis_{dominio}.txt"

pasta_downloads.mkdir(exist_ok=True)
pasta_sensiveis.mkdir(exist_ok=True)

# ==== EXPRESSOES REGULARES PARA DADOS SENSIVEIS ====
regex_sensiveis = {
    "Token JWT": r"eyJ[\w-]+\.[\w-]+\.[\w-]+",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "UUID": r"[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}",
    "Console Log": r"console\\.log|debugger|window\\.debug",
    "Credenciais": r"(user(name)?|senha|pass(word)?|email|auth|cpf|cnpj|session|token)[\"':=\s]+[a-zA-Z0-9\-_.]+",
    "URL Interna": r"https?://[^\"']+"
}

# ==== COLETA DE URLs COM GAU E WAYBACKURLS ====
print("[+] Coletando URLs com gau e waybackurls...")
comando = f"echo {dominio} | gau && echo {dominio} | waybackurls"
result = subprocess.run(comando, shell=True, stdout=subprocess.PIPE, text=True)

# Filtrar URLs
urls_filtradas = set()
for linha in result.stdout.splitlines():
    if any(ext in linha for ext in ['.js', '.json', '.env', '.log', '.bak', '.old', '.zip', '.conf', '.sql', '.xml', '.txt']):
        urls_filtradas.add(linha.strip())

# Salvar URLs encontradas
with open(arquivo_urls, 'w') as f:
    for url in sorted(urls_filtradas):
        f.write(url + "\n")
print(f"[+] {len(urls_filtradas)} URLs salvas em {arquivo_urls}")

# ==== DOWNLOAD DOS ARQUIVOS ====
print("[+] Baixando arquivos com wget...")
for url in urls_filtradas:
    try:
        nome_arquivo = urlparse(url).path.split('/')[-1]
        if any(sensivel in nome_arquivo for sensivel in ['.env', '.log', '.bak', '.old', '.zip', '.conf', '.sql', '.xml', '.txt']):
            destino = pasta_sensiveis / nome_arquivo
        else:
            destino = pasta_downloads / nome_arquivo
        subprocess.run(["wget", "-q", url, "-O", str(destino)])
    except Exception as e:
        print(f"[!] Erro ao baixar {url}: {e}")

# ==== BUSCA POR DADOS SENSIVEIS ====
print("[+] Varredura por dados sensiveis nos arquivos baixados...")
with open(arquivo_resultados, 'w') as saida:
    for pasta in [pasta_downloads, pasta_sensiveis]:
        for arquivo in pasta.glob("*"):
            try:
                conteudo = arquivo.read_text(errors='ignore')
                for nome, padrao in regex_sensiveis.items():
                    encontrados = re.findall(padrao, conteudo)
                    if encontrados:
                        saida.write(f"[+] {nome} encontrado em {arquivo}:")
                        for achado in encontrados:
                            saida.write(f"\n    - {achado}")
                        saida.write("\n\n")
            except Exception as e:
                print(f"[!] Erro ao ler {arquivo}: {e}")

print(f"[+] Varredura completa. Resultados salvos em: {arquivo_resultados}")
