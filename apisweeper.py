import requests
import re
import time
from urllib.parse import urljoin

# Padrões regex para dados sensíveis
regex_patterns = {
    "API Key": r"(?i)(api_key|apikey|token|secret)[=:\"']\s*([a-zA-Z0-9\-_]+)",
    "JWT Token": r"eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
    "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key['\":=\s]*([A-Za-z0-9/+=]{40})",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "IP Address": r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP|EC) PRIVATE KEY-----"
}

# Headers de segurança esperados
security_headers = ["Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"]

# Função para testar cada endpoint
def test_endpoint(url):
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    results = []

    for method in methods:
        try:
            # Faz a requisição
            response = requests.request(method, url, timeout=5)
            print(f"Testing {method} {url} - Status: {response.status_code}")

            # Teste de Autenticação e Autorização
            if response.status_code == 200:
                results.append(f"[+] {method} {url} acessível sem autenticação.")

            # Teste de headers de segurança
            for header in security_headers:
                if header not in response.headers:
                    results.append(f"[-] Header de segurança ausente: {header}")

            # Procura por dados sensíveis na resposta
            for pattern_name, pattern in regex_patterns.items():
                if re.search(pattern, response.text):
                    results.append(f"[-] Possível {pattern_name} exposto em {method} {url}")

            # Teste de permissão excessiva em métodos inseguros
            if method in ["PUT", "DELETE"] and response.status_code == 200:
                results.append(f"[-] Permissão indevida para {method} em {url}")

            # Testa presença de mensagens de erro detalhadas
            if "exception" in response.text.lower() or "error" in response.text.lower():
                results.append(f"[-] Mensagem de erro detalhada exposta em {method} {url}")

            # Teste de Rate Limiting
            rate_limit_result = test_rate_limit(url, method)
            if rate_limit_result:
                results.append(rate_limit_result)

        except requests.RequestException as e:
            print(f"[!] Erro ao acessar {method} {url}: {e}")

    return results

# Função para testar rate limit em um endpoint
def test_rate_limit(url, method):
    try:
        # Envia múltiplas requisições em sequência
        for i in range(5):
            response = requests.request(method, url, timeout=3)
            time.sleep(0.2)  # Intervalo para evitar que pareça um ataque

            # Checa se o status muda para 429 (Too Many Requests) ou similar
            if response.status_code == 429:
                return f"[+] Rate limiting ativado para {method} {url} após {i + 1} requisições."

    except requests.RequestException as e:
        return f"[!] Erro ao testar rate limit: {e}"

    return "[-] Vulnerabilidade de No Rate Limit detectada."

# Função principal para processar as URLs do arquivo
def main(file_path):
    with open(file_path, "r") as file:
        urls = file.read().splitlines()

    print(f"Iniciando teste de vulnerabilidades para APIs do arquivo: {file_path}\n")
    all_vulnerabilities = []

    for url in urls:
        print(f"\nTesting endpoint: {url}")
        results = test_endpoint(url)
        all_vulnerabilities.extend(results)

    print("\n[Relatório de Vulnerabilidades Encontradas]")
    for vuln in all_vulnerabilities:
        print(vuln)

if __name__ == "__main__":
    file_path = input("API URLs File: ")
    main(file_path)
