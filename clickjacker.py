import requests

# Cores para terminal
class Colors:
    GREEN = '\033[92m'  # Verde
    BLUE = '\033[94m'   # Azul
    RED = '\033[91m'    # Vermelho
    RESET = '\033[0m'   # Resetar cor

# Cabeçalhos a serem verificados
SECURITY_HEADERS = [
    'X-Frame-Options',
    'Content-Security-Policy'
]

# Palavras-chave que indicam áreas de risco
RISKY_ENDPOINTS = [
    "config",
    "user",
    "admin",
    "settings",
    "profile",
    "dashboard",
    "account",
    "login",
    "logout",
    "register",
    "signup",
    "reset",
    "forgot",
    "change",
    "edit",
    "update",
    "delete",
    "manage",
    "access",
    "api",
    "token",
    "credential",
    "session",
    "billing",
    "payment",
    "invoice",
    "report",
    "notification",
    "activity",
    "history",
    "validation",
    "search"
]

def is_risky_endpoint(url):
    """Verifica se a URL contém palavras-chave que indicam uma área de risco."""
    return any(keyword in url for keyword in RISKY_ENDPOINTS)

def check_clickjacking(url):
    try:
        response = requests.get(url, timeout=5)
        missing_headers = []

        # Verificando se os cabeçalhos de segurança estão presentes
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                missing_headers.append(header)

        # Avaliando a vulnerabilidade
        if missing_headers:
            print(f"{Colors.GREEN}[!] Vulnerabilidade de Clickjacking detectada em {url}. Falta os cabeçalhos: {', '.join(missing_headers)}{Colors.RESET}")
        else:
            print(f"[+] {url} está protegido contra Clickjacking.")
    except requests.RequestException as e:
        print(f"{Colors.RED}[!] Erro ao acessar {url}: {e}{Colors.RESET}")

def main(file_path):
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Colors.RED}[Erro] Arquivo não encontrado: {file_path}. Verifique o caminho e tente novamente.{Colors.RESET}")
        return

    print(f"{Colors.BLUE}Iniciando verificação de Clickjacking nas URLs do arquivo: {file_path}\n{Colors.RESET}")

    for url in urls:
        if is_risky_endpoint(url):
            print(f"{Colors.BLUE}Verificando URL de risco: {url}{Colors.RESET}")
            check_clickjacking(url)
        else:
            print(f"{Colors.BLUE}[!] URL não considerada de risco, ignorada: {url}{Colors.RESET}")

if __name__ == "__main__":
    file_path = input("URLs File: ")
    main(file_path)
