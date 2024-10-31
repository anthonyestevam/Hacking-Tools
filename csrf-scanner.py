import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Cores para terminal
class Colors:
    GREEN = '\033[92m'  # Verde
    RED = '\033[91m'    # Vermelho
    YELLOW = '\033[93m'  # Amarelo
    RESET = '\033[0m'   # Resetar cor

SECURITY_HEADERS = [
    'X-Frame-Options',
    'Content-Security-Policy'
]

def check_csrf(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            print(f"{Colors.YELLOW}[!] Nenhum formulário encontrado em {url}.{Colors.RESET}")
            return

        csrf_found = False
        for form in forms:
            inputs = form.find_all('input')
            # Verifica se existe um campo de token CSRF
            for input_field in inputs:
                if 'csrf' in input_field.get('name', '').lower() or 'token' in input_field.get('name', '').lower():
                    csrf_found = True
                    break

            if csrf_found:
                print(f"[+] {url} está protegido contra CSRF. Token CSRF encontrado.")
                break
        else:
            print(f"{Colors.GREEN}[+] Vulnerabilidade CSRF detectada em {url}. Nenhum token CSRF encontrado nos formulários.{Colors.RESET}")

        # Verifica se o cookie tem o atributo SameSite
        cookies = response.cookies
        for cookie in cookies:
            if cookie.secure is False:
                print(f"{Colors.RED}[!] Cookie não é seguro em {url}.{Colors.RESET}")
            if not cookie.has_nonstandard_attr('SameSite'):
                print(f"{Colors.RED}[!] Cookie sem atributo SameSite em {url}.{Colors.RESET}")

    except requests.RequestException as e:
        print(f"{Colors.RED}[!] Erro ao acessar {url}: {e}{Colors.RESET}")

def check_csrf_on_methods(url, method='POST'):
    """Verifica o endpoint usando o método especificado (GET, POST, PUT, DELETE)."""
    data = {'test_key': 'test_value'}  # Payload para POST/PUT
    try:
        if method.upper() == 'POST':
            response = requests.post(url, data=data, timeout=5)
        elif method.upper() == 'PUT':
            response = requests.put(url, data=data, timeout=5)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, timeout=5)
        else:
            response = requests.get(url, timeout=5)

        response.raise_for_status()
        print(f"[+] Método {method} em {url} executado com sucesso.")
    except requests.RequestException as e:
        print(f"{Colors.RED}[!] Erro ao testar {method} em {url}: {e}{Colors.RESET}")

def main(file_path):
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Colors.RED}[Erro] Arquivo não encontrado: {file_path}. Verifique o caminho e tente novamente.{Colors.RESET}")
        return

    print(f"Iniciando verificação de CSRF nas URLs do arquivo: {file_path}\n")

    for url in urls:
        print(f"Verificando URL: {url}")
        check_csrf(url)

        # Verificando métodos adicionais
        for method in ['POST', 'PUT', 'DELETE']:
            check_csrf_on_methods(url, method)

if __name__ == "__main__":
    file_path = input("URLs File: ")
    main(file_path)
