import requests
import re

# Cores para terminal
class Colors:
    GREEN = '\033[92m'  # Verde
    RED = '\033[91m'    # Vermelho
    YELLOW = '\033[93m'  # Amarelo
    RESET = '\033[0m'   # Resetar cor

# Função para validar a URL
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// ou https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Domínio
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
        r'(?::\d+)?'  # Porta
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Função para gerar IDs personalizados
def generate_custom_ids(base_id, range_size=10):
    """Gera uma lista de IDs personalizados com base no ID base."""
    return list(range(max(1, base_id - 5), base_id + range_size))

# Função para extrair IDs de parâmetros de URL
def extract_ids_from_url(url):
    """Extrai IDs da URL. Supondo que os IDs sejam numéricos."""
    ids = re.findall(r'([?&])([^=]+)=(\d+)', url)
    return [int(id_match[2]) for id_match in ids]

# Função para testar URLs e identificar IDOR em GET e POST
def test_idor(urls):
    for url in urls:
        if not is_valid_url(url):
            print(f"{Colors.RED}[!] URL inválida: {url}{Colors.RESET}")
            continue
        
        print(f"Verificando: {url}")

        # Extrai IDs da URL
        base_ids = extract_ids_from_url(url)
        if not base_ids:
            print(f"{Colors.YELLOW}[-] Nenhum ID encontrado na URL: {url}{Colors.RESET}")
            continue

        for base_id in base_ids:
            test_ids = generate_custom_ids(base_id)  # Gera IDs baseados no ID encontrado

            # Teste de IDOR usando GET
            for test_id in test_ids:
                modified_url = url.replace(str(base_id), str(test_id))  # Substitui o ID na URL
                try:
                    response = requests.get(modified_url, timeout=5)

                    if response.status_code == 200:
                        if "dados esperados" in response.text.lower():  # Ajuste conforme necessário
                            print(f"{Colors.GREEN}[+] Acesso autorizado com ID {test_id} (GET) em: {modified_url}{Colors.RESET}")
                        else:
                            print(f"{Colors.YELLOW}[-] Acesso com ID {test_id} (GET) em: {modified_url}, mas não contém dados esperados.{Colors.RESET}")

                    elif response.status_code == 403:
                        print(f"{Colors.YELLOW}[-] Acesso negado com ID {test_id} (GET) em: {modified_url}{Colors.RESET}")
                    elif response.status_code == 404:
                        print(f"{Colors.RED}[!] ID não encontrado: {test_id} (GET) em: {modified_url}{Colors.RESET}")

                except requests.RequestException as e:
                    print(f"{Colors.RED}[Erro] Não foi possível acessar {modified_url}: {e}{Colors.RESET}")

            # Teste de IDOR usando POST
            if "id=" in url:
                post_data = {key: value for key, value in re.findall(r'([a-zA-Z0-9_]+)=([^&]*)', url)}  # Extraí dados da URL
                for test_id in test_ids:
                    for param in base_ids:
                        post_data[param] = str(test_id)  # Modifica o ID nos dados do POST
                    try:
                        response = requests.post(url, data=post_data, timeout=5)

                        if response.status_code == 200:
                            if "dados esperados" in response.text.lower():  # Ajuste conforme necessário
                                print(f"{Colors.GREEN}[+] Acesso autorizado com ID {test_id} (POST) em: {url}{Colors.RESET}")
                            else:
                                print(f"{Colors.YELLOW}[-] Acesso com ID {test_id} (POST) em: {url}, mas não contém dados esperados.{Colors.RESET}")

                        elif response.status_code == 403:
                            print(f"{Colors.YELLOW}[-] Acesso negado com ID {test_id} (POST) em: {url}{Colors.RESET}")
                        elif response.status_code == 404:
                            print(f"{Colors.RED}[!] ID não encontrado: {test_id} (POST) em: {url}{Colors.RESET}")

                    except requests.RequestException as e:
                        print(f"{Colors.RED}[Erro] Não foi possível acessar {url}: {e}{Colors.RESET}")

def main():
    url_file = input("URLs File: ")
    
    try:
        with open(url_file, "r") as file:
            urls = file.read().splitlines()
            urls = [url.strip() for url in urls if url.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[Erro] Arquivo não encontrado: {url_file}. Verifique o caminho e tente novamente.{Colors.RESET}")
        exit(1)

    test_idor(urls)

if __name__ == "__main__":
    main()
