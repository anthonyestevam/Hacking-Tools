import requests
from colorama import Fore, Style
import sys

# Defina a quantidade de cookies e tamanho de cada cookie
NUM_COOKIES = 100
COOKIE_SIZE = 4000  # em bytes

def load_domains(file_path):
    """Carrega os domínios e subdomínios a partir de um arquivo .txt"""
    try:
        with open(file_path, "r") as file:
            domains = [line.strip() for line in file if line.strip()]
        return domains
    except FileNotFoundError:
        print("Arquivo não encontrado. Verifique o caminho.")
        sys.exit(1)

def test_cookie_bomb(domain):
    """Testa o domínio para vulnerabilidade de Cookie Bomb"""
    # Configuração dos cookies para o teste
    cookies = {f"cookie{i}": "A" * COOKIE_SIZE for i in range(NUM_COOKIES)}
    
    try:
        # Envia a requisição com os cookies criados
        response = requests.get(f"http://{domain}", cookies=cookies, timeout=5)
        
        # Avalia a resposta do servidor
        if response.status_code == 200:
            print(Fore.GREEN + f"[Vulnerável] {domain} aceitou todos os cookies.")
        else:
            print(Fore.YELLOW + f"[Possivelmente Seguro] {domain} respondeu com o código {response.status_code}.")
    
    except requests.RequestException as e:
        print(Fore.RED + f"[Erro] {domain} - Falha ao conectar ({e}).")

if __name__ == "__main__":
    # Solicita o caminho do arquivo com os domínios
    file_path = input("Domains File: ")
    
    # Carrega os domínios do arquivo
    domains = load_domains(file_path)
    print(f"\nTestando {len(domains)} domínios para vulnerabilidade de Cookie Bomb...\n")
    
    # Testa cada domínio individualmente
    for domain in domains:
        test_cookie_bomb(domain)

    print(Style.RESET_ALL + "\nTeste concluído.")
