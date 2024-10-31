import requests
import dns.resolver

# Cores para terminal
class Colors:
    GREEN = '\033[92m'  # Verde
    RED = '\033[91m'    # Vermelho
    YELLOW = '\033[93m'  # Amarelo
    RESET = '\033[0m'   # Resetar cor

# Função para verificar se o subdomínio está ativo
def check_subdomain(subdomain):
    try:
        result = dns.resolver.resolve(subdomain, 'A')
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False

# Função para verificar se o subdomínio pode ser tomado
def check_takeover(subdomain):
    urls_to_check = [f"http://{subdomain}", f"https://{subdomain}"]
    for url in urls_to_check:
        try:
            response = requests.get(url, timeout=5)
            # Verifica se a resposta é 404 e analisa o conteúdo
            if response.status_code == 404 or "not found" in response.text.lower():
                # Adiciona uma verificação de conteúdo
                if "error" not in response.text.lower() and "not found" in response.text.lower():
                    return True  # O subdomínio existe, mas não está ativo
        except requests.RequestException:
            continue  # Ignora erros de conexão

    return False

# Função principal para verificar subdomínios
def main(subdomain_list):
    print("Verificando subdomínios...\n")

    for full_subdomain in subdomain_list:
        print(f"Verificando: {full_subdomain}")

        if not check_subdomain(full_subdomain):
            print(f"{Colors.RED}[!] Subdomínio não encontrado: {full_subdomain}{Colors.RESET}")
            continue

        if check_takeover(full_subdomain):
            print(f"{Colors.GREEN}[+] Vulnerabilidade de Subdomain Takeover encontrada em: {full_subdomain}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[-] Subdomínio ativo: {full_subdomain}{Colors.RESET}")

if __name__ == "__main__":
    subdomain_file = input("Subdomains File: ")

    try:
        with open(subdomain_file, "r") as file:
            subdomains = file.read().splitlines()
            # Remove espaços em branco e formata os subdomínios
            subdomains = [sub.strip() for sub in subdomains if sub.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[Erro] Arquivo não encontrado: {subdomain_file}. Verifique o caminho e tente novamente.{Colors.RESET}")
        exit(1)

    main(subdomains)
