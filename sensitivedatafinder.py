import requests
import re
import base64
from concurrent.futures import ThreadPoolExecutor

# Expressões regulares para procurar dados sensíveis
regex_patterns = {
    "API Key": r"(?i)(api_key|apikey|key|token)[=:\"']\s*([a-zA-Z0-9\-_]+)",
    "Database Credentials": r"(DB_USER|DB_PASS|DB_NAME|DB_HOST)[=:\"']\s*([a-zA-Z0-9\-_]+)",
    "JWT Token": r"eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
    "Email Addresses": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key['\":=\s]*([A-Za-z0-9/+=]{40})",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Firebase Database URL": r"https:\/\/[a-z0-9-]+\.firebaseio\.com",
    "Google Cloud Service Account": r"\"type\": \"service_account\"",
    "IP Address": r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP|EC) PRIVATE KEY-----",
    "Debug Info": r"(debug|DEBUG|Debug)[\s:=]+(true|1)",
    "Passwords": r"(password|passwd|pwd|secret)[=:\"']\s*([a-zA-Z0-9\-_]+)",
    "Base64 Encoded Strings": r"\b[a-zA-Z0-9+/]{40,}={0,2}\b",
    "Git Exposed": r"\.git/",  # Verifica se há indícios de um diretório .git exposto
    "MongoDB URI": r"mongodb(\+srv)?:\/\/[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_]+@",
    "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
    "Heroku API Key": r"[hH]eroku['\"_]?[\s:=]+([a-zA-Z0-9]{32})",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Facebook OAuth": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Square OAuth": r"sq0atp-[0-9A-Za-z-_]{22}",
    "SSH Key": r"ssh-rsa AAA[0-9A-Za-z+/]+[=]{0,3} [a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+"
}

# Função para verificar cada URL
def analyze_url(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            content = response.text
            print(f"\n[+] Analisando {url}")
            for pattern_name, pattern in regex_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    print(f"  [-] {pattern_name} encontrado:")
                    for match in matches:
                        # Tratamento especial para strings em Base64
                        if pattern_name == "Base64 Encoded Strings":
                            decoded = try_decode_base64(match)
                            print(f"    * {match} (Decodificado: {decoded})")
                        else:
                            print(f"    * {match}")
        elif response.status_code == 403:
            print(f"[!] Acesso proibido para {url} (Status: 403).")
        else:
            print(f"[!] Não foi possível acessar {url} (Status: {response.status_code})")
    except requests.RequestException as e:
        print(f"[!] Erro ao acessar {url}: {e}")

# Função para tentar decodificar Base64
def try_decode_base64(encoded_string):
    try:
        decoded_bytes = base64.b64decode(encoded_string, validate=True)
        decoded_string = decoded_bytes.decode('utf-8').strip()
        return decoded_string
    except (base64.binascii.Error, UnicodeDecodeError):
        return "Não foi possível decodificar"

# Função principal
def main():
    file_name = input("URLs File: ")
    try:
        with open(file_name, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
            
        print(f"[+] {len(urls)} URLs carregadas do arquivo.")

        # Usar threading para acelerar a análise das URLs
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(analyze_url, urls)

    except FileNotFoundError:
        print("[!] Arquivo não encontrado. Verifique o nome e tente novamente.")

if __name__ == "__main__":
    main()
