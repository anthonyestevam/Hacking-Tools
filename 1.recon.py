import subprocess
import socket
import requests
from OpenSSL import crypto
import nmap
import re
import os
from Wappalyzer import Wappalyzer, WebPage

# Padrões aprimorados para identificar URLs específicas
ssti_patterns = re.compile(r"({{.*?}}|{%.+?%}|<%=.+?%>|#{.+?}|@.+?)")  # SSTI/CSTI
idor_patterns = re.compile(r"(id=\d+|user_id=\d+|account_id=\d+|order_id=\d+|profile_id=\d+|document_id=\d+|page_id=\d+|record_id=\d+|item_id=\d+|pid=\d+|uid=\d+)")  # IDOR
api_patterns = re.compile(r"(/api/|/v1/|/v2/|/v\d+/|/graphql|/rest/)")  # API endpoints
ssrf_patterns = re.compile(r"(url=|uri=|redirect=|path=|src=|source=|dest=|destination=|next=|data=|callback=|out=|link=|to=)")  # SSRF/Path Traversal
file_inclusion_patterns = re.compile(r"(file=|filepath=|include=|document=|folder=|dir=|download=|path=|template=|inc=|page=|view=|style=|script=|resource=|module=|load=|content=)")  # LFI/RFI

# Função para coletar subdomínios
def collect_subdomains(domain):
    print("Coletando Subdomínios...")
    subdomains = set()

    try:
        # Subfinder
        subfinder_output = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
        subdomains.update(subfinder_output.stdout.splitlines())

        # Amass
        amass_output = subprocess.run(['amass', 'enum', '-d', domain], capture_output=True, text=True)
        subdomains.update(amass_output.stdout.splitlines())

        # Quickcert (busca subdomínios nos certificados)
        quickcert_output = subprocess.run(['quickcert', domain], capture_output=True, text=True)
        subdomains.update(quickcert_output.stdout.splitlines())

        # DNS reverso para identificar subdomínios adicionais
        try:
            ip = socket.gethostbyname(domain)
            reversed_dns = socket.gethostbyaddr(ip)
            subdomains.add(reversed_dns[0])
            print(f"Subdomínio via DNS reverso encontrado: {reversed_dns[0]}")
        except Exception as e:
            print(f"Erro ao fazer DNS reverso para {domain}: {e}")

    except Exception as e:
        print(f"Erro na coleta de subdomínios: {e}")

    return list(subdomains)

# Função para resolver IPs de subdomínios e escanear portas
def resolve_ips_and_scan_ports(subdomains):
    print("Resolvendo IPs e Escaneando Portas...")
    nm = nmap.PortScanner()
    ip_ports = {}

    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            ip_ports[ip] = []

            # Scanning portas abertas
            print(f"Escaneando portas para {ip}...")
            nm.scan(ip, '1-65535')
            for protocol in nm[ip].all_protocols():
                ip_ports[ip].extend(nm[ip][protocol].keys())

        except Exception as e:
            print(f"Erro ao resolver IP ou escanear portas para {subdomain}: {e}")

    return ip_ports

# Função aprimorada para coletar tecnologias e versões
def collect_technologies(ip_ports):
    print("Coletando Tecnologias e Versões de Serviços...")
    tech_info = {}
    wappalyzer = Wappalyzer.latest()

    for ip in ip_ports:
        tech_info[ip] = []

        for port in ip_ports[ip]:
            try:
                url = f"http://{ip}:{port}"
                webpage = WebPage.new_from_url(url)
                technologies = wappalyzer.analyze(webpage)

                # Adiciona as tecnologias detectadas junto com a versão (se disponível)
                for tech, details in technologies.items():
                    version = details[0].get("version") if details[0].get("version") else "Versão desconhecida"
                    tech_info[ip].append((port, tech, version))

            except Exception as e:
                print(f"Erro ao coletar tecnologias para {ip}:{port} - {e}")

    return tech_info

# Função para classificar URLs para possíveis vulnerabilidades
def classify_urls(urls):
    print("Classificando URLs para Vulnerabilidades Potenciais...")
    forbidden_urls = []
    possible_reflects = []
    possible_ssti_csti = []
    possible_idors = []
    api_endpoints = []
    possible_ssrf_path_traversal = []
    possible_file_inclusion = []

    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            
            # Salva URLs com código 403
            if response.status_code == 403:
                forbidden_urls.append(url)

            # Verifica possíveis reflexões
            if any(param in response.text for param in url.split("?")[1:]):
                possible_reflects.append(url)

            # Verifica possíveis vulnerabilidades SSTI/CSTI
            if ssti_patterns.search(url):
                possible_ssti_csti.append(url)

            # Verifica possíveis vulnerabilidades IDOR
            if idor_patterns.search(url):
                possible_idors.append(url)

            # Verifica possíveis endpoints de API
            if api_patterns.search(url):
                api_endpoints.append(url)

            # Verifica possíveis vulnerabilidades SSRF/Path Traversal
            if ssrf_patterns.search(url):
                possible_ssrf_path_traversal.append(url)

            # Verifica possíveis vulnerabilidades LFI/RFI
            if file_inclusion_patterns.search(url):
                possible_file_inclusion.append(url)

        except requests.RequestException:
            pass

    return {
        "403": forbidden_urls,
        "reflects": possible_reflects,
        "ssti_csti": possible_ssti_csti,
        "idors": possible_idors,
        "apis": api_endpoints,
        "ssrf_path_traversal": possible_ssrf_path_traversal,
        "file_inclusion": possible_file_inclusion
    }

# Função para coletar URLs usando ferramentas de fuzzing
def collect_urls(subdomains):
    print("Coletando URLs usando Waybackurls, Katana, Gau e GauPlus...")
    urls = set()

    for subdomain in subdomains:
        try:
            # Waybackurls
            wayback_output = subprocess.run(['waybackurls', subdomain], capture_output=True, text=True)
            urls.update(wayback_output.stdout.splitlines())

            # Katana
            katana_output = subprocess.run(['katana', '-u', subdomain], capture_output=True, text=True)
            urls.update(katana_output.stdout.splitlines())

            # Gau
            gau_output = subprocess.run(['gau', subdomain], capture_output=True, text=True)
            urls.update(gau_output.stdout.splitlines())

            # GauPlus
            gauplus_output = subprocess.run(['gauplus', subdomain], capture_output=True, text=True)
            urls.update(gauplus_output.stdout.splitlines())

        except Exception as e:
            print(f"Erro ao coletar URLs para {subdomain}: {e}")

    return list(urls)

# Exemplo de execução de todas as etapas
def main(domain):
    print(f"Iniciando Recon para o domínio: {domain}")

    # Coleta de subdomínios
    subdomains = collect_subdomains(domain)
    with open("subs.txt", "w") as f:
        f.write("\n".join(subdomains))

    # Resolução de IPs e escaneamento de portas
    ip_ports = resolve_ips_and_scan_ports(subdomains)
    with open("ips.txt", "w") as f:
        for ip, ports in ip_ports.items():
            f.write(f"{ip}: {', '.join(map(str, ports))}\n")

    # Coleta de tecnologias e versões de serviços
    tech_info = collect_technologies(ip_ports)
    with open("tech.txt", "w") as f:  # Alterado para salvar em tech.txt
        for ip, services in tech_info.items():
            for port, tech, version in services:
                f.write(f"{ip}:{port} - {tech} {version}\n")

    # Coleta de URLs usando fuzzing
    urls = collect_urls(subdomains)
    with open("urls.txt", "w") as f:  # Salva todas as URLs em urls.txt
        f.write("\n".join(urls))

    # Classificação de URLs para possíveis vulnerabilidades
    classified_urls = classify_urls(urls)

    # Salvando resultados em arquivos específicos
    for name, url_list in classified_urls.items():
        with open(f"{name}.txt", "w") as f:
            f.write("\n".join(url_list))

    print("Recon Completo!")

# Exemplo de execução
domain = input("Domain: ")
main(domain)
