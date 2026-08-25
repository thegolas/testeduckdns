import os
import urllib.request
import json
import re

# Lê as variáveis passadas pelo GitHub Actions
AZION_PERSONAL_TOKEN = os.environ.get("AZION_PERSONAL_TOKEN")
AZION_NETWORK_LIST_ID = os.environ.get("AZION_NETWORK_LIST_ID")
GITHUB_RAW_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

def parse_ip_list(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        content = response.read().decode('utf-8')
    
    ip_list = []
    ip_pattern = re.compile(r'^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/[0-9]{1,2})?)\s*$')
    
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            match = ip_pattern.match(line)
            if match:
                ip_list.append(match.group(1))
                
    return list(dict.fromkeys(ip_list))

def update_azion_network_list(token, list_id, items):
    url = f"https://api.azionapi.net/network_lists/{list_id}"
    headers = {
        "Accept": "application/json; version=3",
        "Content-Type": "application/json",
        "Authorization": f"Token {token}"
    }
    payload = {"items_values": items}
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='PUT')
    
    try:
        with urllib.request.urlopen(req) as response:
            if response.status in [200, 201]:
                print(f"Sucesso! Network List {list_id} atualizada com {len(items)} itens.")
            else:
                print(f"Erro na API da Azion: Status {response.status}")
    except urllib.error.HTTPError as e:
        print(f"Falha na requisição: {e.code} - {e.read().decode('utf-8')}")

if __name__ == "__main__":
    if not AZION_PERSONAL_TOKEN or not AZION_NETWORK_LIST_ID:
        raise ValueError("As variáveis de ambiente da Azion não foram encontradas!")
        
    print("Baixando lista de IPs do GitHub...")
    ips = parse_ip_list(GITHUB_RAW_URL)
    
    if ips:
        print(f"Extraídos {len(ips)} IPs/CIDRs válidos. Atualizando a Azion...")
        update_azion_network_list(AZION_PERSONAL_TOKEN, AZION_NETWORK_LIST_ID, ips)
    else:
        print("Nenhum IP foi encontrado.")
