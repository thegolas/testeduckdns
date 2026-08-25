import os
import urllib.request
import json
import re

AZION_PERSONAL_TOKEN = os.environ.get("AZION_PERSONAL_TOKEN")
AZION_NETWORK_LIST_ID = os.environ.get("AZION_NETWORK_LIST_ID")

# Feed público com IPs/CIDRs maliciosos
GITHUB_RAW_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset"

def parse_ip_list(url):
    """Baixa a lista e extrai endereços IP e sub-redes CIDR válidas."""
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
    """Atualiza a Network List enviando os campos obrigatórios para a Azion."""
    url = f"https://api.azionapi.net/network_lists/{list_id}"
    headers = {
        "Accept": "application/json; version=3",
        "Content-Type": "application/json",
        "Authorization": f"Token {token}"
    }
    
    # 1. Faz GET para resgatar os metadados atuais (Nome e Tipo) da lista
    req_get = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req_get) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            current_name = res_data.get('results', {}).get('name', 'GitHub List')
            current_type = res_data.get('results', {}).get('list_type', 'ip_cidr')
    except Exception as e:
        print(f"Aviso: Não foi possível ler metadados existentes, usando padrões. Detalhe: {e}")
        current_name = "GitHub List"
        current_type = "ip_cidr"

    # 2. Payload completo contendo name, list_type e os novos items
    payload = {
        "name": current_name,
        "list_type": current_type,
        "items_values": items
    }
    
    data = json.dumps(payload).encode('utf-8')
    req_put = urllib.request.Request(url, data=data, headers=headers, method='PUT')
    
    try:
        with urllib.request.urlopen(req_put) as response:
            if response.status in [200, 201]:
                print(f"✅ Sucesso! Network List '{current_name}' (ID {list_id}) atualizada com {len(items)} itens na Azion.")
            else:
                print(f"⚠️ Resposta da API da Azion: Status {response.status}")
    except urllib.error.HTTPError as e:
        print(f"❌ Falha na requisição API Azion: {e.code} - {e.read().decode('utf-8')}")

if __name__ == "__main__":
    if not AZION_PERSONAL_TOKEN or not AZION_NETWORK_LIST_ID:
        raise ValueError("Variáveis de ambiente AZION_PERSONAL_TOKEN ou AZION_NETWORK_LIST_ID não foram fornecidas!")
        
    print("Baixando lista de IPs do GitHub...")
    ips = parse_ip_list(GITHUB_RAW_URL)
    
    if ips:
        print(f"Extraídos {len(ips)} IPs/CIDRs válidos.")
        # Limita aos primeiros 1.000 itens para não estourar payload
        items_to_send = ips[:1000]
        print(f"Enviando {len(items_to_send)} itens para a Azion...")
        update_azion_network_list(AZION_PERSONAL_TOKEN, AZION_NETWORK_LIST_ID, items_to_send)
    else:
        print("Nenhum IP foi encontrado na lista fornecida.")
