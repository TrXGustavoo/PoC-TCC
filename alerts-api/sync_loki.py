import urllib.request
import urllib.parse
import json
import time
import uuid
import ipaddress
import requests
import chromadb

print("Iniciando sincronização inteligente entre Loki e ChromaDB dentro do container...")

# 1. Conexão ao ChromaDB
chroma_client = chromadb.HttpClient(host="chromadb", port=8000)
col = chroma_client.get_or_create_collection("honeypot_attacks")
total_inicial = col.count()
print(f"Total de registros atuais no ChromaDB: {total_inicial}")

# Obter IDs e IPs existentes para não duplicar
dados_existentes = col.get(limit=1000)
chaves_existentes = set()
if dados_existentes and dados_existentes.get("metadatas"):
    for meta in dados_existentes["metadatas"]:
        if meta:
            ts = meta.get("timestamp", "")
            ip = meta.get("ip", "")
            ev = meta.get("evento", "")
            chaves_existentes.add(f"{ip}_{ts[:16]}_{ev}")

print(f"Chaves únicas já indexadas: {len(chaves_existentes)}")

# 2. Consultar o Loki para extrair incidentes críticos
url_query = "http://loki:3100/loki/api/v1/query_range"
start_ns = int(time.time() - 86400 * 14) * 1000000000
end_ns = int(time.time() + 3600) * 1000000000

params = urllib.parse.urlencode({
    "query": '{job="honeypot"} |~ "(?i)(login.success|command.input|file_download)"',
    "start": str(start_ns),
    "end": str(end_ns),
    "limit": 5000
})

req = urllib.request.urlopen(f"{url_query}?{params}", timeout=30)
data = json.loads(req.read().decode("utf-8"))
results = data.get("data", {}).get("result", [])

novos_candidatos = {}
if results:
    for stream in results:
        for ts_ns, line in stream.get("values", []):
            try:
                entry = json.loads(line)
                ip = entry.get("src_ip", "")
                sess = entry.get("session", "")
                ev = entry.get("eventid", "")
                ts = entry.get("timestamp", "")
                
                if not ip or ip in ("N/A", "Desconhecido"):
                    continue

                if ts and not ts.endswith("Z"):
                    ts_norm = ts + "Z"
                else:
                    ts_norm = ts
                
                chave = f"{ip}_{ts[:16]}_{ev}"
                if chave not in chaves_existentes and chave not in novos_candidatos:
                    novos_candidatos[chave] = (entry, ts_norm)
            except:
                pass

print(f"Novos incidentes candidatos para indexação: {len(novos_candidatos)}")

geoip_cache = {}
def obter_bandeira(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))
    except Exception:
        return "🌐"

def obter_geoip(ip: str) -> dict:
    if not ip or ip in ("N/A", "Desconhecido", "127.0.0.1", "localhost"):
        return {"pais": "Ambiente Local", "codigo_pais": "BR", "bandeira": "🏠", "cidade": "Rede Interna", "lat": -23.5505, "lon": -46.6333, "isp": "Localhost"}
    if ip in geoip_cache:
        return geoip_cache[ip]
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip.startswith("100."):
            info = {"pais": "Rede Privada / Tailscale", "codigo_pais": "BR", "bandeira": "🔒", "cidade": "VPN Tailscale", "lat": -23.5505, "lon": -46.6333, "isp": "Tailscale Mesh VPN"}
            geoip_cache[ip] = info
            return info
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org", timeout=2)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                cc = d.get("countryCode", "")
                info = {
                    "pais": d.get("country", "Desconhecido"),
                    "codigo_pais": cc,
                    "bandeira": obter_bandeira(cc),
                    "cidade": d.get("city", "N/A"),
                    "lat": float(d.get("lat", 0.0)),
                    "lon": float(d.get("lon", 0.0)),
                    "isp": d.get("isp") or d.get("org", "N/A")
                }
                geoip_cache[ip] = info
                return info
    except:
        pass
    info = {"pais": "Desconhecido", "codigo_pais": "", "bandeira": "🌐", "cidade": "N/A", "lat": 0.0, "lon": 0.0, "isp": "N/A"}
    geoip_cache[ip] = info
    return info

# Processar lote de até 300 incidentes para manter resposta imediata
itens_para_processar = list(novos_candidatos.items())[:300]
print(f"Processando lote de {len(itens_para_processar)} incidentes com embeddings semânticos...")

batch_ids = []
batch_embeddings = []
batch_documents = []
batch_metadatas = []

sucesso_count = 0
for i, (chave, (entry, ts_norm)) in enumerate(itens_para_processar):
    ip = entry.get("src_ip", "N/A")
    sess = entry.get("session", "N/A")
    ev = entry.get("eventid", "N/A")
    geo = obter_geoip(ip)
    
    if "command" in ev:
        cmd_text = entry.get("input", "")
        resumo = f"Comando invasor executado no shell: '{cmd_text}'."
        tatica = "Execution / Discovery (Comando Remoto)"
    elif "login" in ev:
        u = entry.get("username", "N/A")
        p = entry.get("password", "N/A")
        resumo = f"Autenticação bem-sucedida via força bruta com usuário '{u}' e senha '{p}'."
        tatica = "Initial Access / Credential Access"
    else:
        resumo = "Tentativa de download/transferência de payload malicioso."
        tatica = "Ingress Tool Transfer / Malware Payload"

    relatorio_ia = (
        f"🚨 Resumo do Incidente: {resumo}\n"
        f"🎯 Tática MITRE ATT&CK: {tatica}\n"
        f"⚠️ Nível de Ameaça: Crítico (Comprometimento da borda IoT)\n"
        f"🛡️ Ação de Mitigação: Bloquear IP {ip} no firewall perimetral e revogar credenciais."
    )

    texto_para_memoria = (
        f"Data: {ts_norm} | Evento: {ev} | IP: {ip} | "
        f"Origem: {geo['bandeira']} {geo['cidade']}, {geo['pais']} ({geo['isp']}) | Sessão: {sess}\n"
        f"Análise da IA: {relatorio_ia}"
    )

    # Obter vetor via Ollama nomic-embed-text
    try:
        resp_embed = requests.post("http://ollama_tcc:11434/api/embeddings", json={"model": "nomic-embed-text", "prompt": texto_para_memoria}, timeout=5)
        if resp_embed.status_code == 200:
            vetor = resp_embed.json().get("embedding")
        else:
            vetor = None
    except:
        vetor = None

    if vetor:
        doc_id = str(uuid.uuid4())
        batch_ids.append(doc_id)
        batch_embeddings.append(vetor)
        batch_documents.append(texto_para_memoria)
        batch_metadatas.append({
            "ip": ip,
            "evento": ev,
            "timestamp": ts_norm[:19],
            "pais": geo.get("pais", ""),
            "cidade": geo.get("cidade", ""),
            "isp": geo.get("isp", ""),
            "bandeira": geo.get("bandeira", "🌐"),
            "lat": geo.get("lat", 0.0),
            "lon": geo.get("lon", 0.0)
        })
        sucesso_count += 1

    if (i + 1) % 50 == 0:
        print(f"  Vetorizados {i + 1}/{len(itens_para_processar)}...")

if batch_ids:
    col.add(
        ids=batch_ids,
        embeddings=batch_embeddings,
        documents=batch_documents,
        metadatas=batch_metadatas
    )
    print(f"✅ Inseridos com sucesso {len(batch_ids)} novos incidentes no ChromaDB!")

print(f"Total final consolidado no ChromaDB: {col.count()}")
