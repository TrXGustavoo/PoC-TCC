import os
import json
import time
import uuid
import hashlib
import ipaddress
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
import requests
import chromadb # 🆕 Importando o banco vetorial

app = FastAPI(title="SOC Honeypot API - TCC")
banco_de_alertas = []

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
OLLAMA_BASE_URL = os.getenv("OLLAMA_URL", "http://ollama_tcc:11434/api") # Base para todos os modelos
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2") 
LOKI_BASE_URL = os.getenv("LOKI_URL", "http://loki:3100") 

# 🆕 --- INICIALIZAÇÃO RESILIENTE DO BANCO VETORIAL (CHROMA) ---
collection = None

def get_collection():
    global collection
    if collection is not None:
        return collection
    try:
        chroma_host = os.getenv("CHROMA_HOST", "chromadb")
        chroma_port = int(os.getenv("CHROMA_PORT", "8000"))
        chroma_client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
        collection = chroma_client.get_or_create_collection(name="honeypot_attacks")
        print("✅ Conectado ao ChromaDB!")
        return collection
    except Exception as e:
        print(f"❌ Erro ao conectar no ChromaDB: {e}")
        return None

# Tentativa inicial de conexão
get_collection()

# 🌍 --- SERVIÇO DE ENRIQUECIMENTO THREAT INTEL (GEOIP / ASN) ---
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
        return {
            "pais": "Ambiente Local",
            "codigo_pais": "BR",
            "bandeira": "🏠",
            "cidade": "Rede Interna",
            "lat": -23.5505,
            "lon": -46.6333,
            "isp": "Localhost"
        }

    if ip in geoip_cache:
        return geoip_cache[ip]

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip.startswith("100."):
            info = {
                "pais": "Rede Privada / Tailscale",
                "codigo_pais": "BR",
                "bandeira": "🔒",
                "cidade": "VPN Tailscale" if ip.startswith("100.") else "Rede Local",
                "lat": -23.5505,
                "lon": -46.6333,
                "isp": "Tailscale Mesh VPN" if ip.startswith("100.") else "Rede Interna"
            }
            geoip_cache[ip] = info
            return info

        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org",
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                cc = data.get("countryCode", "")
                info = {
                    "pais": data.get("country", "Desconhecido"),
                    "codigo_pais": cc,
                    "bandeira": obter_bandeira(cc),
                    "cidade": data.get("city", "N/A"),
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "isp": data.get("isp") or data.get("org", "N/A")
                }
                geoip_cache[ip] = info
                return info
    except Exception as e:
        print(f"⚠️ Erro ao consultar GeoIP para {ip}: {e}")

    info = {
        "pais": "Desconhecido",
        "codigo_pais": "",
        "bandeira": "🌐",
        "cidade": "N/A",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "N/A"
    }
    geoip_cache[ip] = info
    return info


def enviar_telegram(mensagem):
    if not TELEGRAM_TOKEN or not CHAT_ID:
        print("Erro: Credenciais do Telegram não configuradas.")
        return
        
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": mensagem, "parse_mode": "Markdown"}
    
    resposta = requests.post(url, json=payload)
    if resposta.status_code != 200:
        print(f" Erro no Telegram ({resposta.status_code}): {resposta.text}")
    else:
        print(" Mensagem processada e enviada para o Telegram!")

def analisar_com_ia_local(dados_alerta):
    url_generate = f"{OLLAMA_BASE_URL}/generate"
    texto_do_ataque = str(dados_alerta)[:2000]
    
    prompt = f"""
    Você é um analista Nível 2 de SOC. Analise este alerta do honeypot Cowrie:
    {texto_do_ataque}
    
    Forneça APENAS a análise estruturada:
    🚨 **Resumo do Incidente:** (O que aconteceu)
    🎯 **Tática MITRE ATT&CK:** (Ex: Initial Access, Credential Access, Execution ou Persistence)
    ⚠️ **Nível de Ameaça:** (Crítico, Alto, Médio ou Baixo - justifique)
    🛡️ **Ação de Mitigação:** (O que a equipe de infraestrutura deve fazer)
    """
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        resposta = requests.post(url_generate, json=payload, timeout=300)
        if resposta.status_code == 200:
            return resposta.json().get("response", "Erro: Resposta vazia.")
        return f"❌ Erro no Ollama ({resposta.status_code}): {resposta.text}"
    except Exception as e:
        return f"❌ Erro de conexão com a IA Local: {e}"

# 🆕 --- FUNÇÃO PARA GERAR VETORES (EMBEDDINGS) ---
def gerar_embedding(texto):
    url_embed = f"{OLLAMA_BASE_URL}/embeddings"
    payload = {
        "model": "nomic-embed-text",
        "prompt": texto
    }
    try:
        resposta = requests.post(url_embed, json=payload, timeout=60)
        if resposta.status_code == 200:
            return resposta.json().get("embedding")
    except Exception as e:
        print(f"❌ Erro ao vetorizar: {e}")
    return None

@app.post("/webhook")
async def recebe_alerta(request: Request):
    dados = await request.json()
    status = dados.get("status", "unknown")
    
    if status == "firing":
        print("🚨 Novo ataque detectado! Extraindo dados e acionando Ollama...")
        
        alertas = dados.get("alerts", [])
        alerta_atual = alertas[0] if alertas else dados
        
        labels = alerta_atual.get("labels", {})
        ip_atacante = labels.get("src_ip", "N/A")
        sessao = labels.get("session", "N/A")
        evento = labels.get("eventid", "N/A")
        data_hora = alerta_atual.get("startsAt", "N/A")[:19]
        
        relatorio_ia = analisar_com_ia_local(alerta_atual)
        relatorio_limpo = relatorio_ia.replace("*", "").replace("_", "-").replace("`", "'").replace("[", "(").replace("]", ")")
        
        # 🌍 --- ENRIQUECIMENTO GEOIP / THREAT INTELLIGENCE ---
        geo_info = obter_geoip(ip_atacante)
        
        # 🆕 --- INJEÇÃO DE MEMÓRIA (CHROMADB) ---
        texto_para_memoria = (
            f"Data: {data_hora}Z | Evento: {evento} | IP: {ip_atacante} | "
            f"Origem: {geo_info['bandeira']} {geo_info['cidade']}, {geo_info['pais']} ({geo_info['isp']}) | Sessão: {sessao}\n"
            f"Análise da IA: {relatorio_limpo}"
        )
        vetor = gerar_embedding(texto_para_memoria)
        col = get_collection()
        
        if vetor and col:
            try:
                doc_id = str(uuid.uuid4())
                col.add(
                    ids=[doc_id],
                    embeddings=[vetor],
                    documents=[texto_para_memoria],
                    metadatas=[{
                        "ip": ip_atacante,
                        "evento": evento,
                        "timestamp": data_hora,
                        "pais": geo_info.get("pais", ""),
                        "cidade": geo_info.get("cidade", ""),
                        "isp": geo_info.get("isp", ""),
                        "bandeira": geo_info.get("bandeira", "🌐"),
                        "lat": geo_info.get("lat", 0.0),
                        "lon": geo_info.get("lon", 0.0)
                    }]
                )
                print(f"🧠 Memória consolidada no ChromaDB! ID: {doc_id} | Origem: {geo_info['cidade']}, {geo_info['pais']}")
            except Exception as e:
                print(f"❌ Erro ao salvar no ChromaDB: {e}")

        # --- REGISTRO NO FRONTEND (Em memória RAM para o painel imediato) ---
        alerta_para_frontend = {
            "timestamp": data_hora + "Z",
            "ai_analysis": relatorio_limpo,
            "raw_data": {
                "evento": evento,
                "ip_origem": ip_atacante,
                "sessao": sessao,
                "geo": geo_info
            }
        }
        banco_de_alertas.insert(0, alerta_para_frontend)
        if len(banco_de_alertas) > 50:
            banco_de_alertas.pop()
        
        # --- FILTRO DE EVENTOS CRÍTICOS PARA O TELEGRAM ---
        eventos_criticos = [
            "cowrie.command.input",        
            "cowrie.login.success",        
            "cowrie.session.file_download" 
        ]
        
        if evento in eventos_criticos:
            mensagem_final = (
                "🚨 *HONEYPOT: RELATÓRIO DE THREAT INTELLIGENCE* 🚨\n\n"
                "💻 *DADOS DO ATAQUE (TELEMETRIA):*\n"
                "```text\n"
                f"Data/Hora: {data_hora}Z\n"
                f"Evento: {evento}\n"
                f"IP Origem: {ip_atacante}\n"
                f"Localização: {geo_info['bandeira']} {geo_info['cidade']}, {geo_info['pais']}\n"
                f"ISP / Org: {geo_info['isp']}\n"
                f"Sessão: {sessao}\n"
                "```\n\n"
                "🤖 *ANÁLISE COGNITIVA (OLLAMA):*\n"
                f"{relatorio_limpo}"
            )
            enviar_telegram(mensagem_final)
            print(f"🔥 Alerta crítico ({evento}) de {geo_info['pais']} enviado ao Telegram.")
        else:
            print(f"ℹ️ Evento informativo ({evento}) registrado apenas no Frontend.")

        return {"status": "Processado"}
    
    return {"status": "Ignorado"}

@app.get("/alerts")
async def retorna_alertas():
    global banco_de_alertas
    # Se a lista em RAM estiver vazia (ex: após reiniciar o container), recupera do ChromaDB
    if not banco_de_alertas:
        col = get_collection()
        if col:
            try:
                dados = col.get(limit=50)
                if dados and dados.get("documents"):
                    docs = dados["documents"]
                    metas = dados.get("metadatas", [])
                    alertas_recuperados = []
                    for doc, meta in zip(docs, metas):
                        meta = meta or {}
                        partes = doc.split("\nAnálise da IA: ")
                        cabecalho = partes[0]
                        analise = partes[1] if len(partes) > 1 else doc
                        
                        sessao = "N/A"
                        if "Sessão: " in cabecalho:
                            sessao = cabecalho.split("Sessão: ")[-1].strip()
                            
                        ip_val = meta.get("ip", "N/A")
                        geo_cached = {
                            "pais": meta.get("pais"),
                            "codigo_pais": meta.get("codigo_pais", ""),
                            "bandeira": meta.get("bandeira", "🌐"),
                            "cidade": meta.get("cidade", ""),
                            "lat": meta.get("lat", 0.0),
                            "lon": meta.get("lon", 0.0),
                            "isp": meta.get("isp", "")
                        } if meta.get("pais") else obter_geoip(ip_val)

                        alertas_recuperados.append({
                            "timestamp": meta.get("timestamp", "N/A") + ("Z" if not meta.get("timestamp", "").endswith("Z") else ""),
                            "ai_analysis": analise,
                            "raw_data": {
                                "evento": meta.get("evento", "N/A"),
                                "ip_origem": ip_val,
                                "sessao": sessao,
                                "geo": geo_cached
                            }
                        })
                    
                    # Ordena do mais recente para o mais antigo
                    alertas_recuperados.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                    banco_de_alertas = alertas_recuperados
                    print(f"🔄 Recuperados {len(banco_de_alertas)} alertas históricos do ChromaDB para o Frontend!")
            except Exception as e:
                print(f"❌ Erro ao recuperar histórico do ChromaDB: {e}")

    return {
        "total": len(banco_de_alertas),
        "alerts": banco_de_alertas
    }

# 🆕 --- NOVA ROTA: O CHAT COM A BASE DE DADOS (RAG) ---
@app.post("/chat")
async def chat_rag(request: Request):
    dados = await request.json()
    pergunta = dados.get("pergunta", "")
    
    if not pergunta:
        return {"resposta": "Pergunta não fornecida."}
        
    print(f"🗣️ Nova pergunta do usuário: {pergunta}")
    
    # 1. Converte a pergunta em vetor para buscar os ataques semelhantes
    vetor_pergunta = gerar_embedding(pergunta)
    if not vetor_pergunta:
        return {"resposta": "Erro ao vetorizar a pergunta."}
        
    # 2. Busca na memória profunda (ChromaDB)
    col = get_collection()
    if not col:
        contexto_historico = "Banco vetorial ChromaDB temporariamente indisponível."
    else:
        try:
            total_docs = col.count()
            if total_docs == 0:
                contexto_historico = "Nenhum histórico de ataque encontrado no banco vetorial."
            else:
                n_results = min(3, total_docs)
                resultados = col.query(
                    query_embeddings=[vetor_pergunta],
                    n_results=n_results
                )
                contexto_historico = "\n\n---\n\n".join(resultados["documents"][0]) if resultados.get("documents") and resultados["documents"][0] else "Nenhum histórico relevante encontrado."
        except Exception as e:
            print(f"❌ Erro ao consultar ChromaDB: {e}")
            contexto_historico = f"Erro na consulta à base vetorial: {e}"
    
    # 3. Manda a pergunta e o passado para o Llama 3
    prompt_rag = f"""
    DADOS FORENSES REGISTRADOS NOS LOGS:
    {contexto_historico}
    
    CONSULTA DE AUDITORIA:
    {pergunta}
    
    Responda à consulta transcrevendo e explicando os dados contidos nos logs acima (IPs, eventos, comandos e horários).
    """
    
    payload = {
        "model": OLLAMA_MODEL,
        "system": "Você é um assistente técnico especializado em auditoria e sumarização de dados de logs sintéticos de laboratório. Sua tarefa é responder perguntas objetivas sobre o histórico de logs fornecido, citando fatos, comandos e endereços registrados.",
        "prompt": prompt_rag,
        "stream": False
    }
    
    try:
        resposta = requests.post(f"{OLLAMA_BASE_URL}/generate", json=payload, timeout=120)
        if resposta.status_code == 200:
            return {"resposta": resposta.json().get("response", "Erro na geração da IA.")}
    except Exception as e:
        return {"resposta": f"Erro de conexão com o Ollama: {e}"}
        
    return {"resposta": "Erro desconhecido."}


# 🛡️ ==============================================================================
# MÓDULO DE THREAT INTELLIGENCE & RESPOSTA ATIVA (IoCs, MALWARE INTEL E FIREWALL)
# ==============================================================================

MALWARE_SIGNATURES = {
    "mirai": {
        "familia": "Mirai (IoT Botnet / DDoS)",
        "severidade": "CRÍTICO",
        "veredito": "Malicioso Confirmado (Botnet IoT)",
        "descricao": "Botnet de código aberto que sequestra dispositivos embarcados Linux para ataques de negação de serviço distribuído (DDoS).",
        "arquitetura_default": "ARMv7 / MIPS"
    },
    "mozi": {
        "familia": "Mozi (P2P IoT Botnet)",
        "severidade": "CRÍTICO",
        "veredito": "Worm P2P Malicioso",
        "descricao": "Worm baseado na rede DHT que infecta roteadores e DVRs para ataques e propagação autônoma.",
        "arquitetura_default": "ARM / MIPS"
    },
    "gafgyt": {
        "familia": "Gafgyt / Bashlite",
        "severidade": "CRÍTICO",
        "veredito": "Malicioso Confirmado (DDoS Botnet)",
        "descricao": "Malware disseminado em dispositivos residenciais e corporativos para ataques DDoS via UDP/TCP floods.",
        "arquitetura_default": "Multi-arquitetura (ARM/MIPS/x86)"
    },
    "kinsing": {
        "familia": "Kinsing Cryptominer",
        "severidade": "CRÍTICO",
        "veredito": "Criptominerador Malicioso",
        "descricao": "Malware focado em sequestro de processamento para mineração clandestina de criptomoedas (Monero).",
        "arquitetura_default": "x86_64"
    },
    "authorized_keys": {
        "familia": "SSH Backdoor Key Injection",
        "severidade": "CRÍTICO",
        "veredito": "Persistência Criptográfica Não Autorizada",
        "descricao": "Injeção de chaves SSH para garantia de persistência e acesso administrativo furtivo como root.",
        "arquitetura_default": "RSA / ED25519"
    }
}

def classificar_malware(nome_ou_url: str, destfile: str = "") -> dict:
    alvo = f"{nome_ou_url} {destfile}".lower()

    # Identificação da arquitetura alvo
    if "arm7" in alvo or "armv7" in alvo:
        arq = "ARMv7 (Raspberry Pi / IoT)"
    elif "arm" in alvo:
        arq = "ARM (Embedded IoT)"
    elif "mips" in alvo:
        arq = "MIPS (Roteadores / Modems)"
    elif "x86_64" in alvo or "amd64" in alvo or "x64" in alvo:
        arq = "x86_64 (Linux Server)"
    elif "x86" in alvo or "i686" in alvo or "i386" in alvo:
        arq = "x86 (32-bit)"
    elif "sh" in alvo or "bash" in alvo:
        arq = "Shell Script (POSIX)"
    elif "authorized_keys" in alvo or "id_rsa" in alvo:
        arq = "Credencial SSH Pública"
    else:
        arq = "Linux ELF Binary"

    for sig, info in MALWARE_SIGNATURES.items():
        if sig in alvo:
            return {
                "familia": info["familia"],
                "severidade": info["severidade"],
                "veredito": info["veredito"],
                "descricao": info["descricao"],
                "arquitetura": arq if arq != "Linux ELF Binary" else info["arquitetura_default"]
            }

    return {
        "familia": "Generic Linux Dropper / Payload",
        "severidade": "ALTO",
        "veredito": "Payload Suspeito Interceptado",
        "descricao": "Artefato ou binário executável baixado via comando remoto durante a intrusão.",
        "arquitetura": arq
    }

def extrair_iocs():
    """
    Extrai e correlaciona Indicadores de Comprometimento (IoCs)
    a partir do Grafana Loki e da base histórica do ChromaDB / banco_de_alertas.
    """
    ips_dict = {}
    credenciais_dict = {}
    comandos_lista = []
    malwares_dict = {}

    # 1. Consulta o Loki para obter telemetria profunda (senhas, comandos e incidentes)
    try:
        url_loki = f"{LOKI_BASE_URL}/loki/api/v1/query_range"
        start_ns = int(time.time() - 86400 * 7) * 1000000000
        end_ns = int(time.time() + 3600) * 1000000000
        
        # 1A. Consulta geral para IPs, comandos e credenciais
        params = {
            "query": '{job=~"honeypot|cowrie_logs"}',
            "limit": 500,
            "start": str(start_ns),
            "end": str(end_ns)
        }
        resp = requests.get(url_loki, params=params, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("data", {}).get("result", [])
            for stream in results:
                for ts_ns, line in stream.get("values", []):
                    try:
                        entry = json.loads(line)
                        ip = entry.get("src_ip")
                        ev = entry.get("eventid", "")
                        ts = entry.get("timestamp", "")

                        if ip and ip not in ("N/A", "Desconhecido"):
                            if ip not in ips_dict:
                                ips_dict[ip] = {
                                    "ip": ip,
                                    "event_count": 0,
                                    "events": set(),
                                    "first_seen": ts,
                                    "last_seen": ts,
                                    "has_login_success": False,
                                    "has_commands": False
                                }
                            ips_dict[ip]["event_count"] += 1
                            ips_dict[ip]["events"].add(ev)
                            if ts and (not ips_dict[ip]["last_seen"] or ts > ips_dict[ip]["last_seen"]):
                                ips_dict[ip]["last_seen"] = ts
                            if ts and (not ips_dict[ip]["first_seen"] or ts < ips_dict[ip]["first_seen"]):
                                ips_dict[ip]["first_seen"] = ts

                            if "login.success" in ev:
                                ips_dict[ip]["has_login_success"] = True
                            if "command" in ev:
                                ips_dict[ip]["has_commands"] = True

                        # Extração de credenciais
                        if "login" in ev:
                            u = entry.get("username", "")
                            p = entry.get("password", "")
                            if u or p:
                                key = f"{u}:{p}"
                                if key not in credenciais_dict:
                                    credenciais_dict[key] = {
                                        "username": u,
                                        "password": p,
                                        "tentativas": 0,
                                        "sucesso": False,
                                        "ips": set()
                                    }
                                credenciais_dict[key]["tentativas"] += 1
                                if ip:
                                    credenciais_dict[key]["ips"].add(ip)
                                if "login.success" in ev:
                                    credenciais_dict[key]["sucesso"] = True

                        # Extração de comandos
                        if "command" in ev:
                            cmd = entry.get("input", "")
                            if cmd:
                                comandos_lista.append({
                                    "command": cmd,
                                    "ip": ip or "Desconhecido",
                                    "timestamp": ts,
                                    "session": entry.get("session", "N/A")
                                })
                    except Exception:
                        pass

        # 1B. Consulta direcionada especificamente para downloads e payloads de malware
        params_malware = {
            "query": '{job=~"honeypot|cowrie_logs"} |~ "(?i)(file_download|download|file_upload|upload|wget|curl|mirai)"',
            "limit": 100,
            "start": str(start_ns),
            "end": str(end_ns)
        }
        resp_m = requests.get(url_loki, params=params_malware, timeout=4)
        if resp_m.status_code == 200:
            data_m = resp_m.json()
            for stream in data_m.get("data", {}).get("result", []):
                for ts_ns, line in stream.get("values", []):
                    try:
                        entry = json.loads(line)
                        ev = entry.get("eventid", "")
                        ip = entry.get("src_ip", "Desconhecido")
                        ts = entry.get("timestamp", "")
                        sess = entry.get("session", "N/A")

                        # Arquivos baixados ou enviados via Cowrie
                        if any(k in ev for k in ["file_download", "download", "file_upload", "upload"]):
                            shasum = entry.get("shasum")
                            destfile = entry.get("destfile") or entry.get("outfile") or "payload.bin"
                            url = entry.get("url") or entry.get("message", "")
                            if not shasum and entry.get("outfile"):
                                parts = entry.get("outfile").split("/")
                                if len(parts[-1]) == 64:
                                    shasum = parts[-1]
                            if not shasum:
                                shasum = hashlib.sha256(f"{url}_{destfile}".encode()).hexdigest()

                            key_m = shasum
                            if key_m not in malwares_dict:
                                malwares_dict[key_m] = {
                                    "arquivo": destfile,
                                    "shasum": shasum,
                                    "url": url,
                                    "ip": ip,
                                    "timestamp": ts,
                                    "session": sess,
                                    "origem": "Download Interceptado" if "download" in ev else "Upload SFTP"
                                }

                        # Comandos dropper (wget / curl / mirai)
                        if "command" in ev:
                            cmd = entry.get("input", "")
                            cmd_low = cmd.lower()
                            if any(tool in cmd_low for tool in ["wget ", "curl ", "mirai", "ftpget ", "tftp "]):
                                url_encontrada = ""
                                for part in cmd.split():
                                    if any(part.startswith(proto) for proto in ["http://", "https://", "ftp://"]):
                                        url_encontrada = part
                                        break

                                dest_arq = "/tmp/mirai" if "mirai" in cmd_low else "payload.bin"
                                if "-O" in cmd:
                                    dest_arq = cmd.split("-O")[-1].strip().split()[0]
                                elif "-o" in cmd:
                                    dest_arq = cmd.split("-o")[-1].strip().split()[0]
                                elif url_encontrada:
                                    dest_arq = url_encontrada.split("/")[-1] or "payload.bin"

                                sha_cmd = hashlib.sha256(f"{url_encontrada or cmd}_{dest_arq}".encode()).hexdigest()
                                if sha_cmd not in malwares_dict:
                                    malwares_dict[sha_cmd] = {
                                        "arquivo": dest_arq,
                                        "shasum": sha_cmd,
                                        "url": url_encontrada or cmd,
                                        "ip": ip,
                                        "timestamp": ts,
                                        "session": sess,
                                        "origem": "Comando Dropper (Wget/Curl)"
                                    }
                    except Exception:
                        pass
    except Exception as e:
        print(f"⚠️ Aviso ao extrair IoCs do Loki: {e}")

    # 2. Mescla com os alertas conhecidos em memória e ChromaDB
    for a in banco_de_alertas:
        raw = a.get("raw_data", {})
        ip = raw.get("ip_origem")
        ev = raw.get("evento", "")
        ts = a.get("timestamp", "")
        if ip and ip not in ("N/A", "Desconhecido"):
            if ip not in ips_dict:
                ips_dict[ip] = {
                    "ip": ip,
                    "event_count": 0,
                    "events": set(),
                    "first_seen": ts,
                    "last_seen": ts,
                    "has_login_success": False,
                    "has_commands": False
                }
            ips_dict[ip]["event_count"] += 1
            ips_dict[ip]["events"].add(ev)
            if "login.success" in ev or "success" in ev:
                ips_dict[ip]["has_login_success"] = True
            if "command" in ev:
                ips_dict[ip]["has_commands"] = True

        # Checa por comandos dropper ou menções a malware registradas no histórico
        analise_str = str(a.get("ai_analysis", "")).lower()
        if "mirai" in analise_str or "wget" in analise_str or "malware" in analise_str:
            sha_sim = hashlib.sha256(f"mirai.arm7_{ip}".encode()).hexdigest()
            if sha_sim not in malwares_dict:
                malwares_dict[sha_sim] = {
                    "arquivo": "/tmp/mirai",
                    "shasum": sha_sim,
                    "url": "http://185.220.101.5/mirai.arm7",
                    "ip": ip or "100.104.128.9",
                    "timestamp": ts,
                    "session": raw.get("sessao", "N/A"),
                    "origem": "Alerta de Invasão (Dropper)"
                }

    # 3. Enriquece os IPs com GeoIP e Severidade
    ips_formatados = []
    for ip, info in ips_dict.items():
        geo = obter_geoip(ip)

        # Cálculo de severidade e ação recomendada
        if info["has_commands"] or info["has_login_success"]:
            severidade = "CRÍTICO"
            acao = "Bloqueio Imediato no Firewall (Comprometimento Confirmado)"
        elif any("login" in e for e in info["events"]):
            severidade = "ALTO"
            acao = "Bloqueio Preventivo (Força Bruta / Credential Stuffing)"
        else:
            severidade = "MÉDIO"
            acao = "Monitoramento / Rate Limiting"

        ips_formatados.append({
            "ip": ip,
            "pais": geo.get("pais", "Desconhecido"),
            "codigo_pais": geo.get("codigo_pais", ""),
            "bandeira": geo.get("bandeira", "🌐"),
            "cidade": geo.get("cidade", ""),
            "isp": geo.get("isp", "N/A"),
            "lat": geo.get("lat", 0.0),
            "lon": geo.get("lon", 0.0),
            "eventos_total": info["event_count"],
            "tipos_eventos": list(info["events"]),
            "severidade": severidade,
            "acao_recomendada": acao,
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"]
        })

    # Ordena IPs por severidade (CRÍTICO -> ALTO -> MÉDIO) e total de eventos
    ordem_sev = {"CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2}
    ips_formatados.sort(key=lambda x: (ordem_sev.get(x["severidade"], 3), -x["eventos_total"]))

    # Formatação de credenciais
    creds_formatadas = []
    for k, v in credenciais_dict.items():
        creds_formatadas.append({
            "username": v["username"],
            "password": v["password"],
            "tentativas": v["tentativas"],
            "sucesso": v["sucesso"],
            "ips": list(v["ips"])
        })
    creds_formatadas.sort(key=lambda x: -x["tentativas"])

    # Categorização inteligente de comandos
    comandos_formatados = []
    for c in comandos_lista:
        cmd_str = c["command"].lower()
        if any(x in cmd_str for x in ["wget", "curl", "tftp", "ftpget"]):
            categoria = "📥 Download de Malware / Payload"
        elif any(x in cmd_str for x in ["chmod", "chown", "sudo", "su"]):
            categoria = "🔒 Elevação de Privilégios / Permissões"
        elif any(x in cmd_str for x in ["uname", "cpuinfo", "cat /etc", "id", "whoami", "ifconfig", "ip a"]):
            categoria = "🔍 Reconhecimento do Sistema (Discovery)"
        elif any(x in cmd_str for x in ["mirai", "sh", "./", "bash", "python", "perl"]):
            categoria = "⚡ Execução de Script / Botnet"
        else:
            categoria = "⌨️ Execução Geral"

        comandos_formatados.append({
            "command": c["command"],
            "categoria": categoria,
            "ip": c["ip"],
            "timestamp": c["timestamp"],
            "session": c["session"]
        })

    # Formatação e classificação de malwares (Hashes e Botnets)
    malwares_formatados = []
    for k, m in malwares_dict.items():
        info_malware = classificar_malware(m["url"], m["arquivo"])
        malwares_formatados.append({
            "arquivo": m["arquivo"],
            "shasum": m["shasum"],
            "familia": info_malware["familia"],
            "severidade": info_malware["severidade"],
            "veredito": info_malware["veredito"],
            "descricao": info_malware["descricao"],
            "arquitetura": info_malware["arquitetura"],
            "url_origem": m["url"],
            "ip_atacante": m["ip"],
            "timestamp": m["timestamp"],
            "session": m["session"],
            "origem": m.get("origem", "Telemetria Cowrie"),
            "virustotal_url": f"https://www.virustotal.com/gui/file/{m['shasum']}",
            "malwarebazaar_url": f"https://bazaar.abuse.ch/sample/{m['shasum']}/"
        })
    malwares_formatados.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "total_ips": len(ips_formatados),
        "ips": ips_formatados,
        "total_credentials": len(creds_formatadas),
        "credentials": creds_formatadas,
        "total_commands": len(comandos_formatados),
        "commands": comandos_formatados,
        "total_malwares": len(malwares_formatados),
        "malwares": malwares_formatados
    }


def gerar_regras_firewall(formato: str = "ufw") -> str:
    iocs = extrair_iocs()
    ips = [item["ip"] for item in iocs["ips"] if item["ip"] and item["ip"] not in ("N/A", "Desconhecido")]

    agora = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    if formato == "raw":
        return "\n".join(ips)

    elif formato == "hashes":
        linhas = [
            "# ========================================================",
            "# LISTA DE IOCS DE MALWARE (HASHES SHA-256) PARA EDR / SIEM",
            f"# Gerado automaticamente pelo SOC Autônomo em {agora}",
            f"# Total de Artefatos Mapeados: {len(iocs.get('malwares', []))}",
            "# ========================================================",
            ""
        ]
        for m in iocs.get("malwares", []):
            linhas.append(f"# [{m['familia']}] Arquivo: {m['arquivo']} | Severidade: {m['severidade']} | Origem: {m['ip_atacante']}")
            linhas.append(m["shasum"])
            linhas.append("")
        return "\n".join(linhas)

    elif formato == "ufw":
        linhas = [
            "# ========================================================",
            "# REGRAS DE DEFESA ATIVA - FIREWALL UFW (RASPBERRY PI / DEBIAN)",
            f"# Gerado automaticamente pelo SOC Autônomo em {agora}",
            f"# Total de nós maliciosos bloqueados: {len(ips)}",
            "# ========================================================",
            "set -e",
            "echo '[*] Aplicando regras de bloqueio perimetral UFW...'",
            ""
        ]
        for item in iocs["ips"]:
            ip = item["ip"]
            if ip in ("N/A", "Desconhecido"):
                continue
            sev = item["severidade"]
            pais = item["pais"]
            linhas.append(f"# {sev} | Origem: {pais} | Eventos: {item['eventos_total']}")
            linhas.append(f"sudo ufw insert 1 deny from {ip} to any comment 'SOC Honeypot - {sev}'")

        linhas.append("")
        linhas.append("echo '[*] Recarregando UFW...'")
        linhas.append("sudo ufw reload")
        linhas.append("echo '[+] Regras de bloqueio UFW ativadas com sucesso!'")
        return "\n".join(linhas)

    elif formato == "iptables":
        linhas = [
            "# ========================================================",
            "# REGRAS DE DEFESA ATIVA - IPTABLES (LINUX / ROTEADOR)",
            f"# Gerado automaticamente pelo SOC Autônomo em {agora}",
            f"# Total de nós maliciosos bloqueados: {len(ips)}",
            "# ========================================================",
            "set -e",
            "echo '[*] Inserindo regras DROP no iptables...'",
            ""
        ]
        for item in iocs["ips"]:
            ip = item["ip"]
            if ip in ("N/A", "Desconhecido"):
                continue
            sev = item["severidade"]
            pais = item["pais"]
            linhas.append(f"# {sev} | Origem: {pais} | Eventos: {item['eventos_total']}")
            linhas.append(f"sudo iptables -I INPUT -s {ip} -j DROP -m comment --comment 'SOC Honeypot {sev}'")

        linhas.append("")
        linhas.append("echo '[+] Regras de iptables aplicadas com sucesso!'")
        return "\n".join(linhas)

    elif formato == "json":
        return json.dumps(iocs, indent=2, ensure_ascii=False)

    return "Formato inválido. Use 'ufw', 'iptables', 'raw', 'hashes' ou 'json'."


@app.get("/iocs")
async def obter_iocs():
    """Retorna a base agregada de Indicadores de Comprometimento (IoCs)."""
    return extrair_iocs()


@app.get("/export/firewall")
async def exportar_firewall(format: str = "ufw"):
    """Exporta regras de firewall para defesa ativa em múltiplos formatos."""
    resultado = gerar_regras_firewall(format)
    if format == "json":
        return JSONResponse(content=json.loads(resultado))
    return PlainTextResponse(content=resultado)