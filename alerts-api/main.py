import os
from fastapi import FastAPI, Request
import requests

app = FastAPI()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

def enviar_telegram(mensagem):
    if not TELEGRAM_TOKEN or not CHAT_ID:
        print("Erro: Credenciais do Telegram não configuradas.")
        return
        
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": mensagem, "parse_mode": "Markdown"}
    
    resposta = requests.post(url, json=payload)
    if resposta.status_code != 200:
        print(f"❌ Erro no Telegram ({resposta.status_code}): {resposta.text}")
    else:
        print("✅ Mensagem processada e enviada para o Telegram!")

def analisar_com_ia_local(dados_alerta):
    url_ollama = "http://ollama:11434/api/generate"
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
        "model": "llama3.2:1b",
        "prompt": prompt,
        "stream": False
    }
    
    try:
        resposta = requests.post(url_ollama, json=payload, timeout=300)
        if resposta.status_code == 200:
            return resposta.json().get("response", "Erro: Resposta vazia.")
        return f"❌ Erro no Ollama: {resposta.status_code}"
    except Exception as e:
        return f"❌ Erro de conexão com a IA Local: {e}"

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
        
        # BLINDAGEM DO TELEGRAM: Limpando a sujeira do LLM
        # Trocamos caracteres que quebram o Markdown por equivalentes seguros
        relatorio_limpo = relatorio_ia.replace("*", "").replace("_", "-").replace("`", "'").replace("[", "(").replace("]", ")")
        
        # Formatação blindada contra erros de sintaxe do Python
        mensagem_final = (
            "🚨 *HONEYPOT: RELATÓRIO DE INTELIGÊNCIA* 🚨\n\n"
            "💻 *DADOS DO ATAQUE (RAW):*\n"
            "```text\n"
            f"Data/Hora: {data_hora}Z\n"
            f"Evento: {evento}\n"
            f"IP Origem: {ip_atacante}\n"
            f"Sessão: {sessao}\n"
            "```\n\n"
            "🤖 *ANÁLISE COGNITIVA (OLLAMA):*\n"
            f"{relatorio_limpo}"
        )
        
        enviar_telegram(mensagem_final)
        return {"status": "Processado"}
    
    return {"status": "Ignorado"}