import os
from fastapi import FastAPI, Request
import requests
from google import genai
from datetime import datetime

app = FastAPI()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    client = None

def enviar_telegram(mensagem):
    if not TELEGRAM_TOKEN or not CHAT_ID:
        print("Erro: Credenciais do Telegram não configuradas no .env")
        return
        
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": mensagem}
    
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        print(f"❌ Erro no Telegram ({response.status_code}): {response.text}")
    else:
        print("✅ Mensagem enviada com sucesso ao Telegram!")

def analisar_com_ia(dados_alerta):
    if not client:
        return "⚠️ Alerta recebido, mas a IA não está configurada (Falta API Key no .env)."
    
    prompt = f"""
    Você é um analista de segurança atuando em um SOC. 
    Analise o seguinte alerta de intrusão capturado por um honeypot Cowrie e gerado pelo Grafana:
    
    {dados_alerta}
    
    Forneça um relatório muito curto, em português, ideal para ler rápido no celular via Telegram contendo:
    1. Resumo do Ataque (o que o invasor fez ou tentou fazer)
    2. Nível de Ameaça (Baixo, Médio, Alto)
    3. Mitigação Recomendada (o que a equipe de infraestrutura deve fazer)
    
    Seja direto, profissional e use emojis para facilitar a leitura. Não inclua código JSON na resposta.
    """
    
    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"❌ Erro ao processar análise com a IA: {e}"

@app.post("/webhook")
async def recebe_alerta(request: Request):
    dados = await request.json()
    status = dados.get("status", "unknown")
    
    if status == "firing":
        print("Novo ataque detectado! Iniciando análise com IA via SDK moderno...")
        
        alertas = dados.get("alerts", [])
        detalhes_do_ataque = alertas[0] if alertas else dados
        texto_do_ataque = str(detalhes_do_ataque)[:2000]
        
        relatorio_ia = analisar_com_ia(texto_do_ataque)
        
        # --- SALVANDO NA MEMÓRIA PARA O FRONTEND ---
        novo_alerta = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
            "raw_data": detalhes_do_ataque,
            "ai_analysis": relatorio_ia
        }
        historico_alertas.insert(0, novo_alerta) # Adiciona no início da lista
        if len(historico_alertas) > 50:
            historico_alertas.pop() # Mantém apenas os últimos 50
        
        mensagem_final = f"🚨 *NOVO ATAQUE DETECTADO NO HONEYPOT*\n\n{relatorio_ia}"
        enviar_telegram(mensagem_final)
        
        return {"status": "Processado com IA e Enviado ao Telegram"}
    
    else: 
        print(f"Alerta recebido com status: {status}. Ignorando.")
        return {"status": "Ignorado"}

# --- NOVA ROTA PARA O FRONTEND ---
historico_alertas = []

@app.get("/alerts")
async def listar_alertas():
    return {"total": len(historico_alertas), "alerts": historico_alertas}

# E dentro da função recebe_alerta (status == "firing"), salve o dado:
historico_alertas.insert(0, {
    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
})