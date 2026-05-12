import streamlit as st
import requests
import streamlit.components.v1 as components

# URL FastAPI no Docker 
API_URL = "http://alerts-api:5000/alerts"


st.set_page_config(page_title="SOC - Threat Intelligence", layout="wide", page_icon="🛡️")


st.markdown("""
    <style>
    .stApp { background-color: #0E1117; }
    .titulo { color: #00FFAA; font-family: 'Courier New', Courier, monospace; }
    .ai-report { background-color: #1E1E1E; padding: 15px; border-radius: 10px; border-left: 5px solid #00FFAA; margin-bottom: 20px;}
    </style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='titulo'>🛡️ Portal de Threat Intelligence - IoT</h1>", unsafe_allow_html=True)
st.markdown("*Monitoramento Ativo de Honeypots Embarcados (Cowrie)*")
st.divider()


def fetch_alerts():
    try:
        response = requests.get(API_URL, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

data = fetch_alerts()

col1, col2, col3 = st.columns(3)

if data is not None:
    alertas = data.get("alerts", [])
    total_alertas = data.get("total", 0)
    
    
    col1.metric("Status da API", "Online 🟢", "Conectado")
    col2.metric("Total de Alertas", total_alertas, "Sessão Atual")
    col3.metric("Integração IA", "Ativa 🤖", "Ollama (Llama 3)")
    
    st.divider()
    st.subheader("🚨 Últimas Intrusões Detectadas")
    
    if total_alertas == 0:
        st.info("Nenhum ataque detectado ainda. Aguardando a telemetria do honeypot...")
    else:
        for i, alerta in enumerate(alertas):
            with st.expander(f"⚠️ Alerta {i+1} | Detectado em: {alerta.get('timestamp', 'Data Indisponível')}"):
                col_ia, col_raw = st.columns([2, 1])
                
                with col_ia:
                    st.markdown("### 🤖 Análise da IA")
                    st.markdown(f"<div class='ai-report'>{alerta.get('ai_analysis', 'N/A')}</div>", unsafe_allow_html=True)
                
                with col_raw:
                    st.markdown("### 🛠️ Dados Brutos")
                    st.json(alerta.get('raw_data', {}))
else:
    col1.metric("Status da API", "Offline 🔴", "-")
    col2.metric("Total de Alertas", "-", "-")
    st.error("Não foi possível conectar à API de alertas na porta 5000. Verifique os logs do container 'alerts-api'.")

st.divider()

# EMBED DO GRAFANA 
st.subheader("📊 Observabilidade em Tempo Real (Grafana)")
st.markdown("Visualização direta do cluster de logs e métricas.")


GRAFANA_URL = "http://localhost:3000/goto/eflrckk7a641sa?orgId=1" 

components.iframe(GRAFANA_URL, height=800, scrolling=True)