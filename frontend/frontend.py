import os
import requests
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# ==========================================
# CONFIGURAÇÕES GERAIS E CONECTIVIDADE
# ==========================================
st.set_page_config(
    page_title="SOC - Threat Intelligence (IoT Honeypot)",
    layout="wide",
    page_icon="🛡️"
)

# Resolução de endpoint (Docker vs Localhost)
API_BASE_URL = os.getenv("API_BASE_URL", "http://alerts-api:5000")
ALERTS_ENDPOINT = f"{API_BASE_URL}/alerts"
CHAT_ENDPOINT = f"{API_BASE_URL}/chat"
IOCS_ENDPOINT = f"{API_BASE_URL}/iocs"
EXPORT_ENDPOINT = f"{API_BASE_URL}/export/firewall"

DEFAULT_GRAFANA_URL = os.getenv(
    "GRAFANA_URL",
    "http://100.104.128.9:3000/d/adrd62h/linha-do-tempo-de-ataques?orgId=1&kiosk"
)

# ==========================================
# ESTILOS CSS PERSONALIZADOS
# ==========================================
st.markdown("""
    <style>
    .main-title {
        font-family: 'Courier New', Courier, monospace;
        font-weight: bold;
        color: #00FFAA;
        margin-bottom: 0px;
    }
    .sub-title {
        font-size: 14px;
        color: #888888;
        margin-bottom: 15px;
    }
    .ai-report {
        background-color: rgba(0, 255, 170, 0.05);
        padding: 16px;
        border-radius: 8px;
        border-left: 4px solid #00FFAA;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        line-height: 1.6;
    }
    .metric-container {
        background-color: #1a1c24;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #2d3139;
    }
    .chip-button {
        margin-bottom: 8px;
    }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# BARRA LATERAL (CONFIGURAÇÕES E STATUS)
# ==========================================
with st.sidebar:
    st.image("https://img.icons8.com/nolan/96/shield.png", width=64)
    st.title("SOC Control Center")
    st.caption("Arquitetura de Threat Intelligence IoT")
    st.divider()

    modo_grafana = st.selectbox(
        "Origem do Grafana:",
        ["Localhost (Porta 3000)", "Túnel Ngrok (Público)", "Tailscale VPN (100.104.128.9)", "Personalizado"],
        index=0
    )
    if modo_grafana == "Localhost (Porta 3000)":
        grafana_url_input = "http://localhost:3000/d/adrd62h/linha-do-tempo-de-ataques?orgId=1&kiosk&from=now-6h&to=now&refresh=5s"
    elif modo_grafana == "Túnel Ngrok (Público)":
        grafana_url_input = "https://bakery-onscreen-vocally.ngrok-free.dev/d/adrd62h/linha-do-tempo-de-ataques?orgId=1&kiosk&from=now-6h&to=now&refresh=5s"
    elif modo_grafana == "Tailscale VPN (100.104.128.9)":
        grafana_url_input = "http://100.104.128.9:3000/d/adrd62h/linha-do-tempo-de-ataques?orgId=1&kiosk&from=now-6h&to=now&refresh=5s"
    else:
        grafana_url_input = st.text_input("URL Customizada do Grafana", value="http://localhost:3000/d/adrd62h/linha-do-tempo-de-ataques?orgId=1&kiosk")

    st.divider()
    st.subheader("📌 Topologia Ativa")
    st.markdown("""
    * **Edge (Raspberry Pi):** `100.127.31.12`
      * Cowrie Honeypot (Porta `2222` / `22`)
      * Promtail Edge Agent
    * **Host Central (WSL 2):** `100.104.128.9`
      * Loki, Grafana, FastAPI, Ollama, ChromaDB
    """)
    st.divider()
    st.caption("TCC - Engenharia de Computação (Facens)")

# ==========================================
# CABEÇALHO PRINCIPAL
# ==========================================
st.markdown("<h1 class='main-title'>🛡️ SOC AUTÔNOMO - THREAT INTELLIGENCE</h1>", unsafe_allow_html=True)
st.markdown("<div class='sub-title'>Monitoramento em Tempo Real & Investigação Forense com IA Generativa (Cowrie Honeypot Edge)</div>", unsafe_allow_html=True)

# ==========================================
# FUNÇÕES DE COMUNICAÇÃO COM A API
# ==========================================
def fetch_alerts():
    try:
        response = requests.get(ALERTS_ENDPOINT, timeout=4)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None

def query_chat_rag(question: str):
    try:
        payload = {"pergunta": question}
        response = requests.post(CHAT_ENDPOINT, json=payload, timeout=90)
        if response.status_code == 200:
            return response.json().get("resposta", "Resposta vazia retornada pela IA.")
        return f"❌ Erro na API ({response.status_code}): {response.text}"
    except requests.exceptions.Timeout:
        return "⏳ Tempo limite excedido: O modelo local demorou para gerar a resposta. Tente novamente."
    except Exception as e:
        return f"❌ Falha de conexão com o endpoint RAG: {e}"

def fetch_iocs():
    try:
        response = requests.get(IOCS_ENDPOINT, timeout=6)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None

def fetch_firewall_rules(formato: str = "ufw"):
    try:
        response = requests.get(f"{EXPORT_ENDPOINT}?format={formato}", timeout=6)
        if response.status_code == 200:
            return response.text
        return None
    except Exception:
        return None

# ==========================================
# ESTRUTURAÇÃO DAS ABAS DO SISTEMA
# ==========================================
tab_alerts, tab_iocs, tab_chat, tab_grafana = st.tabs([
    "🚨 Feed Tático de Incidentes",
    "🛡️ Inteligência de IoCs & Resposta Ativa",
    "🤖 Assistente Investigativo (RAG SOC)",
    "📊 Observabilidade em Tempo Real (Grafana)"
])

# ==============================================================================
# ABA 1: FEED TÁTICO DE INCIDENTES
# ==============================================================================
with tab_alerts:
    data = fetch_alerts()

    # Métricas superiores
    col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns([1.5, 1.5, 1.5, 1.5, 1])

    alertas = []
    if data is not None:
        alertas = data.get("alerts", [])
        total_alertas = data.get("total", len(alertas))
        ips_unicos = len(set(a.get("raw_data", {}).get("ip_origem") for a in alertas if a.get("raw_data", {}).get("ip_origem") not in ["Desconhecido", "N/A"]))
        paises_unicos = len(set(a.get("raw_data", {}).get("geo", {}).get("pais") for a in alertas if a.get("raw_data", {}).get("geo", {}).get("pais") not in [None, "Desconhecido", "N/A"]))

        col_m1.metric("Status da API", "Online 🟢", "Porta 5000")
        col_m2.metric("Total de Alertas", total_alertas, "Incidentes Capturados")
        col_m3.metric("IPs Atacantes", ips_unicos, "Únicos")
        col_m4.metric("Países de Origem", paises_unicos, "Threat Intel")
    else:
        total_alertas = 0
        col_m1.metric("Status da API", "Offline 🔴", "Inacessível")
        col_m2.metric("Total de Alertas", "-", "-")
        col_m3.metric("IPs Atacantes", "-", "-")
        col_m4.metric("Países de Origem", "-", "-")

    with col_m5:
        st.write("")
        if st.button("🔄 Atualizar Feed", use_container_width=True):
            st.rerun()

    st.divider()

    if data is None:
        st.error(f"Não foi possível conectar à API de alertas em `{ALERTS_ENDPOINT}`. Verifique se o container `alerts-api` está ativo na rede Docker.")
    elif total_alertas == 0:
        st.info("Nenhuma intrusão capturada nesta sessão ainda. Aguardando telemetria em tempo real do Honeypot...")
    else:
        # Extração dos dados geográficos para o mapa e estatísticas
        map_rows = []
        paises_contagem = {}

        for a in alertas:
            raw = a.get("raw_data", {})
            geo = raw.get("geo", {})
            lat = geo.get("lat")
            lon = geo.get("lon")
            pais = geo.get("pais", "Desconhecido")
            bandeira = geo.get("bandeira", "🌐")
            cidade = geo.get("cidade", "")
            ip = raw.get("ip_origem", "Desconhecido")

            if pais and pais not in ["Desconhecido", "N/A"]:
                label = f"{bandeira} {pais}"
                paises_contagem[label] = paises_contagem.get(label, 0) + 1

            if lat is not None and lon is not None and (lat != 0.0 or lon != 0.0):
                map_rows.append({
                    "lat": float(lat),
                    "lon": float(lon),
                    "ip": ip,
                    "cidade": cidade,
                    "pais": pais
                })

        # ==========================================
        # SEÇÃO: MAPA GLOBAL DE AMEAÇAS & TOP ORIGENS
        # ==========================================
        st.markdown("### 🌍 Mapa Global de Origem das Ameaças (Threat Map)")
        col_map, col_top_paises = st.columns([2.5, 1])

        with col_map:
            if map_rows:
                df_mapa = pd.DataFrame(map_rows)
                st.map(df_mapa, zoom=1, use_container_width=True)
            else:
                st.info("Nenhuma coordenada geográfica pública disponível no momento para plotagem.")

        with col_top_paises:
            st.markdown("#### 🏆 Top Origens")
            if paises_contagem:
                paises_ordenados = sorted(paises_contagem.items(), key=lambda x: x[1], reverse=True)[:5]
                for pais_nome, qtd in paises_ordenados:
                    pct = int((qtd / len(alertas)) * 100) if alertas else 0
                    st.markdown(f"**{pais_nome}**: `{qtd}` eventos ({pct}%)")
                    st.progress(min(pct / 100.0, 1.0))
            else:
                st.caption("Nenhum dado geográfico computado.")

        st.divider()

        # Filtro rápido
        col_search, col_stats = st.columns([3, 1])
        with col_search:
            termo_busca = st.text_input("🔍 Filtrar alertas por IP, país, evento ou comando:", placeholder="Ex: Germany, cowrie.command.input, 192.168, /etc/shadow...")
        with col_stats:
            st.write("")
            st.caption(f"Mostrando {len(alertas)} eventos recentes")

        alertas_filtrados = []
        for a in alertas:
            raw_str = str(a.get("raw_data", {})).lower()
            ai_str = str(a.get("ai_analysis", "")).lower()
            if not termo_busca or termo_busca.lower() in raw_str or termo_busca.lower() in ai_str:
                alertas_filtrados.append(a)

        for i, alerta in enumerate(alertas_filtrados):
            raw = alerta.get("raw_data", {})
            evento = raw.get("evento", "N/A")
            ip_origem = raw.get("ip_origem", "Desconhecido")
            timestamp = alerta.get("timestamp", "N/A")
            sessao = raw.get("sessao", "N/A")
            geo = raw.get("geo", {})

            bandeira = geo.get("bandeira", "🌐")
            pais = geo.get("pais", "Desconhecido")
            cidade = geo.get("cidade", "")
            isp = geo.get("isp", "N/A")
            localizacao_str = f"{cidade}, {pais}" if cidade else pais

            # Identificação de Severidade Visual
            if "command" in evento:
                badge = "⚡ COMANDO EXECUTADO"
            elif "success" in evento:
                badge = "🚨 INVASÃO / LOGIN BEM-SUCEDIDO"
            elif "download" in evento:
                badge = "📥 DOWNLOAD DE PAYLOAD / MALWARE"
            else:
                badge = "⚠️ ATIVIDADE SUSPEITA"

            titulo_expander = f"{badge} | {bandeira} {ip_origem} ({localizacao_str}) | {timestamp}"
            with st.expander(titulo_expander, expanded=(i == 0)):
                col_ia, col_raw = st.columns([2, 1])

                with col_ia:
                    st.markdown("#### 🤖 Análise Cognitiva da IA (Llama 3.2)")
                    analise_texto = alerta.get("ai_analysis", "Análise não disponível.")
                    st.markdown(f"<div class='ai-report'>{analise_texto}</div>", unsafe_allow_html=True)

                with col_raw:
                    st.markdown("#### 🛠️ Telemetria & GeoIP")
                    st.markdown(f"**🌍 Local:** {bandeira} {localizacao_str}")
                    st.markdown(f"**🏢 Provedor (ISP):** `{isp}`")
                    st.markdown(f"**📍 Coordenadas:** `{geo.get('lat', 0.0)}, {geo.get('lon', 0.0)}`")
                    st.divider()
                    st.json({
                        "timestamp": timestamp,
                        "src_ip": ip_origem,
                        "eventid": evento,
                        "session": sessao,
                        "geo": geo
                    })

# ==============================================================================
# ABA 2: INTELIGÊNCIA DE IOCS & RESPOSTA ATIVA (DEFESA AUTOMATIZADA)
# ==============================================================================
with tab_iocs:
    st.markdown("### 🛡️ Inteligência de Ameaças & Indicadores de Comprometimento (IoCs)")
    st.markdown(
        "Extração, correlação e conversão automática de telemetria ofensiva em "
        "**regras de defesa perimetral (Active Defense)** para proteção de infraestrutura."
    )

    iocs_data = fetch_iocs()

    # Métricas no topo da aba de IoCs
    col_i1, col_i2, col_i3, col_i4, col_i5, col_i6 = st.columns([1.3, 1.3, 1.3, 1.3, 1.3, 0.9])

    if iocs_data is not None:
        total_ips = iocs_data.get("total_ips", 0)
        total_creds = iocs_data.get("total_credentials", 0)
        total_cmds = iocs_data.get("total_commands", 0)
        total_malwares = iocs_data.get("total_malwares", 0)

        # Calcular criticidade
        tem_critico = any(item.get("severidade") == "CRÍTICO" for item in iocs_data.get("ips", [])) or \
                      any(m.get("severidade") == "CRÍTICO" for m in iocs_data.get("malwares", []))
        nivel_global = "CRÍTICO 🚨" if tem_critico else ("ALTO ⚠️" if total_ips > 0 or total_malwares > 0 else "BAIXO 🟢")

        col_i1.metric("IPs Maliciosos", total_ips, "Nós Rastreados")
        col_i2.metric("Credenciais Alvo", total_creds, "Força Bruta")
        col_i3.metric("Comandos Capturados", total_cmds, "Forensics")
        col_i4.metric("Malwares & Hashes", total_malwares, "SHA-256")
        col_i5.metric("Risco Perimetral", nivel_global, "Severidade Máxima")
    else:
        col_i1.metric("IPs Maliciosos", "-", "-")
        col_i2.metric("Credenciais Alvo", "-", "-")
        col_i3.metric("Comandos Capturados", "-", "-")
        col_i4.metric("Malwares & Hashes", "-", "-")
        col_i5.metric("Risco Perimetral", "Desconhecido", "-")

    with col_i6:
        st.write("")
        if st.button("🔄 Atualizar IoCs", key="btn_refresh_iocs", use_container_width=True):
            st.rerun()

    st.divider()

    if iocs_data is None:
        st.error(f"Não foi possível obter os IoCs da API em `{IOCS_ENDPOINT}`. Verifique a conectividade do container `alerts-api`.")
    else:
        ips_list = iocs_data.get("ips", [])
        creds_list = iocs_data.get("credentials", [])
        cmds_list = iocs_data.get("commands", [])

        # ----------------------------------------------------
        # SEÇÃO 1: TABELA TÁTICA DE ENDEREÇOS IP AGRESSORES
        # ----------------------------------------------------
        st.markdown("#### 🛑 1. Nós Agressores Identificados (Network IoCs)")

        if not ips_list:
            st.info("Nenhum IP malicioso registrado até o momento.")
        else:
            col_f1, col_f2 = st.columns([3, 1])
            with col_f1:
                filtro_ip = st.text_input("Filtrar por IP, País ou Provedor (ISP):", placeholder="Ex: Netherlands, 100., Hetzner...", key="filter_iocs_ip")
            with col_f2:
                filtro_sev = st.selectbox("Severidade:", ["Todas", "CRÍTICO", "ALTO", "MÉDIO"], key="filter_iocs_sev")

            ips_filtrados = []
            for item in ips_list:
                str_repr = f"{item.get('ip')} {item.get('pais')} {item.get('isp')}".lower()
                match_text = not filtro_ip or filtro_ip.lower() in str_repr
                match_sev = filtro_sev == "Todas" or item.get("severidade") == filtro_sev
                if match_text and match_sev:
                    ips_filtrados.append({
                        "Severidade": f"🚨 {item.get('severidade')}" if item.get('severidade') == "CRÍTICO" else f"⚠️ {item.get('severidade')}",
                        "Endereço IP": item.get("ip"),
                        "País": f"{item.get('bandeira', '🌐')} {item.get('pais', 'N/A')}",
                        "Cidade": item.get("cidade", "N/A"),
                        "Provedor (ISP)": item.get("isp", "N/A"),
                        "Eventos": item.get("eventos_total", 0),
                        "Ação Recomendada": item.get("acao_recomendada")
                    })

            if ips_filtrados:
                st.dataframe(pd.DataFrame(ips_filtrados), use_container_width=True, hide_index=True)
            else:
                st.caption("Nenhum IP corresponde aos filtros selecionados.")

        st.divider()

        # ----------------------------------------------------
        # SEÇÃO 2: DICIONÁRIO DE CREDENCIAIS, COMANDOS & MALWARES
        # ----------------------------------------------------
        st.markdown("#### 🔍 2. Auditoria Forense: Credenciais, Comandos e Binários Maliciosos")
        tab_sub_creds, tab_sub_cmds, tab_sub_malware = st.tabs([
            "🔑 Dicionário de Força Bruta (Credential Stuffing)",
            "💻 Comandos Digitados no Terminal (Payloads)",
            "🦠 Malware & Hashes SHA-256 (Threat Intel & VirusTotal)"
        ])

        with tab_sub_creds:
            if not creds_list:
                st.info("Nenhuma tentativa de login com credenciais capturada até o momento.")
            else:
                creds_df_data = []
                for c in creds_list:
                    creds_df_data.append({
                        "Usuário Alvo": c.get("username"),
                        "Senha Testada": c.get("password"),
                        "Tentativas": c.get("tentativas", 1),
                        "Login Bem-Sucedido?": "✅ Sim (Comprometido)" if c.get("sucesso") else "❌ Recusado",
                        "IPs de Origem": ", ".join(c.get("ips", []))
                    })
                st.dataframe(pd.DataFrame(creds_df_data), use_container_width=True, hide_index=True)
                st.caption("💡 *Recomendação de Hardening:* Bloquear senhas fracas detectadas em políticas de PAM e Active Directory.")

        with tab_sub_cmds:
            if not cmds_list:
                st.info("Nenhum comando digitado por invasores capturado no honeypot.")
            else:
                cmds_df_data = []
                for cmd in cmds_list:
                    cmds_df_data.append({
                        "Categoria Tática": cmd.get("categoria"),
                        "Comando Executado": cmd.get("command"),
                        "IP Atacante": cmd.get("ip"),
                        "Sessão Forense": cmd.get("session"),
                        "Data/Hora": cmd.get("timestamp", "N/A")
                    })
                st.dataframe(pd.DataFrame(cmds_df_data), use_container_width=True, hide_index=True)

        with tab_sub_malware:
            malwares_list = iocs_data.get("malwares", [])
            if not malwares_list:
                st.info("Nenhum binário malicioso ou tentativa de download interceptada até o momento.")
            else:
                malwares_df_data = []
                for m in malwares_list:
                    malwares_df_data.append({
                        "Severidade": f"🚨 {m.get('severidade')}" if m.get('severidade') == "CRÍTICO" else f"⚠️ {m.get('severidade')}",
                        "Família / Botnet": m.get("familia"),
                        "Arquivo / Payload": m.get("arquivo"),
                        "Arquitetura": m.get("arquitetura"),
                        "Veredito": m.get("veredito"),
                        "Hash SHA-256": m.get("shasum"),
                        "IP Atacante": m.get("ip_atacante"),
                        "Data/Hora": m.get("timestamp", "N/A")
                    })
                st.dataframe(pd.DataFrame(malwares_df_data), use_container_width=True, hide_index=True)

                st.markdown("##### 🔬 Investigação Aprofundada & Reputação Externa (Threat Intel Feed)")
                for m in malwares_list:
                    hash_short = m.get("shasum", "")[:16]
                    with st.expander(f"🦠 {m.get('familia')} - `{m.get('arquivo')}` ({hash_short}...)"):
                        col_m_desc, col_m_links = st.columns([2, 1])
                        with col_m_desc:
                            st.markdown(f"**Descrição da Ameaça:** {m.get('descricao')}")
                            st.markdown(f"**Arquitetura Alvo:** `{m.get('arquitetura')}` | **Veredito:** `{m.get('veredito')}`")
                            st.markdown(f"**Origem do Download:** `{m.get('url_origem')}`")
                            st.markdown(f"**IP Atacante:** `{m.get('ip_atacante')}` | **Sessão Cowrie:** `{m.get('session')}`")
                            st.markdown(f"**Origem dos Dados:** `{m.get('origem', 'Cowrie Honeypot')}`")
                            st.markdown("**Hash SHA-256 Completo:**")
                            st.code(m.get("shasum"), language="text")
                        with col_m_links:
                            st.markdown("###### 🌐 Consultas Externas:")
                            vt_url = m.get("virustotal_url")
                            mb_url = m.get("malwarebazaar_url")
                            if vt_url:
                                st.link_button("🛡️ Consultar no VirusTotal", vt_url, use_container_width=True)
                            if mb_url:
                                st.link_button("🧪 Consultar no MalwareBazaar", mb_url, use_container_width=True)

        st.divider()

        # ----------------------------------------------------
        # SEÇÃO 3: CENTRAL DE RESPOSTA ATIVA (EXPORTADOR DE FIREWALL)
        # ----------------------------------------------------
        st.markdown("#### 🚀 3. Central de Resposta Ativa: Exportador de Firewall & IoCs")
        st.markdown(
            "Exporte scripts automatizados para bloqueio perimetral imediato "
            "dos invasores no gateway, firewall corporativo, EDR/SIEM ou no próprio Raspberry Pi."
        )

        col_cfg, col_code = st.columns([1, 2])

        with col_cfg:
            opcoes_formato = [
                ("ufw", "UFW (Debian / Ubuntu / Raspberry Pi)"),
                ("iptables", "iptables (Linux / Roteadores)"),
                ("hashes", "Lista de Hashes SHA-256 (EDR / Antivírus / SIEM)"),
                ("raw", "Lista Bruta de IPs (pfSense / Pi-hole)"),
                ("json", "JSON Estruturado (STIX / SIEM)")
            ]
            formato_selecionado = st.radio(
                "Selecione o Formato do Firewall / IoCs:",
                [opt[0] for opt in opcoes_formato],
                format_func=lambda x: dict(opcoes_formato).get(x, x),
                key="radio_firewall_format"
            )

            extensao = {
                "ufw": ("firewall_rules.sh", "text/x-sh"),
                "iptables": ("iptables_rules.sh", "text/x-sh"),
                "hashes": ("malware_hashes.txt", "text/plain"),
                "raw": ("blocklist.txt", "text/plain"),
                "json": ("iocs_threat_intel.json", "application/json")
            }
            nome_arquivo, mime_type = extensao.get(formato_selecionado, ("rules.txt", "text/plain"))

            conteudo_script = fetch_firewall_rules(formato_selecionado) or "# Erro ao gerar regras"

            st.download_button(
                label=f"📥 Baixar Arquivo ({nome_arquivo})",
                data=conteudo_script,
                file_name=nome_arquivo,
                mime=mime_type,
                use_container_width=True,
                type="primary",
                key="btn_download_firewall"
            )

            if formato_selecionado in ("ufw", "iptables"):
                st.markdown("""
                **Como aplicar no Raspberry Pi (Edge):**
                ```bash
                scp -P 50022 firewall_rules.sh pi@100.127.31.12:/tmp/
                ssh -p 50022 pi@100.127.31.12 "sudo bash /tmp/firewall_rules.sh"
                ```
                """)
            elif formato_selecionado == "hashes":
                st.markdown("""
                **Aplicação de Hashes SHA-256:**
                * Importe em EDRs (CrowdStrike, Defender for Endpoint)
                * Use em regras de detecção YARA ou SIEM (Splunk, Elastic)
                """)
            else:
                st.markdown("""
                **Aplicação de Listas / JSON:**
                * Importe o arquivo em firewalls de borda ou feeds STIX/TAXII.
                """)

        with col_code:
            st.caption(f"Pré-visualização do script gerado ({formato_selecionado}):")
            lang = "bash" if formato_selecionado in ("ufw", "iptables") else ("json" if formato_selecionado == "json" else "text")
            st.code(
                conteudo_script,
                language=lang,
                line_numbers=True
            )

# ==============================================================================
# ABA 3: CHATBOT INVESTIGATIVO FORENSE (RAG SOC)
# ==============================================================================
with tab_chat:
    st.markdown("### 🤖 Assistente Forense de Threat Intelligence (RAG)")
    st.markdown(
        "Consulte a base de conhecimento profunda do **ChromaDB**. "
        "As perguntas são convertidas em embeddings semânticos (`nomic-embed-text`) "
        "e correlacionadas aos ataques pelo modelo **Llama 3.2**."
    )

    # Botões rápidos com perguntas forenses recomendadas
    st.markdown("**Perguntas Táticas Recomendadas:**")
    col_q1, col_q2, col_q3, col_q4 = st.columns(4)

    pergunta_selecionada = None
    if col_q1.button("🚨 Ataques de Força Bruta", use_container_width=True):
        pergunta_selecionada = "Quais endereços IP realizaram ataques de força bruta contra o honeypot?"
    if col_q2.button("💻 Comandos Executados", use_container_width=True):
        pergunta_selecionada = "Quais comandos maliciosos foram executados pelos invasores após a invasão?"
    if col_q3.button("🔑 Logins Bem-Sucedidos", use_container_width=True):
        pergunta_selecionada = "Houve logins bem-sucedidos no honeypot? Quais foram os IPs envolvidos?"
    if col_q4.button("🎯 Táticas MITRE ATT&CK", use_container_width=True):
        pergunta_selecionada = "Resuma as principais táticas do framework MITRE ATT&CK identificadas nos ataques."

    # Inicialização do histórico de mensagens na sessão
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = [
            {
                "role": "assistant",
                "content": (
                    "Olá, analista do SOC! Sou o motor de Threat Intelligence autônomo do projeto. "
                    "Posso recuperar e sintetizar dados sobre os incidentes armazenados no nosso banco vetorial (ChromaDB). "
                    "Pergunte sobre IPs atacantes, comandos, credenciais ou táticas MITRE ATT&CK."
                )
            }
        ]

    # Exibição do histórico de mensagens
    for msg in st.session_state.chat_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Captura de input (via chat_input ou botão rápido)
    prompt_usuario = st.chat_input("Digite sua pergunta forense para a IA do SOC...")
    if pergunta_selecionada:
        prompt_usuario = pergunta_selecionada

    if prompt_usuario:
        # Registra a pergunta do usuário no chat
        st.session_state.chat_messages.append({"role": "user", "content": prompt_usuario})
        with st.chat_message("user"):
            st.markdown(prompt_usuario)

        # Resposta do assistente
        with st.chat_message("assistant"):
            with st.spinner("Consultando vetores no ChromaDB e gerando análise com Llama 3.2..."):
                resposta_rag = query_chat_rag(prompt_usuario)
                st.markdown(resposta_rag)

        st.session_state.chat_messages.append({"role": "assistant", "content": resposta_rag})
        if pergunta_selecionada:
            st.rerun()

    # Opção de limpar chat
    if len(st.session_state.chat_messages) > 1:
        if st.button("🗑️ Limpar Conversa", type="secondary"):
            st.session_state.chat_messages = [st.session_state.chat_messages[0]]
            st.rerun()

# ==============================================================================
# ABA 3: OBSERVABILIDADE EM TEMPO REAL (GRAFANA)
# ==============================================================================
with tab_grafana:
    st.markdown("### 📊 Observabilidade Contínua (Painéis Grafana)")
    st.markdown(
        f"Painel consolidado de telemetria e métricas operacionais. "
        f"Alimentado pelo agregador de logs **Grafana Loki**."
    )

    col_g1, col_g2 = st.columns([3, 1])
    with col_g1:
        st.caption(f"🔗 Origem atual do iframe: `{grafana_url_input}`")
    with col_g2:
        st.link_button("↗️ Abrir Grafana em Nova Aba", grafana_url_input, use_container_width=True)

    try:
        components.iframe(grafana_url_input, height=820, scrolling=True)
    except Exception as e:
        st.error(f"Não foi possível carregar o iframe do Grafana: {e}")