```markdown
# 🛡️ SOC-IoT: Monitoramento e Inteligência de Ameaças com IA Local

Este repositório contém o código-fonte e a arquitetura do projeto de **Trabalho de Conclusão de Curso (TCC)** em Engenharia da Computação na **Facens**. O projeto implementa um Centro de Operações de Segurança (SOC) especializado em **Indústria 4.0** e **IoT**, utilizando Honeypots para detecção e Inteligência Artificial Local para análise de incidentes.

## 📋 Visão Geral do Projeto

O sistema é uma Prova de Conceito (PoC) que simula um ambiente industrial protegido por um Honeypot (Cowrie). A solução automatiza o ciclo de vida de um incidente de segurança: desde a captura do log bruto até a entrega de um relatório de inteligência estruturado via IA.

### 🧩 Arquitetura do Sistema
O fluxo de dados é composto pelos seguintes componentes:
1. **Captura**: Honeypot Cowrie rodando em Raspberry Pi (IoT).
2. **Pipeline de Logs**: Promtail (coleta) -> Loki (armazenamento) -> Grafana (visualização e alertas).
3. **Orquestração (API)**: FastAPI recebe os alertas via Webhook.
4. **Cérebro Cognitivo**: Ollama rodando Llama 3.2 localmente para análise dos logs.
5. **Entrega de Valor**:
   - **Frontend**: Dashboard centralizado em Streamlit com gráficos do Grafana embutidos.
   - **Telegram**: Notificações em tempo real apenas para eventos críticos (Filtro Anti-Fadiga).

---

## 🚀 Funcionalidades Atuais

- [x] **Análise Cognitiva Local**: Integração com Ollama (Llama 3.2) para análise de táticas MITRE ATT&CK sem enviar dados para a nuvem.
- [x] **Filtro Inteligente de Alertas**: Roteamento seletivo (Eventos críticos -> Telegram; Todos os eventos -> Dashboard).
- [x] **Observabilidade Unificada**: Dashboard Streamlit que integra dados da API e painéis do Grafana via Iframe.
- [x] **Arquitetura em Containers**: Todo o ambiente é orquestrado via Docker Compose.

---

## 🛠️ Tecnologias Utilizadas

- **Defesa**: Cowrie Honeypot
- **Observabilidade**: Grafana, Loki, Promtail
- **Backend**: Python, FastAPI, Uvicorn
- **Inteligência Artificial**: Ollama (Llama 3.2:1b)
- **Frontend**: Streamlit
- **Mensageria**: Telegram Bot API
- **Infraestrutura**: Docker & Docker Compose

---

## ⚙️ Como Executar

### 1. Pré-requisitos
- Docker & Docker Compose instalados.
- Python 3.10 ou superior.

### 2. Configuração do Ambiente (.env)
Crie um arquivo `.env` na raiz do projeto com as suas credenciais:

```env
# Configurações do Telegram
TELEGRAM_TOKEN=seu_token_aqui
CHAT_ID=seu_chat_id_aqui

# Configurações da IA
OLLAMA_URL=http://ollama_tcc:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
