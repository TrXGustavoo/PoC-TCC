import json
import time
from datetime import datetime, timezone

def iniciar_ataque_continuo(arquivo_entrada, arquivo_saida):
    print("Iniciando simulação de tráfego contínuo (Streaming)... Pressione CTRL+C para parar.")
    
    with open(arquivo_entrada, 'r', encoding='utf-8') as f_in:
        linhas = f_in.readlines()
        
    linhas_processadas = 0
    
    try:
        for linha in linhas:
            if not linha.strip(): continue
                
            dados = json.loads(linha.strip())
            
            # Atualiza o tempo para o exato momento da injeção
            agora = datetime.now(timezone.utc)
            dados['timestamp'] = agora.isoformat().replace('+00:00', 'Z')
            
            # Modo 'a' (append) contínuo
            with open(arquivo_saida, 'a', encoding='utf-8') as f_out:
                f_out.write(json.dumps(dados) + '\n')
            
            linhas_processadas += 1
            print(f"Log {linhas_processadas} injetado: {dados.get('eventid')} - IP: {dados.get('src_ip')}")
            
            # Pausa de 0.5 segundos entre cada log para o Grafana desenhar o gráfico bonito
            time.sleep(0.5) 
            
    except KeyboardInterrupt:
        print(f"\nSimulação interrompida. {linhas_processadas} logs enviados com sucesso.")

ARQUIVO_KAGGLE = "kaggle_logs.json"
ARQUIVO_FINAL = "cowrie/var/log/cowrie/cowrie.json"

iniciar_ataque_continuo(ARQUIVO_KAGGLE, ARQUIVO_FINAL)