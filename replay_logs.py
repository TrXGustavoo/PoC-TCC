import json
from datetime import datetime, timedelta, timezone

def injetar_logs_agora(arquivo_entrada, arquivo_saida):
    print("Preparando injeção tática de logs...")
    
    with open(arquivo_entrada, 'r', encoding='utf-8') as f_in, open(arquivo_saida, 'a', encoding='utf-8') as f_out:
        linhas = f_in.readlines()
        
        # Pega a hora exata de agora e volta 2 minutos (janela perfeita do Grafana)
        tempo_base = datetime.now(timezone.utc) - timedelta(minutes=2)
        linhas_processadas = 0
        
        for i, linha in enumerate(linhas):
            if not linha.strip(): 
                continue
                
            try:
                dados = json.loads(linha.strip())
                
                # Força cada ataque a ter 1 segundo de diferença do outro
                novo_tempo = tempo_base + timedelta(seconds=i)
                dados['timestamp'] = novo_tempo.isoformat().replace('+00:00', 'Z')
                
                f_out.write(json.dumps(dados) + '\n')
                linhas_processadas += 1
                
            except Exception as e:
                continue
                
    print(f"Sucesso! {linhas_processadas} logs espremidos cirurgicamente nos últimos 2 minutos.")

ARQUIVO_KAGGLE = "dataset_antigo_cowrie.json"
ARQUIVO_FINAL = "cowrie/var/log/cowrie/cowrie.json"

injetar_logs_agora(ARQUIVO_KAGGLE, ARQUIVO_FINAL)