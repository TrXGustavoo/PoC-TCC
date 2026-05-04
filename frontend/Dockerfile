# Usa uma imagem leve do Python
FROM python:3.11-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia as dependências e instala
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r ./requirements.txt

# Copia o código do frontend para dentro do container
COPY ./frontend.py .

# Expõe a porta padrão do Streamlit
EXPOSE 8501

# Comando para rodar a aplicação
CMD ["streamlit", "run", "frontend.py", "--server.port=8501", "--server.address=0.0.0.0"]