FROM python:3.11-slim

WORKDIR /app

# Copia as dependências e instala
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r ./requirements.txt

# Copia o código da API
COPY ./main.py .

# Expõe a porta que o FastAPI usa
EXPOSE 5000

# Se o seu tiver algo como CMD ["python", "main.py"], mude para isso:
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]