# PoC - TCC

## Como Executar

```bash
docker compose up -d --build
```

```bash
# Limpa a chave anterior para evitar o erro de "Host Identification Changed"
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[localhost]:2222"
```

```bash
# Simula o ataque
ssh root@localhost -p 2222
```
