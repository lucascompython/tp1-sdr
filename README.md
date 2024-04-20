# Instruções

```bash
# se tiverem o github CLI instalado e logado
gh repo clone https://github.com/lucascompython/tp1-sdr 

cd tp1-sdr

# Criar ambiente virtual
python3 -m venv .venv

# Ativar ambiente virtual

# Linux
source .venv/bin/activate
# Windows
.venv\Scripts\activate

# Instalar dependências
cd server
pip install -r requirements.txt

# Servidor 
python3 server/main.py

# Cliente
python3 terminal-client/main.py
```
