import jwt
import uuid
import time
import sys

# Mismo secreto que en la APP
JWT_SECRET = "secret-devops-challenge-2024"

def generate_token():
    # Creamos un payload con un ID único (jti) para cumplir el requisito de "único por transacción"
    payload = {
        "jti": str(uuid.uuid4()), # ID único del token
        "iat": int(time.time()),  # Emitido ahora
        "exp": int(time.time()) + 3600 # Expira en 1 hora
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

if __name__ == "__main__":
    token = generate_token()
    print(f"\n--- JWT GENERADO (Válido por 1 hora) ---")
    print(token)
    print("-" * 40)
    print("Usa este token en el header 'X-JWT-KWY'")