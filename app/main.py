from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel, Field
import jwt
import time

app = FastAPI()

# (En prod variables de entorno)
API_KEY_EXPECTED = "2f5ae96c-b558-4c7b-a590-a501ae1c3f6c"
# secreto para firmar y validar.
JWT_SECRET = "secret-devops-challenge-2024"

# Simulación de caché para verificar unicidad del JWT (JTI - ID único del token)
used_tokens = set()

class MessageInput(BaseModel):
    message: str
    to: str
    # 'from' es una palabra reservada en Python, usamos un alias
    from_user: str = Field(..., alias="from") 
    timeToLifeSec: int

@app.middleware("http")
async def validation_middleware(request: Request, call_next):
    # 1. Validar Método (Cualquier método que no sea POST en /DevOps da ERROR)
    if request.url.path == "/DevOps":
        if request.method != "POST":
            return Response(content="ERROR", media_type="text/plain", status_code=405)
        
        # 2. Validar API Key
        api_key = request.headers.get("X-Parse-REST-API-Key")
        if api_key != API_KEY_EXPECTED:
            return Response(content="ERROR", media_type="text/plain", status_code=403)

        # 3. Validar JWT
        token = request.headers.get("X-JWT-KWY")
        if not token:
            return Response(content="ERROR", media_type="text/plain", status_code=401)
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
            # Verificar si el token ya fue usado (Requisito: Único por transacción)
            jti = payload.get("jti")
            if not jti or jti in used_tokens:
                return Response(content="ERROR", media_type="text/plain", status_code=401)
            
            # Marcar token como usado
            used_tokens.add(jti)
            
        except jwt.ExpiredSignatureError:
            return Response(content="ERROR", media_type="text/plain", status_code=401)
        except jwt.InvalidTokenError:
            return Response(content="ERROR", media_type="text/plain", status_code=401)

    response = await call_next(request)
    return response

@app.post("/DevOps")
async def devops_endpoint(data: MessageInput):
    # Lógica del negocio
    return {
        "message": f"Hello {data.to} your message will be send"
    }

@app.get("/health")
def health_check():
    return {"status": "ok"}