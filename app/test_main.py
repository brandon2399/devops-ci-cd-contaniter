from fastapi.testclient import TestClient
from main import app, JWT_SECRET, API_KEY_EXPECTED
import jwt
import time
import uuid

# Creamos un cliente de pruebas que simula peticiones HTTP sin levantar el servidor real
client = TestClient(app)

def generate_valid_token():
    """Genera un token válido fresco para las pruebas"""
    payload = {
        "jti": str(uuid.uuid4()), # ID único
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def test_devops_post_success():
    """Prueba el flujo correcto: POST con headers y body válidos"""
    token = generate_valid_token()
    headers = {
        "X-Parse-REST-API-Key": API_KEY_EXPECTED,
        "X-JWT-KWY": token
    }
    data = {
        "message": "This is a test",
        "to": "Juan Perez",
        "from": "Rita Asturia",
        "timeToLifeSec": 45
    }
    
    response = client.post("/DevOps", json=data, headers=headers)
    
    assert response.status_code == 200
    assert response.json() == {"message": "Hello Juan Perez your message will be send"}

def test_devops_invalid_api_key():
    """Prueba que rechace una API Key incorrecta"""
    token = generate_valid_token()
    headers = {
        "X-Parse-REST-API-Key": "LLAVE_INCORRECTA",
        "X-JWT-KWY": token
    }
    data = {"message": "test", "to": "Juan", "from": "Rita", "timeToLifeSec": 45}
    
    response = client.post("/DevOps", json=data, headers=headers)
    
    # Según tu código devuelve 403 Forbidden o el string ERROR
    assert response.status_code == 403 or response.text == "ERROR"

def test_devops_invalid_method_get():
    """Prueba que cualquier otro método (GET) responda ERROR"""
    # Incluso con headers validos, el GET debe fallar
    token = generate_valid_token()
    headers = {
        "X-Parse-REST-API-Key": API_KEY_EXPECTED,
        "X-JWT-KWY": token
    }
    
    response = client.get("/DevOps", headers=headers)
    
    # El requisito dice: Cualquier otro método HTTP debe responder: "ERROR"
    assert response.text == "ERROR"
    assert response.status_code == 405

def test_jwt_replay_attack():
    """Prueba que un mismo JWT no pueda usarse dos veces (Unicidad por transacción)"""
    token = generate_valid_token()
    headers = {
        "X-Parse-REST-API-Key": API_KEY_EXPECTED,
        "X-JWT-KWY": token
    }
    data = {"message": "test", "to": "Juan", "from": "Rita", "timeToLifeSec": 45}
    
    # Primera llamada: Éxito
    response1 = client.post("/DevOps", json=data, headers=headers)
    assert response1.status_code == 200
    
    # Segunda llamada con MISMO token: Fallo
    response2 = client.post("/DevOps", json=data, headers=headers)
    assert response2.status_code == 401