import requests
import time

TARGET_IP = "http://127.0.0.1:8000"  # Alvo do ataque servidor local/loopback
ATTEMPTS = 60  # Número de tentativas

for i in range(ATTEMPTS):
    try:
        response = requests.get(TARGET_IP)
        print(f"Tentativa {i+1}, Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Erro na tentativa {i+1}: {e}")

    time.sleep(0.1)  # Delay de 100ms entre as entativas