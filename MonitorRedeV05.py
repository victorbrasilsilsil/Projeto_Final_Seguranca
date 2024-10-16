import streamlit as st
import time
import subprocess
import sys
import pandas as pd
from collections import defaultdict, deque
import datetime

# Verifica se o Scapy tá instalado e instala se nao tiver
try:
    from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_hwaddr
except ImportError:
    # Instala o Scapy se não estiver disponivel
    st.warning("Scapy não encontrado. Instalando agora...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_hwaddr

#### Configurações do STREAMLIT #################################################################################################
# Titulo do Dashboard
st.title("Monitor de Tráfego de Rede em Tempo Real")

# Introdução da aplicação
st.markdown(
    '''
    Este aplicativo monitora o tráfego de rede em tempo real, capturando pacotes
    e exibindo informações importantes, como IP de origem, IP de destino e protocolo.
    Para iniciar o monitoramento, clique no botão abaixo.
    '''
)

# Variavel de estado para controlar a execução
monitoring = st.session_state.get("monitoring", False)

# Barra lateral para configurar a interface de rede
# Lista as interfaces de rede disponíveis
available_interfaces = get_if_list()

# Filtra interfaces que possuem endereços MAC válidos (excluindo "00:00:00:00:00:00" e similares)
valid_interfaces = [iface for iface in available_interfaces if get_if_hwaddr(iface) != "00:00:00:00:00:00" or iface == r"\Device\NPF_Loopback"]

# Exibe todas as interfaces encontradas
st.write("Interfaces disponíveis:")
for iface in valid_interfaces:
    st.write(f"Interface: {iface}, Endereço MAC: {get_if_hwaddr(iface)}")

# Se não houver interfaces ele avisa o usuário
if not valid_interfaces:
    st.warning("Nenhuma interface de rede válida encontrada.")
else:
    # Se houver interfaces disponíveis permite ao usuário escolher uma
    interface = st.sidebar.selectbox("Selecione a interface de rede", valid_interfaces)

    # Contador de pacotes capturados
    packet_count = st.sidebar.number_input("Número de pacotes a capturar por vez", min_value=1, value=10, step=1)

    # Cria um dataframe para armazenar pacotes capturados
    packet_log = pd.DataFrame(columns=["Protocolo", "Origem", "Destino", "Hora"])

    # Variáveis para detecção de anomalias
    suspicious_ip_count = defaultdict(int)
    brute_force_attempts = defaultdict(lambda: deque(maxlen=20))  # Armazena os tempos das tentativas de cada IP
    last_activity_time = defaultdict(lambda: datetime.datetime.now())  # Armazena o tempo da última atividade de cada IP
    ip_packet_times = defaultdict(lambda: deque(maxlen=100))  # Armazena os tempos dos pacotes de cada IP
    ALERT_THRESHOLD = 150  # Limite para detectar DDoS
    BRUTE_FORCE_THRESHOLD = 5  # Limite de tentativas para ataques de Força Bruita
    TIME_WINDOW = 10  # Janela de tempo (segundos) para verificar o número de pacotes (para DDoS)
    RESET_TIME = 10  # Tempo em (segundos) para redefinir o contador de tentativas de Força Bruta

##### Configurações da APLICAÇÃO ###################################################################################################
    # Função para tratar pacotes capturados
    def packet_handler(packet):
        # Verifica se o pacote tem uma camada IP
        if IP in packet:
            # Extrai as informações relevantes do pacote
            src_ip = packet[IP].src    # IP de origem
            dst_ip = packet[IP].dst    # IP de destino
            protocol = "Desconhecido"  # Protocolo padrão

            # Atualiza o tempo da última atividade do IP
            current_time = datetime.datetime.now()
            last_activity_time[src_ip] = current_time

            # Verifica se o pacote é TCP ou UDP e define o protocolo que será usado
            if TCP in packet:
                protocol = "TCP"
                # Verifica pacotes TCP com flag SYN ou SYN/ACK (indicando tentativa de conexão)
                if packet[TCP].flags in ["S", "SA"]:
                    brute_force_attempts[src_ip].append(current_time)
                    # Verifica quantas tentativas ocorreram dentro da janela de tempo definida
                    recent_attempts = [t for t in brute_force_attempts[src_ip] if (current_time - t).seconds <= TIME_WINDOW]
                    if len(recent_attempts) > BRUTE_FORCE_THRESHOLD:
                        st.warning(f"Possível ataque de força bruta detectado do IP: {src_ip}")
                        brute_force_attempts[src_ip].clear()  # Limpa o contador de tentativas depois de detectar o ataque
            elif UDP in packet:
                protocol = "UDP"

            # Formatando a hora atual para exibir com o pacote capturado na tabela
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            # Adiciona os dados ao log de pacotes
            global packet_log
            packet_log = packet_log.append(
                {"Protocolo": protocol, "Origem": src_ip, "Destino": dst_ip, "Hora": timestamp},
                ignore_index=True
            )

            # Detecção de DDoS baseada em taxa de pacotes
            ip_packet_times[src_ip].append(current_time)
            # Verifica quantos pacotes foram recebidos do mesmo IP dentro da janela de tempo definida
            recent_packets = [t for t in ip_packet_times[src_ip] if (current_time - t).seconds <= TIME_WINDOW]
            if len(recent_packets) > ALERT_THRESHOLD:
                st.error(f"Possível ataque DDoS detectado do IP: {src_ip}")

            # Para exibir o log atualizado no dash do streamlit em tempo real
            with placeholder:
                st.dataframe(packet_log.tail(10), height=300)  # Ajusta altura da tab para mostrar só 10 pacotes

    # Função que inicia a captura de pacotes
    def start_sniffing(interface, count):
        global monitoring
        st.write(f"Capturando pacotes na interface {interface}...")

        while monitoring:
            sniff(iface=interface, prn=packet_handler, count=count, store=False)
            # Redefinir contadores de força bruta se não houver atividade recente
            current_time = datetime.datetime.now()
            for ip in list(brute_force_attempts.keys()):
                if (current_time - last_activity_time[ip]).seconds > RESET_TIME:
                    brute_force_attempts[ip].clear()
            time.sleep(1)  # dando um delay para evitar a sobrecarga

    # Função para parar o monitoramento
    def stop_monitoring():
        global monitoring
        monitoring = False
        st.session_state["monitoring"] = False
        st.write("Monitoramento interrompido.")

#####################################################################################################################

    # Placeholder para o log dos pacotes
    placeholder = st.empty()

    # Para os botões de controle e mantém o botão de parar visível ------ REMOVER DEPOIS
    col1, col2 = st.columns(2)
    
    with col1:
        # Botão para iniciar o monitoramento continuo
        if not monitoring and st.button("Iniciar Monitoramento"):
            # Limpa o dataframe de pacotes quando inicia uma nova captura
            packet_log = packet_log[0:0]
            monitoring = True
            st.session_state["monitoring"] = True
            start_sniffing(interface, packet_count)  # Inicia captura continua

    with col2:
        # Botão para parar o monitoramento
        if monitoring and st.button("Parar Monitoramento"):
            stop_monitoring()

    # Exibe o log de pacotes se existirem dados capturados
    if not packet_log.empty:
        st.dataframe(packet_log.tail(10), height=300)  # Ajusta altura para mostrar exatamente 10 pacotes

    # Botão para limpar o log de pacotes
    if st.button("Limpar Log"):
        packet_log = packet_log[0:0]
        st.write("Log zerado. Pronto para a captura de novos pacotes.")

### PARA EXECUTAR, ACESSE NO TERMINAL, COMO ADMINISTRADOR, A PASTA ONDE O CODIGO ESTÁ E EXECUTE O STREAMLIT ASSIM: "streamlit run MonitorRedeV2.py"