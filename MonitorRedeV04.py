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

# Variaveis de sessão para controlar a execução
if "monitoring" not in st.session_state:
    st.session_state["monitoring"] = False
if "packet_log" not in st.session_state:
    st.session_state["packet_log"] = pd.DataFrame(columns=["Protocolo", "Origem", "Destino", "Hora"])
if "suspicious_ip_count" not in st.session_state:
    st.session_state["suspicious_ip_count"] = defaultdict(int)
if "brute_force_attempts" not in st.session_state:
    st.session_state["brute_force_attempts"] = defaultdict(lambda: deque(maxlen=20))
if "last_activity_time" not in st.session_state:
    st.session_state["last_activity_time"] = defaultdict(lambda: datetime.datetime.now())
if "ip_packet_times" not in st.session_state:
    st.session_state["ip_packet_times"] = defaultdict(lambda: deque(maxlen=100))

monitoring = st.session_state["monitoring"]
packet_log = st.session_state["packet_log"]

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

    # Placeholder para o log dos pacotes
    placeholder = st.empty()

    # Variáveis para detecção de anomalias
    suspicious_ip_count = st.session_state["suspicious_ip_count"]
    brute_force_attempts = st.session_state["brute_force_attempts"]
    last_activity_time = st.session_state["last_activity_time"]
    ip_packet_times = st.session_state["ip_packet_times"]
    ALERT_THRESHOLD = 150  # Limite para detectar DDoS
    BRUTE_FORCE_THRESHOLD = 5  # Reduzido para facilitar a detecção
    TIME_WINDOW = 10  # Janela de tempo em segundos para verificar o número de pacotes (para DDoS)
    RESET_TIME = 10  # Tempo em segundos para redefinir o contador de tentativas de força bruta

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
            st.session_state["last_activity_time"] = last_activity_time

            # Verifica se o pacote é TCP ou UDP e define o protocolo a ser usado
            if TCP in packet:
                protocol = "TCP"
                # Verifica pacotes TCP com flag SYN ou SYN/ACK (indicando tentativa de conexão)
                if packet[TCP].flags in ["S", "SA"]:
                    brute_force_attempts[src_ip].append(current_time)
                    st.session_state["brute_force_attempts"] = brute_force_attempts
                    # Verifica quantas tentativas ocorreram dentro da janela de tempo definida
                    recent_attempts = [t for t in brute_force_attempts[src_ip] if (current_time - t).seconds <= TIME_WINDOW]
                    if len(recent_attempts) > BRUTE_FORCE_THRESHOLD:
                        st.warning(f"Possível ataque de força bruta detectado do IP: {src_ip}")
                        brute_force_attempts[src_ip].clear()  # Limpa o contador de tentativas após detectar o ataque
                        st.session_state["brute_force_attempts"] = brute_force_attempts
            elif UDP in packet:
                protocol = "UDP"

            # Formata a hora atual para exibir com o pacote capturado
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            # Adiciona os dados ao log de pacotes (dataframe)
            packet_log = packet_log.append(
                {"Protocolo": protocol, "Origem": src_ip, "Destino": dst_ip, "Hora": timestamp},
                ignore_index=True
            )
            st.session_state["packet_log"] = packet_log

            # Detecção de DDoS baseada em taxa de pacotes
            ip_packet_times[src_ip].append(current_time)
            st.session_state["ip_packet_times"] = ip_packet_times
            # Verifica quantos pacotes foram recebidos do mesmo IP dentro da janela de tempo definida
            recent_packets = [t for t in ip_packet_times[src_ip] if (current_time - t).seconds <= TIME_WINDOW]
            if len(recent_packets) > ALERT_THRESHOLD:
                st.error(f"Possível ataque DDoS detectado do IP: {src_ip}")

            # Para exibir o log atualizado no dashboard do streamlit em tempo real
            with placeholder:
                st.dataframe(packet_log.tail(10), height=300)  # Ajusta altura para mostrar exatamente 10 pacotes

    # Função que inicia a captura de pacotes
    def start_sniffing(interface, count):
        st.write(f"Capturando pacotes na interface {interface}...")

        while st.session_state["monitoring"]:
            sniff(iface=interface, prn=packet_handler, count=count, store=False)
            time.sleep(1)  # Delay para evitar sobrecarga

    # Função para parar o monitoramento
    def stop_monitoring():
        st.session_state["monitoring"] = False
        st.write("Monitoramento interrompido.")

    #####################################################################################################################

    # Controle de botões para iniciar ou parar o monitoramento
    if not monitoring:
        if st.button("Iniciar Monitoramento"):
            # Limpa o dataframe de pacotes quando inicia uma nova captura
            st.session_state["packet_log"] = st.session_state["packet_log"][0:0]
            st.session_state["monitoring"] = True
            monitoring = True
    else:
        if st.button("Parar Monitoramento"):
            stop_monitoring()
            monitoring = False

    # Botão para limpar o log de pacotes
    if not packet_log.empty:
        if st.button("Limpar Log"):
            st.session_state["packet_log"] = packet_log[0:0]
            st.write("Log zerado. Pronto para a captura de novos pacotes.")

    # Exibe o log de pacotes se existirem dados capturados
    if not packet_log.empty:
        with placeholder:
            st.dataframe(packet_log.tail(10), height=300)  # Ajusta altura para mostrar exatamente 10 pacotes

### PARA EXECUTAR, ACESSE NO TERMINAL, COMO ADMINISTRADOR, A PASTA ONDE O CODIGO ESTÁ E EXECUTE O STREAMLIT ASSIM: "streamlit run MonitorRedeV2.py"