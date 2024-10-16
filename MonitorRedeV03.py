import streamlit as st
import time
import subprocess
import sys
import pandas as pd
from collections import defaultdict, deque
import datetime
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

# Lista as interfaces de rede disponíveis
available_interfaces = get_if_list()
valid_interfaces = [iface for iface in available_interfaces if get_if_hwaddr(iface) != "00:00:00:00:00:00" or iface == r"\Device\NPF_Loopback"]

# Se não houver interfaces ele avisa o usuário
if not valid_interfaces:
    st.warning("Nenhuma interface de rede válida encontrada.")
else:
    # Se houver interfaces disponíveis permite ao usuário escolher uma
    interface = st.sidebar.selectbox("Selecione a interface de rede", valid_interfaces)

    # Cria um dataframe para armazenar pacotes capturados
    packet_log = pd.DataFrame(columns=["Protocolo", "Origem", "Destino", "Hora"])

    # Variáveis para detecção de anomalias
    brute_force_attempts = defaultdict(lambda: deque(maxlen=50))  # Armazena os tempos das tentativas de força bruta por IP
    ddos_packet_times = defaultdict(lambda: deque(maxlen=1000))  # Armazena os tempos dos pacotes recebidos por IP
    ALERT_DDOS_THRESHOLD = 500  # Limite de pacotes por IP para detectar DDoS
    BRUTE_FORCE_THRESHOLD = 15  # Limite de tentativas de conexão para detectar força bruta
    TIME_WINDOW_DDOS = 10  # Janela de tempo em segundos para verificar pacotes para DDoS
    TIME_WINDOW_BRUTE_FORCE = 10  # Janela de tempo em segundos para verificar tentativas de força bruta

##### Funções de Captura e Monitoramento ###################################################################################################
    def packet_handler(packet):
        # Verifica se o pacote tem uma camada IP
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "Desconhecido"
            current_time = datetime.datetime.now()

            # Identifica o protocolo
            if TCP in packet:
                protocol = "TCP"
                if packet[TCP].flags == "S":  # Tentativa de conexão TCP (SYN)
                    brute_force_attempts[src_ip].append(current_time)
                    # Verifica quantas tentativas ocorreram dentro da janela de tempo definida
                    recent_attempts = [t for t in brute_force_attempts[src_ip] if (current_time - t).seconds <= TIME_WINDOW_BRUTE_FORCE]
                    if len(recent_attempts) >= BRUTE_FORCE_THRESHOLD:
                        st.warning(f"Possível ataque de força bruta detectado do IP: {src_ip}")
                        brute_force_attempts[src_ip].clear()  # Reseta o contador após o alerta
            elif UDP in packet:
                protocol = "UDP"

            # Monitoramento de DDoS, ignorando o loopback para evitar falsos-positivos
            if src_ip != "127.0.0.1":
                ddos_packet_times[src_ip].append(current_time)
                # Remove tempos de pacotes fora da janela de tempo para DDoS
                recent_packets = [t for t in ddos_packet_times[src_ip] if (current_time - t).seconds <= TIME_WINDOW_DDOS]
                if len(recent_packets) > ALERT_DDOS_THRESHOLD:
                    st.error(f"Possível ataque DDoS detectado do IP: {src_ip}")
                    ddos_packet_times[src_ip].clear()  # Reseta o contador após o alerta

            # Formata a hora atual para exibir no log
            timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")

            # Adiciona os dados ao log de pacotes
            global packet_log
            packet_log = packet_log.append(
                {"Protocolo": protocol, "Origem": src_ip, "Destino": dst_ip, "Hora": timestamp},
                ignore_index=True
            )

            # Atualiza o dashboard do Streamlit em tempo real
            with placeholder:
                st.dataframe(packet_log.tail(10), height=300)  # Ajusta altura para mostrar exatamente 10 pacotes

    def start_sniffing(interface):
        global monitoring
        st.write(f"Capturando pacotes na interface {interface}...")

        while monitoring:
            sniff(iface=interface, prn=packet_handler, store=False)
            time.sleep(1)  # Delay para evitar sobrecarga

    def stop_monitoring():
        global monitoring
        monitoring = False
        st.session_state["monitoring"] = False
        st.write("Monitoramento interrompido.")

##### Controle de Interface ###################################################################################################
    # Placeholder para o log dos pacotes
    placeholder = st.empty()

    # Colunas para botoes de controle
    col1, col2 = st.columns(2)
    
    with col1:
        if not monitoring and st.button("Iniciar Monitoramento"):
            packet_log = packet_log[0:0]  # Limpa o log de pacotes
            monitoring = True
            st.session_state["monitoring"] = True
            start_sniffing(interface)

    with col2:
        if monitoring and st.button("Parar Monitoramento"):
            stop_monitoring()

    # Exibe o log de pacotes
    if not packet_log.empty:
        st.dataframe(packet_log.tail(10), height=300)

    # Botão para limpar o log de pacotes
    if st.button("Limpar Log"):
        packet_log = packet_log[0:0]
        st.write("Log zerado. Pronto para a captura de novos pacotes.")

### PARA EXECUTAR, ACESSE NO TERMINAL, COMO ADMINISTRADOR, A PASTA ONDE O CODIGO ESTÁ E EXECUTE O STREAMLIT ASSIM: "streamlit run MonitorRedeV2.py"