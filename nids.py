from scapy.all import TCP, IP, UDP, sniff
import time
import os
import platform

limite_pacotes = 3000
tempo_por_sg = 50
historico = []
historico_udp = []

os.system("cls" if os.name == "nt" else "clear")

def main(pacote):
    if IP in pacote:
        if TCP in pacote:
            pacotes_tcp(pacote)
        elif UDP in pacote:
            pacotes_UDP(pacote)

def pacotes_tcp(pacote):
        if IP in pacote and TCP in pacote:
            porta_src_TCP = pacote[TCP].sport
            porta_dst_TCP = pacote[TCP].dport
            Origem_IP = pacote[IP].src
            Destino_IP = pacote[IP].dst
            Flags = pacote[TCP].flags
            Flags_str = str(pacote[TCP].flags)
            Flags_str_real = pacote.sprintf('%TCP.flags%')
            tempo = time.time()
            print(f"IP: {Origem_IP}, Destino: {Destino_IP}, Portas: {porta_src_TCP} - {porta_dst_TCP}, Flags: {Flags_str_real} ({Flags})")

            historico.append({"IP": Origem_IP,"Dst_IP": Destino_IP,"Scr_Porta": porta_src_TCP,"Dst_Porta": porta_dst_TCP,"Flags": Flags,"Tempo": tempo })
         
        limite = tempo - tempo_por_sg
        for item in historico[:]:
            if item["Tempo"] < limite:
                historico.remove(item)

        contagem_por_ip = {}
        for item in historico:
            ip = item["IP"]
            contagem_por_ip[ip] = contagem_por_ip.get(ip, 0) + 1

            for ip, contagem in contagem_por_ip.items():
                if contagem > limite_pacotes:
                    print(f"Possivel DoS-DDoS TCP - IP: {ip} | Pacotes: {contagem} | Flags: {Flags_str_rel} ({Flags})")
            for item in historico[:]:
                if item["IP"] == ip:
                    historico.remove(item)

def pacotes_UDP(pacote):
        if pacote.haslayer(UDP):
            ip_src = pacote[0][1].src
            ip_dst = pacote[0][1].dst
            sport = pacote[UDP].sport
            dport = pacote[UDP].dport
            tempo = time.time()

            print(f"UDP: {ip_src}:{sport} Destino: {ip_dst}:{dport}")

            historico_udp.append({"IP": ip_src,"Dst_IP": ip_dst,"Scr_Porta": sport,"Dst_Porta": dport,"Tempo": tempo})
            
            limite = tempo - tempo_por_sg
            for item in historico_udp[:]:
                if item["Tempo"] < limite:
                    historico_udp.remove(item)

        contagem_por_ip = {}
        for item in historico_udp:
            ip = item["IP"]
            contagem_por_ip[ip] = contagem_por_ip.get(ip, 0) + 1

        for ip, contagem in contagem_por_ip.items():
            if contagem > limite_pacotes:
                print(f"Possivel DoS-DDoS UDP - IP: {ip} | Pacotes: {contagem}")
                for item in historico_udp[:]:
                    if item["IP"] == ip:
                        historico_udp.remove(item)

if __name__ == "__main__":
    RPST = input("Digite sua interface: ")
    sniff(iface=RPST, filter="tcp or udp", prn=main, store=False)
