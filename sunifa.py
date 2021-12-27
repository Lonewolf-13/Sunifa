#!/usr/bin/python3 
import sys,os,time
from socket import *
from scapy import interfaces
from scapy.all import *
from colorama import Fore
from scapy.utils import PcapWriter
from scapy.all import TCP,UDP,IP,ICMP



banner="""
                                            ░██████╗██╗░░░██╗███╗░░██╗██╗███████╗░█████╗░
                                            ██╔════╝██║░░░██║████╗░██║██║██╔════╝██╔══██╗
                                            ╚█████╗░██║░░░██║██╔██╗██║██║█████╗░░███████║
                                            ░╚═══██╗██║░░░██║██║╚████║██║██╔══╝░░██╔══██║
                                            ██████╔╝╚██████╔╝██║░╚███║██║██║░░░░░██║░░██║
                                            ╚═════╝░░╚═════╝░╚═╝░░╚══╝╚═╝╚═╝░░░░░╚═╝░░╚═╝
                    S U N I F A
                            B Y O C C U P Y ''THE'' W E B
"""

print(Fore.LIGHTWHITE_EX + banner)
print("\n[>>>] Packet Sniffer initialized. Waiting for incoming "
                "data. Press Ctrl-C to abort...\n")

def help():
    print(Fore.LIGHTRED_EX)
    print('Hello Friend!!')
    print('*'*60)
    print('Sniffing and Save in Pcap File')
    print('Usage: sudo ./Sunifa.py [Interface name] w [Pcap File Name .pcap]')
    print('Example: sudo ./Sunifa.py eth0 w file.pcap ')
    print('*'*60)
    print('Read Pcap Files')
    print('Usage: sudo ./Sunifa [Interface name] r [Pcap File Name .pcap]')
    print('Example: sudo ./Sunifa eth0 r file.pcap')
    print('*'*60)
    print(Fore.LIGHTMAGENTA_EX + "ICMP")
    print(Fore.LIGHTBLUE_EX + "TCP")
    print(Fore.LIGHTGREEN_EX  + "UDP")
    print(f'{Fore.LIGHTRED_EX}\n[^-^] スニファー [^-^] ')


def anlz(pkt):

    try:
        src_ip = pkt[IP].src 
        dst_ip = pkt[IP].dst 
        mac_src = pkt.src  
        mac_dst = pkt.dst  

        if switChar == 'w':
            write(pcap_file,pkt)
        elif switChar == 'r':
            read(pcap_file)
            
        else:
            print(f'{Fore.LIGHTRED_EX} [!] This Switch "{switChar}" not found you can use only [r] for read or [w] for writing data and save in files [!]')
            exit()

        if pkt.haslayer(ICMP):
            size_packet = len(pkt[ICMP]) 
            print(f'{Fore.LIGHTMAGENTA_EX} ICMP ip.src: {src_ip} > ip.dst: {dst_ip}, mac.src: {mac_src} > mac.dst: {mac_dst} ,proto: icmp, len: {size_packet}')

        else: 
            ttl = pkt[IP].ttl
            lenght = pkt[IP].len 
            proto = pkt[IP].proto 
            
            if pkt.haslayer(TCP):
                flag = pkt[TCP].flags
                wind = pkt[IP].window
                seq = pkt[IP].seq
                port_src = pkt[TCP].sport
                port_dst = pkt[TCP].dport
                sport = getSport(port_src)
                dport = getDport(port_dst)

                print(f'{Fore.LIGHTBLUE_EX} TCP src.ip: {src_ip}:{sport} > dst.ip: {dst_ip}:{dport}, mac.src: {mac_src} > mac.dst :{mac_dst}, proto: {proto}, Flag: {flag}, seq: {seq}, wind: {wind} , ttl: {ttl} , len: {lenght}')
                
            elif pkt.haslayer(UDP):
               port_src = pkt[UDP].sport
               port_dst = pkt[UDP].dport
               sport = getSport(port_src)
               dport = getDport(port_dst)
               print(f'{Fore.LIGHTGREEN_EX} UDP src.ip: {src_ip}:{sport} > dst.ip: {dst_ip}:{sport}  src.mac: {mac_src} > dst.mac: {mac_dst}, proto: {proto},ttl: {ttl}')
                
    except Exception:
        pass


def read(file):
    pktdump = rdpcap(filename=file)
    print(pktdump)
    print(pktdump.summary())
    sys.exit(1)

def write(file,pkt):
    pktdump = PcapWriter(filename=file, append=True, sync=True)
    pktdump.write(pkt)


def getSport(sport):
    try:
        service = getservbyport(sport)
    except:
        return sport
    else:
        return service

def getDport(dport):
    try:
        service = getservbyport(dport)
    except:
        return dport
    else:
        return service


if __name__=='__main__':
    try:
        interface = sys.argv[1]
        switChar = sys.argv[2]
        pcap_file = sys.argv[3]
    except Exception:
        help()
        exit()    

try:
    if len(sys.argv) == 4:
        sniff(iface=interface, prn=anlz)
    else:
        help()
except PermissionError:
    print(f'{Fore.RED}Operation not permitted ')
    if sys.platform() == 'linux':
        print('Try Sudo')


print(f'\n {Fore.LIGHTYELLOW_EX}To see the data and Packets well and understandable, try Wireshark')

