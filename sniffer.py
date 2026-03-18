from scapy.all import sniff
from analyzer import process_packet

def start_sniffing():
    print("[+] Packet Sniffer Started...\n")
    
    # Capture packets (you can change filter if needed)
    sniff(filter="tcp or udp", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()