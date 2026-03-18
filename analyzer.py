from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.packet import Raw

# Try importing HTTP (may not work on all systems)
try:
    from scapy.layers.http import HTTPRequest
    HTTP_AVAILABLE = True
except:
    HTTP_AVAILABLE = False


def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        print("\n==============================")
        print(f"[IP] {ip_layer.src} --> {ip_layer.dst}")

        # Protocol detection
        if packet.haslayer(TCP):
            print("[+] Protocol: TCP")

        elif packet.haslayer(UDP):
            print("[+] Protocol: UDP")

        # DNS detection
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:  # DNS request
                try:
                    print(f"[DNS Request] {dns.qd.qname.decode()}")
                except:
                    print("[DNS Request] Unable to decode")

        # HTTP URL detection
        if HTTP_AVAILABLE and packet.haslayer(HTTPRequest):
            try:
                host = packet[HTTPRequest].Host.decode()
                path = packet[HTTPRequest].Path.decode()
                url = f"http://{host}{path}"
                print(f"[HTTP] {url}")
            except:
                pass

        # Credential detection
        detect_credentials(packet)


def detect_credentials(packet):
    if packet.haslayer(Raw):
        try:
            load = packet[Raw].load.decode(errors="ignore")
            keywords = ["username", "user", "login", "password", "pass"]

            for keyword in keywords:
                if keyword in load.lower():
                    print("\n[!!!] Possible Credentials Found:")
                    print(load)
                    break
        except:
            pass