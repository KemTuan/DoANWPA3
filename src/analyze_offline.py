# analyze_offline.py
from scapy.all import rdpcap
from src.analyzer import Wpa3Analyzer

def process_lab_data(pcap_file):
    packets = rdpcap(pcap_file)
    stats = {"sae_handshakes": 0, "downgrade_attempts": 0}
    
    for pkt in packets:
        if Wpa3Analyzer.is_sae_auth(pkt):
            stats["sae_handshakes"] += 1
        if Wpa3Analyzer.detect_downgrade(pkt):
            stats["downgrade_attempts"] += 1
            
    print(f"Kết quả phân tích: {stats}")

if __name__ == "__main__":
    process_lab_data("data/lab_data.pcap")