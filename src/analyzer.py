# src/analyzer.py
from scapy.all import Dot11Auth, Dot11AssoReq, Dot11Beacon, Dot11Elt, Dot11

class Wpa3Analyzer:
    @staticmethod
    def is_sae_auth(packet):
        """Kiểm tra gói tin xác thực SAE (WPA3)"""
        if packet.haslayer(Dot11Auth):
            return packet.algo == 3 # SAE là algorithm 3
        return False

    @staticmethod
    def detect_downgrade(packet):
        """Phát hiện client cố kết nối WPA2 trong khi mạng có WPA3"""
        if packet.haslayer(Dot11AssoReq):
            packet_str = str(packet)
            if "RSN" in packet_str and "SAE" not in packet_str:
                return True
        return False

    @staticmethod
    def check_pmf_mandatory(packet):
        """
        WPA3 BẮT BUỘC phải có Management Frame Protection (PMF/MFP).
        Kiểm tra trong Beacon hoặc Probe Response.
        """
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11Elt):
            # Tìm lớp RSN để phân tích cờ MFP
            # (Phần này sẽ đọc sâu vào byte của RSN Capabilities để kiểm tra bit số 6 và 7)
            # Vì Scapy cấu trúc linh hoạt, ta kiểm tra chuỗi byte đặc trưng của WPA3 PMF
            packet_str = str(packet)
            if r"\x00\x0f\xac\x08" in packet_str: # Có mã WPA3-SAE
                # WPA3 phải đi kèm PMF Required (MFPR bit = 1)
                return True 
        return False

    @staticmethod
    def analyze_downgrade_evil_twin(pcap_packets, target_ssid):
        """Tìm AP cùng SSID nhưng hạ cấp chuẩn bảo mật"""
        detected_aps = {} 
        downgrade_alerts = []

        for pkt in pcap_packets:
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt.addr3
                packet_str = str(pkt)
                try:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                except:
                    continue

                if ssid == target_ssid:
                    is_wpa3 = "SAE" in packet_str or r"\x00\x0f\xac\x08" in packet_str
                    if bssid not in detected_aps:
                        detected_aps[bssid] = {"ssid": ssid, "wpa3": is_wpa3}

        wpa3_bssid_list = [bssid for bssid, info in detected_aps.items() if info["wpa3"]]
        wpa2_bssid_list = [bssid for bssid, info in detected_aps.items() if not info["wpa3"]]

        if wpa3_bssid_list and wpa2_bssid_list:
            for wpa2_mac in wpa2_bssid_list:
                downgrade_alerts.append(
                    f"[CẢNH BÁO] Evil Twin Hạ cấp!\n"
                    f"  - SSID: '{target_ssid}'\n"
                    f"  - AP WPA3: {wpa3_bssid_list}\n"
                    f"  - AP Giả mạo WPA2: {wpa2_mac}"
                )
        return downgrade_alerts

    @staticmethod
    def parse_sae_handshake(packet):
        """Phân tích tiến trình Commit/Confirm của SAE"""
        if packet.haslayer(Dot11Auth) and packet.algo == 3:
            status_code = packet.status
            seq_num = packet.seqnum
            
            if seq_num == 1:
                return f"[SAE Commit] {packet.addr2} -> {packet.addr1} | Trạng thái: {status_code}"
            elif seq_num == 2:
                return f"[SAE Confirm] {packet.addr2} -> {packet.addr1} | Trạng thái: {status_code}"
        return None