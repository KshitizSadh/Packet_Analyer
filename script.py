import argparse
import csv
import os
from datetime import datetime
from scapy.all import sniff, IP

# === Log File Paths ===
TEXT_LOG_FILE = "packet_log.txt"
CSV_LOG_FILE = "packet_log.csv"

# === Protocol Mapping ===
protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

# === Ensure log files exist ===
if not os.path.exists(TEXT_LOG_FILE):
    with open(TEXT_LOG_FILE, "w") as f:
        f.write("=== Packet Analyzer Log ===\n\n")

if not os.path.exists(CSV_LOG_FILE):
    with open(CSV_LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Protocol", "Source IP", "Destination IP", "Payload (Hex)"])

# === Packet Analyzer Function ===
def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        proto_name = protocol_map.get(proto_num, f"OTHER({proto_num})")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        payload = bytes(packet.payload)
        payload_snippet = payload[:100].hex()

        # Logging string
        log_entry = (
            f"[{timestamp}] Protocol: {proto_name}\n"
            f" Source IP      : {src_ip}\n"
            f" Destination IP : {dst_ip}\n"
            f" Payload (hex)  : {payload_snippet or 'None'}\n"
            f"{'-'*60}\n"
        )

        print(log_entry)

        # Append to text log
        with open(TEXT_LOG_FILE, "a") as f:
            f.write(log_entry)

        # Append to CSV log
        with open(CSV_LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, proto_name, src_ip, dst_ip, payload_snippet])

# === Main Sniffing Function ===
def main():
    parser = argparse.ArgumentParser(description="📡 Advanced Packet Analyzer with CSV Export")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on", required=True)
    parser.add_argument("-f", "--filter", type=str, help="BPF filter string (e.g., 'tcp', 'udp port 53')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    args = parser.parse_args()

    print("📡 Starting packet capture...")
    print("✅ Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=analyze_packet,
            store=False,
            count=args.count
        )
    except KeyboardInterrupt:
        print("\n🛑 Packet capture manually stopped.")
    except PermissionError:
        print("❌ Permission denied. Please run the script with admin/root privileges.")
    except Exception as e:
        print(f"⚠️ Unexpected Error: {e}")

if __name__ == "__main__":
    main()
