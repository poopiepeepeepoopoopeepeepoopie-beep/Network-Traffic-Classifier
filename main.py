import sys
from scapy.all import rdpcap, Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS
import pandas as pd

# Well-known ports -> service name (application-level classification by port)
PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 587: "SMTP", 631: "IPP (printing)",
    993: "IMAPS", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 8080: "HTTP-alt",
}


def classify_service(protocol, src_port, dst_port):
    """Name the service from whichever endpoint uses a well-known port."""
    if protocol in ("ARP", "ICMP", "ICMPv6"):
        return protocol
    for port in (dst_port, src_port):
        if port is not None and int(port) in PORT_SERVICES:
            return PORT_SERVICES[int(port)]
    return "Other / ephemeral" if src_port is not None else "Other"


import os

DATASET_DIR = "Datasets"

# Usage:  python main.py SkypeIRC.cap      (looked up inside Datasets/)
name = sys.argv[1] if len(sys.argv) > 1 else "traffic.pcap"
pcap_file = name if os.path.exists(name) else os.path.join(DATASET_DIR, name)

if not os.path.exists(pcap_file):
    print(f"File not found: {pcap_file}")
    print("Available captures:", os.listdir(DATASET_DIR) if os.path.isdir(DATASET_DIR) else "Datasets/ folder missing")
    raise SystemExit

# 1. Read the PCAP file
print(f"Reading network packets from {pcap_file} ...")
packets = rdpcap(pcap_file)

records = []

# 2. Process each packet
for packet in packets:
    src_ip = "Unknown"
    dst_ip = "Unknown"
    src_port = None
    dst_port = None
    protocol = "Other"

    # Extract IP addresses
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    elif ARP in packet:
        # ARP is not IP, but it still carries IPv4 addresses
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    # Classify the protocol
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    elif IPv6 in packet and packet[IPv6].nh == 58:   # next header 58 = ICMPv6
        protocol = "ICMPv6"
    elif ARP in packet:
        protocol = "ARP"

    # DNS is carried over UDP/TCP, so label it separately
    if DNS in packet:
        protocol = "DNS"

    # 3. Save extracted information
    records.append({
        "Timestamp": float(packet.time),
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Source Port": src_port,
        "Destination Port": dst_port,
        "Protocol": protocol,
        "Service": classify_service(protocol, src_port, dst_port),
        "Packet Size (bytes)": len(packet),
    })

# 4. Convert records to a DataFrame
df = pd.DataFrame(records)

if df.empty:
    print("No packets found.")
else:
    # 5. Display traffic statistics
    print("\n===== TRAFFIC REPORT =====")
    print("Total packets:", len(df))
    print("Total data:", df["Packet Size (bytes)"].sum(), "bytes")

    print("\n===== PACKET COUNTS BY PROTOCOL =====")
    print(df["Protocol"].value_counts().to_string())

    print("\n===== DATA VOLUME BY PROTOCOL =====")
    print(
        df.groupby("Protocol")["Packet Size (bytes)"]
        .sum()
        .sort_values(ascending=False)
        .to_string()
    )

    print("\n===== PACKET COUNTS BY SERVICE =====")
    print(df["Service"].value_counts().to_string())

    print("\n===== FIRST 10 PACKETS =====")
    print(df.head(10).to_string(index=False))

    # 6. Export packet records
    df.to_csv("packet_analysis.csv", index=False)

    print("\nAnalysis saved to packet_analysis.csv")
