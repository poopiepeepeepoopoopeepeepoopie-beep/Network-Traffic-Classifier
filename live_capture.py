"""
Live packet capture -> live_packets.csv   (run this in its own terminal)

  python live_capture.py --list            show network interfaces
  python live_capture.py                   capture on the default interface
  python live_capture.py --iface "Wi-Fi"   capture on a chosen interface
  python live_capture.py --duration 60     stop automatically after 60 s

Windows: install Npcap (https://npcap.com) and run the terminal as Administrator.
Linux/macOS: run with sudo.   Only capture on networks you are authorised to monitor.
Press Ctrl+C to stop.
"""
import argparse
import csv
import time

from scapy.all import sniff, conf, ARP, IP, IPv6, TCP, UDP, ICMP, DNS

OUT_FILE = "live_packets.csv"
COLUMNS = ["Timestamp", "Source IP", "Destination IP", "Source Port",
           "Destination Port", "Protocol", "Service", "Packet Size (bytes)"]

PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 587: "SMTP", 631: "IPP (printing)",
    993: "IMAPS", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 8080: "HTTP-alt",
}


def classify_service(protocol, sport, dport):
    if protocol in ("ARP", "ICMP", "ICMPv6"):
        return protocol
    for port in (dport, sport):
        if port is not None and int(port) in PORT_SERVICES:
            return PORT_SERVICES[int(port)]
    return "Other / ephemeral" if sport is not None else "Other"


def extract(packet):
    """Same classification logic as main.py, for a single packet."""
    src = dst = "Unknown"
    sport = dport = None
    proto = "Other"

    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    elif ARP in packet:
        src, dst = packet[ARP].psrc, packet[ARP].pdst

    if TCP in packet:
        sport, dport, proto = packet[TCP].sport, packet[TCP].dport, "TCP"
    elif UDP in packet:
        sport, dport, proto = packet[UDP].sport, packet[UDP].dport, "UDP"
    elif ICMP in packet:
        proto = "ICMP"
    elif IPv6 in packet and packet[IPv6].nh == 58:
        proto = "ICMPv6"
    elif ARP in packet:
        proto = "ARP"
    if DNS in packet:
        proto = "DNS"

    return [float(packet.time), src, dst, sport, dport, proto,
            classify_service(proto, sport, dport), len(packet)]


def main():
    ap = argparse.ArgumentParser(description="Live capture to CSV")
    ap.add_argument("--iface", help="interface name (see --list)")
    ap.add_argument("--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("--duration", type=int, default=0, help="seconds (0 = until Ctrl+C)")
    ap.add_argument("--filter", default=None, help='BPF filter, e.g. "tcp port 443"')
    ap.add_argument("--offline", help="replay a pcap file instead of sniffing (for testing)")
    args = ap.parse_args()

    if args.list:
        print(conf.ifaces)
        return

    count = 0
    with open(OUT_FILE, "w", newline="") as f:      # start a fresh file each run
        writer = csv.writer(f)
        writer.writerow(COLUMNS)
        f.flush()

        def handle(packet):
            nonlocal count
            writer.writerow(extract(packet))
            f.flush()                               # so the dashboard sees it immediately
            count += 1
            if count % 50 == 0:
                print(f"\r{count} packets captured", end="", flush=True)

        print(f"Capturing on {args.iface or conf.iface} -> {OUT_FILE}  (Ctrl+C to stop)")
        try:
            if args.offline:
                sniff(offline=args.offline, prn=handle, store=False)
            else:
                sniff(iface=args.iface, prn=handle, store=False, filter=args.filter,
                      timeout=args.duration or None)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print("\nPermission denied: run the terminal as Administrator / with sudo.")
        print(f"\nStopped. {count} packets saved to {OUT_FILE}")


if __name__ == "__main__":
    main()