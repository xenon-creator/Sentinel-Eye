import os
from config import PORT_SCAN_PORT_COUNT, PORT_SCAN_WINDOW
import database
from parser import parse_pcap_packet
from detector import analyze_packet
import threat_intel


def analyze_pcap_file(filepath):
    if not os.path.exists(filepath):
        return {"error": "File not found"}

    try:
        from scapy.all import rdpcap

        packets = rdpcap(filepath)
        ip_ports = {}

        for pkt in packets:
            parsed = parse_pcap_packet(pkt)
            if parsed and "src_ip" in parsed:
                ip = parsed["src_ip"]
                if "dport" in parsed:
                    port = parsed["dport"]

                    if ip not in ip_ports:
                        ip_ports[ip] = set()

                    ip_ports[ip].add(port)

        alerts_created = 0

        for ip, ports in ip_ports.items():
            if len(ports) >= PORT_SCAN_PORT_COUNT:
                details = f"Port scan detected in PCAP: {len(ports)} ports"
                alert_id = database.insert_alert(
                    threat_type="Port Scan",
                    source_ip=ip,
                    severity="MEDIUM",
                    details=details
                )
                alerts_created += 1

                threat_intel.check_ip(ip)

        return {
            "packets": len(packets),
            "unique_ips": len(ip_ports),
            "alerts_created": alerts_created
        }

    except ImportError:
        return {"error": "Scapy not installed"}
    except Exception as e:
        return {"error": str(e)}


def start_live_capture(interface=None, packet_count=100):
    try:
        from scapy.all import sniff

        def packet_callback(pkt):
            parsed = parse_pcap_packet(pkt)
            analyze_packet(parsed)

        packets = sniff(iface=interface, count=packet_count, timeout=10, prn=packet_callback)

        return {"captured": len(packets)}

    except ImportError:
        return {"error": "Scapy not installed"}
    except Exception as e:
        return {"error": str(e)}