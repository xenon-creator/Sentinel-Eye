import re
from datetime import datetime
import database


AUTH_LOG_PATTERNS = {
    "ssh_failed": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"),
    "ssh_accept": re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"),
    "sudo_fail": re.compile(r"FAILED login attempt"),
    "ssh_invalid": re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)"),
}

SYSLOG_PATTERNS = {
    "sshd": re.compile(r"sshd\[(\d+)\]: (.*)"),
    "sudo": re.compile(r"sudo\[(\d+)\]: (.*)"),
    "kernel": re.compile(r"kernel: \[.*\] (.*)"),
}


def parse_auth_log_line(line):
    for name, pattern in AUTH_LOG_PATTERNS.items():
        match = pattern.search(line)
        if match:
            if name == "ssh_failed":
                return {
                    "type": "ssh_failed_login",
                    "username": match.group(1),
                    "ip": match.group(2),
                    "raw": line.strip()
                }
            elif name == "ssh_accept":
                return {
                    "type": "ssh_accepted",
                    "username": match.group(1),
                    "ip": match.group(2),
                    "raw": line.strip()
                }
            elif name == "ssh_invalid":
                return {
                    "type": "ssh_invalid_user",
                    "username": match.group(1),
                    "ip": match.group(2),
                    "raw": line.strip()
                }
    return None


def parse_syslog_line(line):
    match = SYSLOG_PATTERNS["sshd"].search(line)
    if match:
        return {
            "type": "sshd",
            "raw": line.strip()
        }
    return None


def parse_log_line(line, source):
    result = parse_auth_log_line(line)
    if result:
        return result
    if "syslog" in source.lower():
        return parse_syslog_line(line)
    return None


def parse_pcap_packet(packet):
    if not packet.haslayer("IP"):
        return None

    src_ip = packet["IP"].src
    dst_ip = packet["IP"].dst
    proto = packet.proto if hasattr(packet, "proto") else None

    result = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "length": packet.len
    }

    if packet.haslayer("TCP"):
        result["sport"] = packet["TCP"].sport
        result["dport"] = packet["TCP"].dport
        result["flags"] = str(packet["TCP"].flags)
    elif packet.haslayer("UDP"):
        result["sport"] = packet["UDP"].sport
        result["dport"] = packet["UDP"].dport

    return result