import time
from collections import defaultdict
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, PORT_SCAN_PORT_COUNT, PORT_SCAN_WINDOW
import database
import threat_intel


failed_logins = defaultdict(list)
port_scans = defaultdict(list)


def detect_brute_force(ip, parsed_log):
    current_time = time.time()
    failed_logins[ip].append(current_time)

    cutoff_time = current_time - BRUTE_FORCE_WINDOW
    failed_logins[ip] = [t for t in failed_logins[ip] if t > cutoff_time]

    if len(failed_logins[ip]) >= BRUTE_FORCE_THRESHOLD:
        details = f"{len(failed_logins[ip])} failed SSH attempts in {BRUTE_FORCE_WINDOW}s"
        alert_id = database.insert_alert(
            threat_type="Brute Force",
            source_ip=ip,
            severity="HIGH",
            details=details
        )

        check_ip_reputation(ip, alert_id)
        failed_logins[ip] = []
        return True

    return False


def detect_port_scan(ip, port):
    current_time = time.time()
    port_scans[ip].append((current_time, port))

    cutoff_time = current_time - PORT_SCAN_WINDOW
    port_scans[ip] = [(t, p) for t, p in port_scans[ip] if t > cutoff_time]

    unique_ports = set(p for t, p in port_scans[ip])

    if len(unique_ports) >= PORT_SCAN_PORT_COUNT:
        details = f"{len(unique_ports)} ports probed in {PORT_SCAN_WINDOW}s"
        alert_id = database.insert_alert(
            threat_type="Port Scan",
            source_ip=ip,
            severity="MEDIUM",
            details=details
        )

        check_ip_reputation(ip, alert_id)
        port_scans[ip] = []
        return True

    return False


def check_ip_reputation(ip, alert_id):
    if not ip:
        return

    try:
        result = threat_intel.check_ip(ip)
        if result and result.get("malicious", 0) > 0:
            db = database.get_connection()
            cursor = db.cursor()
            cursor.execute(
                "UPDATE alerts SET severity = ?, details = ? WHERE id = ?",
                ("CRITICAL", f"VT Score: {result['malicious']}/{result['total']} - {result.get('permalink', '')}", alert_id)
            )
            db.commit()
            db.close()
    except Exception:
        pass


def analyze_packet(packet_info):
    if not packet_info:
        return []

    alerts = []

    if "src_ip" in packet_info:
        ip = packet_info["src_ip"]
        if "dport" in packet_info:
            if detect_port_scan(ip, packet_info["dport"]):
                alerts.append("Port Scan Detected")

    return alerts


def analyze_log(parsed_log, source):
    if not parsed_log:
        return []

    alerts = []

    if parsed_log.get("type") in ["ssh_failed_login", "ssh_invalid_user"]:
        ip = parsed_log.get("ip")
        if ip:
            if detect_brute_force(ip, parsed_log):
                alerts.append("Brute Force Detected")

            database.insert_log(source, parsed_log["raw"])

    return alerts


def reset_detection_state():
    global failed_logins, port_scans
    current_time = time.time()
    cutoff = current_time - max(BRUTE_FORCE_WINDOW, PORT_SCAN_WINDOW)

    failed_logins = defaultdict(list, {k: [t for t in v if t > cutoff] for k, v in failed_logins.items()})
    port_scans = defaultdict(list, {k: [(t, p) for t, p in v if t > cutoff] for k, v in port_scans.items()})