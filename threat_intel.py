import time
import requests
from config import VIRUSTOTAL_API_KEY


rate_limit_time = 0
MIN_REQUEST_INTERVAL = 16


def check_ip(ip):
    if not VIRUSTOTAL_API_KEY:
        return None

    global rate_limit_time
    current_time = time.time()

    if current_time - rate_limit_time < MIN_REQUEST_INTERVAL:
        time.sleep(MIN_REQUEST_INTERVAL - (current_time - rate_limit_time))

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 429:
            rate_limit_time = time.time()
            return None

        if response.status_code == 404:
            return {"malicious": 0, "total": 0, "permalink": ""}

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = malicious + suspicious + stats.get("undetected", 0) + stats.get("harmless", 0) + stats.get("timeout", 0)

            permalink = f"https://www.virustotal.com/gui/ip-address/{ip}"

            rate_limit_time = time.time()

            return {
                "malicious": malicious + suspicious,
                "total": total,
                "permalink": permalink
            }

    except Exception:
        pass

    return None