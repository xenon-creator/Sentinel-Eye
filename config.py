import os
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60

PORT_SCAN_PORT_COUNT = 10
PORT_SCAN_WINDOW = 30

DATABASE_PATH = "soc_data.db"

LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "sample.log"
]

REFRESH_INTERVAL = 2

LOG_COLORS = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "yellow",
    "LOW": "yellow"
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}