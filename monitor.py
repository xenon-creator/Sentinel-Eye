import os
import time
import threading
import database
from parser import parse_log_line
from detector import analyze_log
from config import LOG_PATHS


class LogMonitor:
    def __init__(self):
        self.running = False
        self.threads = []
        self.file_positions = {}
        self.latest_log = None

    def tail_file(self, filepath):
        if not os.path.exists(filepath):
            return

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, 2)

                while self.running:
                    line = f.readline()
                    if line:
                        line = line.strip()
                        parsed = parse_log_line(line, filepath)

                        database.insert_log(filepath, line)

                        analyze_log(parsed, filepath)
                        self.latest_log = (filepath, line)
                    else:
                        time.sleep(0.3)

        except Exception:
            pass

    def start(self):
        self.running = True

        for path in LOG_PATHS:
            if os.path.exists(path):
                thread = threading.Thread(target=self.tail_file, args=(path,), daemon=True)
                thread.start()
                self.threads.append(thread)

    def stop(self):
        self.running = False
        for thread in self.threads:
            thread.join(timeout=1)

    def get_latest_log(self):
        return self.latest_log


def start_monitoring():
    monitor = LogMonitor()
    monitor.start()
    return monitor


def stop_monitoring(monitor):
    monitor.stop()