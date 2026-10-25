import logging
import os
import sys

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'soc_lite.log')

# Custom formatter to match YYYY-MM-DD HH:MM:SS
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Store original stream handles to prevent recursion
original_stdout = sys.stdout
original_stderr = sys.stderr

# File handler
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

# Console handler (writes to original stdout)
console_handler = logging.StreamHandler(original_stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)

# Root logger configuration
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

# Clean existing handlers to avoid duplicates
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)

root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# Prevent Werkzeug request logs from spamming stdout/file logs
logging.getLogger('werkzeug').setLevel(logging.ERROR)

class StreamToLogger(object):
    """
    Redirects stdout/stderr writes to logging.info/logging.error
    """
    def __init__(self, logger, log_level=logging.INFO):
        self.logger = logger
        self.log_level = log_level

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            clean_line = line.rstrip()
            if clean_line:
                self.logger.log(self.log_level, clean_line)

    def flush(self):
        pass

# Redirect python print() statements and standard error outputs to the logging layer
sys.stdout = StreamToLogger(logging.getLogger('stdout'), logging.INFO)
sys.stderr = StreamToLogger(logging.getLogger('stderr'), logging.ERROR)

def get_log_lines(limit=40):
    """
    Reads the last N lines from the log file and returns them parsed.
    """
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        last_lines = lines[-limit:]
        parsed_lines = []
        for line in last_lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split(' - ', 2)
            if len(parts) >= 3:
                timestamp, level, message = parts[0], parts[1], parts[2]
                parsed_lines.append({
                    "timestamp": timestamp,
                    "level": level,
                    "message": message
                })
            else:
                parsed_lines.append({
                    "timestamp": "N/A",
                    "level": "INFO",
                    "message": line
                })
        return parsed_lines
    except Exception as e:
        return [{"timestamp": "N/A", "level": "ERROR", "message": f"Failed to read log file: {str(e)}"}]
