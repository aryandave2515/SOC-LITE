import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'soc_lite.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ── Alerts ────────────────────────────────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            description TEXT,
            raw_data TEXT,
            mitre_technique TEXT
        )
    ''')

    # ── System Health ─────────────────────────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_health (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            defender_status TEXT,
            firewall_status TEXT,
            updates_status TEXT,
            defender_raw TEXT,
            firewall_raw TEXT
        )
    ''')

    # ── Legacy USB logs ───────────────────────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usb_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            drive_letter TEXT,
            files_transferred INTEGER
        )
    ''')

    # ── Rich USB Device Events ────────────────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usb_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            drive_letter TEXT,
            device_name TEXT,
            manufacturer TEXT,
            serial_number TEXT,
            device_type TEXT,
            username TEXT,
            hostname TEXT,
            event_id TEXT,
            severity TEXT,
            raw_data TEXT
        )
    ''')

    # ── File Transfer Events ──────────────────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_transfer_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            source_path TEXT,
            destination_path TEXT,
            file_name TEXT,
            file_extension TEXT,
            file_size_bytes INTEGER,
            operation TEXT,
            usb_device TEXT,
            drive_letter TEXT,
            sha256_hash TEXT,
            severity TEXT,
            detection_rule TEXT,
            raw_data TEXT
        )
    ''')

    # ── Linux Events Table ────────────────────────────────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS linux_events (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT,        -- ISO 8601 from log or agent
            received_at    TEXT,        -- when SOC-Lite received it
            hostname       TEXT,        -- Linux endpoint hostname
            service        TEXT,        -- syslog service/program name
            pid            TEXT,        -- process id (may be empty)
            source_file    TEXT,        -- /var/log/auth.log etc.
            event_type     TEXT,        -- e.g. SSH_FAILED_LOGIN
            severity       TEXT,        -- HIGH / MEDIUM / LOW
            message        TEXT,        -- parsed log message
            mitre_technique TEXT,       -- e.g. T1110.001
            raw            TEXT         -- original raw log line
        )
    ''')

    # ── Safe migrations ───────────────────────────────────────────────────────
    def _add_col(table, col, coltype="TEXT"):
        cursor.execute(f"PRAGMA table_info({table})")
        if col not in [c['name'] for c in cursor.fetchall()]:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")

    _add_col("system_health", "defender_raw")
    _add_col("system_health", "firewall_raw")
    _add_col("alerts",        "mitre_technique")

    conn.commit()
    conn.close()

# ─────────────────────────────────────────────────────────────────────────────
#  Insert helpers
# ─────────────────────────────────────────────────────────────────────────────

def insert_alert(event_type, severity, description, raw_data, mitre_technique=None):
    conn = get_db_connection()
    conn.cursor().execute(
        'INSERT INTO alerts (timestamp,event_type,severity,description,raw_data,mitre_technique) VALUES (?,?,?,?,?,?)',
        (datetime.now().isoformat(), event_type, severity, description, str(raw_data), mitre_technique)
    )
    conn.commit(); conn.close()

def insert_linux_event(timestamp, hostname, service, pid, source_file,
                       event_type, severity, message, mitre_technique, raw):
    """Store a parsed Linux log event in the dedicated linux_events table."""
    conn = get_db_connection()
    conn.cursor().execute(
        '''INSERT INTO linux_events
           (timestamp, received_at, hostname, service, pid, source_file,
            event_type, severity, message, mitre_technique, raw)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (timestamp, datetime.now().isoformat(), hostname, service, pid,
         source_file, event_type, severity, message[:2000], mitre_technique, raw[:4000])
    )
    conn.commit(); conn.close()

def get_linux_events(limit=200):
    """Return recent Linux events from linux_events table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT id, timestamp, received_at, hostname, service, pid, source_file,
                  event_type, severity, message, mitre_technique, raw
           FROM linux_events ORDER BY received_at DESC LIMIT ?''',
        (limit,)
    )
    rows = cursor.fetchall(); conn.close()
    return [dict(r) for r in rows]

def get_linux_stats():
    """Return summary statistics for the Linux monitoring dashboard card."""
    conn = get_db_connection()
    cursor = conn.cursor()
    def _c(q, p=()):
        cursor.execute(q, p); return cursor.fetchone()['c']
    stats = {
        "total":         _c("SELECT COUNT(*) as c FROM linux_events"),
        "high":          _c("SELECT COUNT(*) as c FROM linux_events WHERE severity='HIGH'"),
        "ssh_failures":  _c("SELECT COUNT(*) as c FROM linux_events WHERE event_type IN ('SSH_FAILED_LOGIN','SSH_BRUTE_FORCE')"),
        "brute_force":   _c("SELECT COUNT(*) as c FROM linux_events WHERE event_type='SSH_BRUTE_FORCE'"),
        "privesc":       _c("SELECT COUNT(*) as c FROM linux_events WHERE event_type IN ('SU_TO_ROOT','SUDO_COMMAND','SETUID_CHMOD')"),
        "unique_hosts":  _c("SELECT COUNT(DISTINCT hostname) as c FROM linux_events"),
    }
    conn.close()
    return stats

def insert_health(defender_status, firewall_status, updates_status,
                  defender_raw=None, firewall_raw=None):
    conn = get_db_connection()
    conn.cursor().execute(
        '''INSERT INTO system_health
           (timestamp,defender_status,firewall_status,updates_status,defender_raw,firewall_raw)
           VALUES (?,?,?,?,?,?)''',
        (datetime.now().isoformat(), defender_status, firewall_status,
         updates_status, defender_raw, firewall_raw)
    )
    conn.commit(); conn.close()

def insert_usb_log(action, drive_letter, files_transferred):
    conn = get_db_connection()
    conn.cursor().execute(
        'INSERT INTO usb_logs (timestamp,action,drive_letter,files_transferred) VALUES (?,?,?,?)',
        (datetime.now().isoformat(), action, drive_letter, files_transferred)
    )
    conn.commit(); conn.close()

def insert_usb_event(action, drive_letter, device_name='Unknown', manufacturer='Unknown',
                     serial_number='N/A', device_type='Removable', username='Unknown',
                     hostname='Unknown', event_id='N/A', severity='MEDIUM', raw_data=''):
    conn = get_db_connection()
    conn.cursor().execute(
        '''INSERT INTO usb_events
           (timestamp,action,drive_letter,device_name,manufacturer,serial_number,
            device_type,username,hostname,event_id,severity,raw_data)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
        (datetime.now().isoformat(), action, drive_letter, device_name, manufacturer,
         serial_number, device_type, username, hostname, event_id, severity, str(raw_data))
    )
    conn.commit(); conn.close()

def insert_file_transfer(username, source_path, destination_path, file_name,
                         file_extension, file_size_bytes, operation, usb_device,
                         drive_letter, sha256_hash, severity, detection_rule, raw_data):
    conn = get_db_connection()
    conn.cursor().execute(
        '''INSERT INTO file_transfer_events
           (timestamp,username,source_path,destination_path,file_name,file_extension,
            file_size_bytes,operation,usb_device,drive_letter,sha256_hash,
            severity,detection_rule,raw_data)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (datetime.now().isoformat(), username, source_path, destination_path, file_name,
         file_extension, file_size_bytes, operation, usb_device, drive_letter, sha256_hash,
         severity, detection_rule, str(raw_data))
    )
    conn.commit(); conn.close()

# ─────────────────────────────────────────────────────────────────────────────
#  Query helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_recent_alerts(limit=20):
    conn = get_db_connection()
    cursor = conn.cursor()
    if limit is None:
        cursor.execute(
            'SELECT id,timestamp,event_type,severity,description,raw_data,mitre_technique FROM alerts ORDER BY timestamp DESC'
        )
    else:
        cursor.execute(
            'SELECT id,timestamp,event_type,severity,description,raw_data,mitre_technique FROM alerts ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
    rows = cursor.fetchall(); conn.close()
    return [dict(r) for r in rows]

def get_latest_health():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT timestamp,defender_status,firewall_status,updates_status,defender_raw,firewall_raw FROM system_health ORDER BY timestamp DESC LIMIT 1'
    )
    row = cursor.fetchone(); conn.close()
    return dict(row) if row else None

def get_severity_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity')
    rows = cursor.fetchall(); conn.close()
    stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in rows:
        sev = row['severity'].upper()
        if sev in stats:
            stats[sev] = row['count']
        elif "CRITICAL" in sev:
            stats["HIGH"] += row['count']
    return stats

def get_category_counts():
    """Return per-category alert counts for dashboard cards."""
    conn = get_db_connection()
    cursor = conn.cursor()

    def _count(where_clause, params=()):
        cursor.execute(f"SELECT COUNT(*) as c FROM alerts WHERE {where_clause}", params)
        return cursor.fetchone()['c']

    counts = {
        "powershell_alerts": _count(
            "event_type IN ('SUSPICIOUS_POWERSHELL','POWERSHELL_ENCODED','POWERSHELL_DEFENDER_TAMPER','POWERSHELL_EXECUTION_BYPASS')"
        ),
        "failed_logins": _count(
            "event_type IN ('FAILED_LOGON','BRUTE_FORCE_ATTEMPT')"
        ),
        "log_tampering": _count(
            "event_type IN ('LOG_CLEARED','SECURITY_LOG_CLEARED','SYSTEM_LOG_CLEARED')"
        ),
        "service_alerts": _count(
            "event_type IN ('SERVICE_TAMPERING','SECURITY_SERVICE_STOPPED','SECURITY_SERVICE_DISABLED')"
        ),
        "process_alerts": _count(
            "event_type IN ('SUSPICIOUS_PROCESS_SPAWN','FILE_INTEGRITY')"
        ),
    }
    conn.close()
    return counts

def get_usb_events(limit=200):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT id,timestamp,action,drive_letter,device_name,manufacturer,
                  serial_number,device_type,username,hostname,event_id,severity,raw_data
           FROM usb_events ORDER BY timestamp DESC LIMIT ?''',
        (limit,)
    )
    rows = cursor.fetchall(); conn.close()
    return [dict(r) for r in rows]

def get_file_transfers(limit=200):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''SELECT id,timestamp,username,source_path,destination_path,file_name,
                  file_extension,file_size_bytes,operation,usb_device,drive_letter,
                  sha256_hash,severity,detection_rule,raw_data
           FROM file_transfer_events ORDER BY timestamp DESC LIMIT ?''',
        (limit,)
    )
    rows = cursor.fetchall(); conn.close()
    return [dict(r) for r in rows]

def get_usb_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    def _c(q, p=()):
        cursor.execute(q, p); return cursor.fetchone()['c']
    s = {
        "insertions": _c("SELECT COUNT(*) as c FROM usb_events WHERE action='INSERT'"),
        "removals":   _c("SELECT COUNT(*) as c FROM usb_events WHERE action='REMOVE'"),
        "transfers":  _c("SELECT COUNT(*) as c FROM file_transfer_events"),
        "high_severity": _c("SELECT COUNT(*) as c FROM usb_events WHERE severity='HIGH'") +
                          _c("SELECT COUNT(*) as c FROM file_transfer_events WHERE severity='HIGH'"),
    }
    conn.close()
    return s

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully.")
