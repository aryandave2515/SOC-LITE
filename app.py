from flask import Flask, render_template, jsonify, request
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import logger
import database

app = Flask(__name__, template_folder='templates')

# ── Core ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

# ── Alerts ────────────────────────────────────────────────────────────────────

@app.route('/api/alerts')
def api_alerts():
    try:
        limit_val = request.args.get('limit', default=20, type=int)
        if request.args.get('all') == 'true':
            limit_val = None
        return jsonify(database.get_recent_alerts(limit=limit_val))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Health ────────────────────────────────────────────────────────────────────

@app.route('/api/health')
def api_health():
    try:
        health = database.get_latest_health()
        if health:
            return jsonify(health)
        return jsonify({
            "defender_status": "Checking…",
            "firewall_status":  "Checking…",
            "updates_status":   "Checking…",
            "timestamp": None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Stats ─────────────────────────────────────────────────────────────────────

@app.route('/api/stats')
def api_stats():
    try:
        stats = database.get_severity_stats()

        conn   = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM alerts")
        stats["TOTAL"] = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE severity='HIGH'")
        stats["HIGH_RISK"] = cursor.fetchone()['count']
        conn.close()

        # Per-category counts (new cards)
        cats = database.get_category_counts()
        stats["PS_ALERTS"]     = cats["powershell_alerts"]
        stats["FAILED_LOGINS"] = cats["failed_logins"]
        stats["LOG_TAMPERING"] = cats["log_tampering"]
        stats["SERVICE_ALERTS"]= cats["service_alerts"]

        # USB aggregate
        usb = database.get_usb_stats()
        stats["USB_INSERTIONS"] = usb["insertions"]
        stats["USB_REMOVALS"]   = usb["removals"]
        stats["USB_TRANSFERS"]  = usb["transfers"]
        stats["USB_HIGH"]       = usb["high_severity"]

        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── System Logs ───────────────────────────────────────────────────────────────

@app.route('/api/logs')
def api_logs():
    try:
        lines = logger.get_log_lines(40)
        return jsonify(lines)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── USB ───────────────────────────────────────────────────────────────────────

@app.route('/api/usb')
def api_usb():
    try:
        limit = request.args.get('limit', default=200, type=int)
        return jsonify(database.get_usb_events(limit=limit))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/usb/transfers')
def api_usb_transfers():
    try:
        limit = request.args.get('limit', default=200, type=int)
        return jsonify(database.get_file_transfers(limit=limit))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/usb/stats')
def api_usb_stats():
    try:
        return jsonify(database.get_usb_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Filtered alert views for modal detail endpoints ───────────────────────────

@app.route('/api/alerts/filter')
def api_alerts_filter():
    """Return alerts filtered by event_type prefix(es), newest first."""
    try:
        types = request.args.get('types', '')        # comma-separated list
        limit = request.args.get('limit', default=200, type=int)
        if not types:
            return jsonify([])
        type_list = [t.strip() for t in types.split(',') if t.strip()]

        conn   = database.get_db_connection()
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(type_list))
        cursor.execute(
            f'''SELECT id,timestamp,event_type,severity,description,raw_data,mitre_technique
                FROM alerts
                WHERE event_type IN ({placeholders})
                ORDER BY timestamp DESC LIMIT ?''',
            type_list + [limit]
        )
        rows = cursor.fetchall(); conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Linux Agent Ingestion ─────────────────────────────────────────────────────

from collectors.linux_event_receiver import authenticate_request, process_linux_batch

@app.route('/api/linux/logs', methods=['POST'])
def api_linux_logs():
    """
    Endpoint for the Linux agent to POST batched log events.
    Expects JSON: { agent_hostname, agent_version, events: [...] }
    Protected by Bearer token (set SOC_AGENT_TOKEN env var on server).
    """
    try:
        if not authenticate_request(request):
            return jsonify({"error": "Unauthorized — invalid or missing token"}), 401

        payload = request.get_json(silent=True)
        if not payload or "events" not in payload:
            return jsonify({"error": "Invalid payload — expected {events: [...]}"}), 400

        result = process_linux_batch(payload)
        return jsonify({"status": "ok", **result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/linux/events')
def api_linux_events():
    """Return recent Linux events for the dashboard Linux panel."""
    try:
        limit = request.args.get('limit', default=200, type=int)
        return jsonify(database.get_linux_events(limit=limit))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/linux/stats')
def api_linux_stats():
    """Return aggregate Linux monitoring stats for dashboard cards."""
    try:
        return jsonify(database.get_linux_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    database.init_db()
    app.run(debug=False, host='127.0.0.1', port=5000)

