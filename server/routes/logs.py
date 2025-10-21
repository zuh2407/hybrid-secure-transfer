from flask import Blueprint, render_template, request, jsonify
import os
import pandas as pd
import re

logs_bp = Blueprint('logs_bp', __name__, template_folder='../templates')

LOG_DIR = 'storage/logs/ids'
ACCESS_LOG = os.path.join(LOG_DIR, 'access.log')
INTRUSION_LOG = os.path.join(LOG_DIR, 'intrusion.log')

def parse_log_file(log_path):
    log_entries = []
    log_format = re.compile(
        r'(?P<timestamp>^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - '
        r'(?P<level>\w+) - '
        r'(?P<ip>[\d.:a-fA-F]+) - ' # Added IPv6 support
        r'(?P<message>.*)'
    )
    if not os.path.exists(log_path):
        return []
    with open(log_path, 'r') as f:
        for line in f:
            match = log_format.match(line)
            if match:
                log_entries.append(match.groupdict())
    return log_entries

@logs_bp.route('/dashboard')
def logs_page():
    return render_template('logs.html')

@logs_bp.route('/api/log_data')
def get_log_data():
    intrusion_logs = parse_log_file(INTRUSION_LOG)
    if not intrusion_logs:
        return jsonify({'by_ip': {'labels': [], 'data': []}, 'by_type': {'labels': [], 'data': []}})

    df = pd.DataFrame(intrusion_logs)
    ip_counts = df['ip'].value_counts()
    df['event_type'] = df['message'].apply(lambda x: ' '.join(x.split()[:3]))
    type_counts = df['event_type'].value_counts()

    return jsonify({
        'by_ip': {'labels': ip_counts.index.tolist(), 'data': ip_counts.values.tolist()},
        'by_type': {'labels': type_counts.index.tolist(), 'data': type_counts.values.tolist()}
    })

@logs_bp.route('/api/raw_logs')
def get_raw_logs():
    log_type = request.args.get('type', 'intrusion')
    log_path = INTRUSION_LOG if log_type == 'intrusion' else ACCESS_LOG
    if not os.path.exists(log_path):
        return jsonify({"logs": "Log file not found."})
    with open(log_path, 'r') as f:
        lines = f.readlines()
        raw_logs = "".join(lines[-50:])
    return jsonify({"logs": raw_logs})