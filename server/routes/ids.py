from flask import Blueprint, jsonify, current_app
import os
import pandas as pd
import re
from server.security import ids

ids_bp = Blueprint('ids_bp', __name__)

LOG_DIR = 'storage/logs/ids'
INTRUSION_LOG = os.path.join(LOG_DIR, 'intrusion.log')
ACCESS_LOG = os.path.join(LOG_DIR, 'access.log') # Added for completeness if needed

@ids_bp.route('/api/ids/report/<task_id>', methods=['GET'])
def get_sandbox_report(task_id):
    report = ids.fetch_sandbox_report(task_id)
    if report:
        return jsonify(report)
    else:
        return jsonify({'error': 'Report not found or sandbox unreachable'}), 404

def parse_log_file(log_path):
    log_entries = []
    log_format = re.compile(
        r'(?P<timestamp>^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - '
        r'(?P<level>\w+) - '
        r'(?P<ip>[\d.:a-fA-F]+) - '
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

@ids_bp.route('/api/ids/summary', methods=['GET'])
def get_ids_summary():
    intrusion_logs = parse_log_file(INTRUSION_LOG)
    
    # Initialize default structure
    summary = {
        'total_events': 0,
        'by_ip': {},
        'by_type': {},
        'recent_alerts': []
    }

    if not intrusion_logs:
        return jsonify(summary)

    df = pd.DataFrame(intrusion_logs)
    summary['total_events'] = len(df)
    
    # Events by IP
    if 'ip' in df.columns:
        summary['by_ip'] = df['ip'].value_counts().to_dict()
    
    # Events by Type (first few words of message)
    if 'message' in df.columns:
        df['event_type'] = df['message'].apply(lambda x: ' '.join(str(x).split()[:3]))
        summary['by_type'] = df['event_type'].value_counts().to_dict()
        
        # Recent alerts (last 10)
        summary['recent_alerts'] = df.tail(10).to_dict('records')

    return jsonify(summary)
