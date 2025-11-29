from flask import Blueprint, render_template, request, jsonify
import os
import pandas as pd
import re
from datetime import datetime

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
                entry = match.groupdict()
                # Convert timestamp to datetime object for analysis
                try:
                    entry['dt'] = datetime.strptime(entry['timestamp'], '%Y-%m-%d %H:%M:%S,%f')
                except ValueError:
                    entry['dt'] = None
                log_entries.append(entry)
    return log_entries

def analyze_logs():
    """
    Performs behavioral analysis on the logs.
    """
    intrusion_data = parse_log_file(INTRUSION_LOG)
    access_data = parse_log_file(ACCESS_LOG)
    
    all_data = intrusion_data + access_data
    if not all_data:
        return {'alerts': [], 'stats': {}}

    df = pd.DataFrame(all_data)
    
    alerts = []
    
    # 1. Pattern Detection: High frequency of requests from single IP (Potential Brute Force/DoS)
    if not df.empty:
        # Count requests per IP in the last minute (simulated by just checking recent entries)
        # For simplicity in this demo, we just check total counts in the loaded log window
        ip_counts = df['ip'].value_counts()
        suspicious_ips = ip_counts[ip_counts > 20].index.tolist() # Threshold: 20 requests
        for ip in suspicious_ips:
            alerts.append(f"High traffic detected from IP: {ip} ({ip_counts[ip]} requests)")

    # 2. Behavioral Analysis: Accessing sensitive endpoints
    sensitive_endpoints = ['/admin', '/config', '/.env']
    if 'message' in df.columns:
        for endpoint in sensitive_endpoints:
            suspicious_access = df[df['message'].str.contains(endpoint, na=False)]
            for _, row in suspicious_access.iterrows():
                alerts.append(f"Suspicious access attempt to {endpoint} from {row['ip']}")

    # 3. Intrusion Log Analysis
    if intrusion_data:
        idf = pd.DataFrame(intrusion_data)
        error_counts = idf['level'].value_counts().to_dict()
    else:
        error_counts = {}

    return {
        'alerts': alerts,
        'stats': {
            'total_requests': len(df),
            'unique_ips': len(df['ip'].unique()) if not df.empty else 0,
            'error_distribution': error_counts
        }
    }

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

def generate_daily_report():
    """
    Generates a CSV report of the day's activity.
    """
    intrusion_data = parse_log_file(INTRUSION_LOG)
    access_data = parse_log_file(ACCESS_LOG)
    all_data = intrusion_data + access_data
    
    if not all_data:
        return None

    df = pd.DataFrame(all_data)
    # Filter for today
    today = datetime.now().strftime('%Y-%m-%d')
    # Assuming 'timestamp' starts with YYYY-MM-DD
    df_today = df[df['timestamp'].str.startswith(today)]
    
    if df_today.empty:
        return None
        
    report_path = os.path.join(LOG_DIR, f'daily_report_{today}.csv')
    df_today.to_csv(report_path, index=False)
    return report_path