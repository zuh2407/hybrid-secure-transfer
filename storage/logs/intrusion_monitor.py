import pandas as pd
import re
import os
from datetime import datetime

print("Initializing Standalone IDS Monitor...")

# --- Configuration ---
LOG_DIR = os.path.join(os.path.dirname(__file__), 'ids')
INTRUSION_LOG = os.path.join(LOG_DIR, 'intrusion.log')
REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
REPORT_FILE = os.path.join(REPORT_DIR, f'daily_report_{datetime.now().strftime("%Y-%m-%d")}.csv')
BRUTE_FORCE_THRESHOLD = 5 # Number of failed events from one IP to be flagged

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

def parse_log_file(log_path):
    """Parses the intrusion log file into a pandas DataFrame."""
    log_entries = []
    log_format = re.compile(
        r'(?P<timestamp>^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - '
        r'(?P<level>\w+) - '
        r'(?P<ip>[\d.:a-fA-F]+) - '
        r'(?P<message>.*)'
    )
    if not os.path.exists(log_path):
        print(f"Error: Log file not found at {log_path}")
        return None
    with open(log_path, 'r') as f:
        for line in f:
            match = log_format.match(line)
            if match:
                log_entries.append(match.groupdict())
    if not log_entries:
        return None
    df = pd.DataFrame(log_entries)
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S,%f')
    return df

def analyze_logs(df):
    """Analyzes the log DataFrame and prints a summary."""
    print("\n--- Intrusion Log Analysis ---")
    
    print(f"Total suspicious events: {len(df)}")
    
    print("\n[+] Events by IP Address:")
    ip_counts = df['ip'].value_counts()
    print(ip_counts.to_string())
    
    print("\n[+] Events by Type:")
    df['event_type'] = 'Other'
    df.loc[df['message'].str.contains('VERIFICATION FAILED', case=False), 'event_type'] = 'Verification Failure'
    df.loc[df['message'].str.contains('upload attempt', case=False), 'event_type'] = 'Bad Upload Attempt'
    df.loc[df['message'].str.contains('404 Not Found', case=False), 'event_type'] = 'Resource Scanning (404)'
    type_counts = df['event_type'].value_counts()
    print(type_counts.to_string())
    
    print("\n[!] Potential Brute-Force Activity:")
    suspicious_ips = ip_counts[ip_counts >= BRUTE_FORCE_THRESHOLD]
    if not suspicious_ips.empty:
        print(f"WARNING: IPs with {BRUTE_FORCE_THRESHOLD} or more failed events detected:")
        for ip, count in suspicious_ips.items():
            print(f"  - IP: {ip}, Events: {count}")
    else:
        print("  No high-activity IPs detected meeting the threshold.")
    
def generate_report(df):
    """Saves the analysis to a CSV report."""
    if df is not None:
        try:
            df.to_csv(REPORT_FILE, index=False)
            print(f"\n[+] Successfully generated daily report: {REPORT_FILE}")
        except Exception as e:
            print(f"[-] Failed to write report: {e}")

if __name__ == "__main__":
    log_df = parse_log_file(INTRUSION_LOG)
    if log_df is not None:
        analyze_logs(log_df)
        generate_report(log_df)
    else:
        print("No intrusion log entries found to analyze.")