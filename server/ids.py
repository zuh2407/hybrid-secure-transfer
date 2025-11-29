import os
import sqlite3
import requests
import json
import time
import random
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DB_PATH = 'server/sandbox_reports.db'
SANDBOX_URL = os.getenv('SANDBOX_API_URL', 'http://localhost:8090/tasks/create/file')
SANDBOX_TOKEN = os.getenv('SANDBOX_API_TOKEN', '')
USE_MOCK = os.getenv('USE_MOCK_SANDBOX', 'true').lower() == 'true'

def init_db():
    """Initializes the SQLite database for sandbox reports."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            task_id TEXT PRIMARY KEY,
            filename TEXT,
            status TEXT,
            verdict TEXT,
            timestamp REAL
        )
    ''')
    conn.commit()
    conn.close()

class SandboxClient:
    def __init__(self):
        if not os.path.exists(os.path.dirname(DB_PATH)):
             # Ensure server directory exists, though it should
            pass
        init_db()

    def _save_task(self, task_id, filename, status='pending', verdict='unknown'):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO reports (task_id, filename, status, verdict, timestamp) VALUES (?, ?, ?, ?, ?)',
                  (str(task_id), filename, status, verdict, time.time()))
        conn.commit()
        conn.close()

    def _update_task(self, task_id, status, verdict):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE reports SET status = ?, verdict = ? WHERE task_id = ?',
                  (status, verdict, str(task_id)))
        conn.commit()
        conn.close()

    def get_report(self, task_id):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM reports WHERE task_id = ?', (str(task_id),))
        row = c.fetchone()
        conn.close()
        
        if row:
            return {
                'task_id': row[0],
                'filename': row[1],
                'status': row[2],
                'verdict': row[3],
                'timestamp': row[4]
            }
        return None

    def submit_file(self, file_path, original_filename):
        """Submits a file to the sandbox."""
        if USE_MOCK:
            return self._mock_submit(original_filename)
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (original_filename, f)}
                headers = {'Authorization': f'Bearer {SANDBOX_TOKEN}'} if SANDBOX_TOKEN else {}
                response = requests.post(SANDBOX_URL, files=files, headers=headers)
                response.raise_for_status()
                
                # Assuming Cuckoo-style response: {"task_id": 123}
                task_id = response.json().get('task_id')
                if not task_id:
                     raise ValueError("No task_id returned from sandbox")
                
                self._save_task(task_id, original_filename)
                return task_id
        except Exception as e:
            print(f"Sandbox submission failed: {e}")
            # Fallback to mock or error handling? For now, let's error.
            # Or maybe fallback to mock if configured to do so on failure?
            # Let's stick to strict config.
            raise e

    def _mock_submit(self, filename):
        """Simulates file submission."""
        task_id = str(int(time.time() * 1000)) # Fake ID
        self._save_task(task_id, filename)
        
        # Simulate background processing (in a real app, this would be async)
        # For this demo, we'll just determine the result immediately but 
        # the client will have to poll or we update it "later".
        # Actually, let's just save it as pending, and _mock_check_status will flip it.
        return task_id

    def check_status(self, task_id):
        """Checks status of a task (Mock or Real)."""
        report = self.get_report(task_id)
        if not report:
            return None
            
        if report['status'] == 'completed':
            return report

        if USE_MOCK:
            # Randomly finish the task
            if time.time() - report['timestamp'] > 5: # 5 seconds "processing"
                # 80% chance clean, 20% malicious
                verdict = 'clean' if random.random() > 0.2 else 'malicious'
                self._update_task(task_id, 'completed', verdict)
                return self.get_report(task_id)
            else:
                return report # Still pending
        
        # Real API check would go here
        # ...
        return report

# Singleton instance
sandbox_client = SandboxClient()
