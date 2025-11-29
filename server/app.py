from flask import Flask, render_template, request
import os
import logging
from logging.handlers import RotatingFileHandler

# Import the Blueprints from the routes package
from .routes.upload import upload_bp
from .routes.download import download_bp
from .routes.logs import logs_bp

# --- Setup Secure Logging ---
log_dir = 'storage/logs/ids'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Define a custom filter to add IP to the log record
class IPFilter(logging.Filter):
    def filter(self, record):
        record.ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        return True

# Access Logger (INFO level)
access_log_file = os.path.join(log_dir, 'access.log')
access_logger = logging.getLogger('access')
access_logger.setLevel(logging.INFO)
access_handler = RotatingFileHandler(access_log_file, maxBytes=1024*1024, backupCount=3)
access_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(ip)s - %(message)s')
access_handler.setFormatter(access_formatter)
access_logger.addHandler(access_handler)
access_logger.addFilter(IPFilter())

# Intrusion Logger (WARNING level)
intrusion_log_file = os.path.join(log_dir, 'intrusion.log')
intrusion_logger = logging.getLogger('intrusion')
intrusion_logger.setLevel(logging.WARNING)
intrusion_handler = RotatingFileHandler(intrusion_log_file, maxBytes=1024*1024, backupCount=3)
intrusion_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(ip)s - %(message)s')
intrusion_handler.setFormatter(intrusion_formatter)
intrusion_logger.addHandler(intrusion_handler)
intrusion_logger.addFilter(IPFilter())
# ---------------------

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'storage/encrypted_files'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Middleware for Logging ---
@app.before_request
def log_request_info():
    access_logger.info(f"{request.method} {request.path}")

# --- Register Blueprints ---
app.register_blueprint(upload_bp)
app.register_blueprint(download_bp)
app.register_blueprint(logs_bp)
from .routes.ids_routes import ids_bp
app.register_blueprint(ids_bp)

# --- Main App Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/keys')
def keys_page():
    return render_template('keys.html')

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    access_logger.warning(f"404 Not Found: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    intrusion_logger.error(f"500 Internal Error: {request.path} - {e}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Ensure you have run 'python client/keygen.py' at least once.")
    app.run(debug=True, port=5000)