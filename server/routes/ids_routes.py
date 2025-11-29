from flask import Blueprint, request, jsonify, current_app
import os
import time
from server.ids import sandbox_client
from werkzeug.utils import secure_filename

ids_bp = Blueprint('ids_bp', __name__)

@ids_bp.route('/api/upload', methods=['POST'])
def api_upload():
    """
    API Endpoint to upload a file for sandbox analysis.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        try:
            filename = secure_filename(file.filename)
            # Save temporarily to upload folder
            temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(temp_path)

            # Submit to sandbox
            task_id = sandbox_client.submit_file(temp_path, filename)
            
            # Clean up temp file? 
            # For now, we might keep it or the sandbox client handles it.
            # If we delete it immediately, we can't use it later if it's clean.
            # But this is just the analysis step.
            
            return jsonify({
                'message': 'File submitted for analysis',
                'task_id': task_id,
                'status': 'pending'
            }), 202

        except Exception as e:
            return jsonify({'error': str(e)}), 500

@ids_bp.route('/api/ids/report/<task_id>', methods=['GET'])
def get_report(task_id):
    """
    Fetch the analysis report for a given task ID.
    """
    # Trigger a status check (updates DB if mock)
    report = sandbox_client.check_status(task_id)
    
    if not report:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify(report)

from server.routes.logs import analyze_logs, generate_daily_report
from flask import send_file

@ids_bp.route('/api/ids/summary', methods=['GET'])
def ids_summary():
    """
    Returns IDS summary stats and alerts.
    """
    analysis = analyze_logs()
    return jsonify(analysis)

@ids_bp.route('/api/ids/daily_report', methods=['GET'])
def daily_report():
    """
    Generates and downloads the daily report.
    """
    report_path = generate_daily_report()
    if report_path and os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    else:
        return jsonify({'message': 'No data for today to generate report'}), 404
