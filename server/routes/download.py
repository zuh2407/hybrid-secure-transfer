from flask import (Blueprint, render_template, request, current_app,
                   flash, redirect, url_for, send_file)
import os
import json
import base64
from io import BytesIO
from logging import getLogger

# Import your crypto functions
from client.crypto_utils import (
    decrypt_file_aes, decrypt_key_rsa,
    verify_signature, hash_data, load_public_key, load_private_key
)

download_bp = Blueprint('download_bp', __name__, template_folder='../templates')

intrusion_logger = getLogger('intrusion')

@download_bp.route('/verify', methods=['GET', 'POST'])
def verify_page():
    upload_folder = current_app.config['UPLOAD_FOLDER']
    files = [f for f in os.listdir(upload_folder) if f.endswith('.json')]

    if request.method == 'POST':
        selected_file = request.form.get('file')

        if not selected_file or selected_file not in files:
            flash('Invalid file selected.', 'danger')
            intrusion_logger.warning("Download attempt with invalid file selection")
            return redirect(request.url)

        envelope_path = os.path.join(upload_folder, selected_file)
        
        # --- THIS IS THE CORRECTED LINE ---
        # It now removes .json before adding .data
        file_data_path = os.path.join(upload_folder, selected_file.removesuffix('.json') + '.data')
        # ------------------------------------

        try:
            public_key = load_public_key()
            private_key = load_private_key()

            with open(envelope_path, 'r') as f:
                envelope = json.load(f)
            
            # Check if data file exists before trying to open it
            if not os.path.exists(file_data_path):
                flash(f'Error: Missing data file for {selected_file}', 'danger')
                intrusion_logger.error(f"Missing data file: {file_data_path}")
                return redirect(request.url)
                
            with open(file_data_path, 'rb') as f:
                ciphertext = f.read()

            encrypted_aes_key = base64.b64decode(envelope['encrypted_aes_key'])
            nonce = base64.b64decode(envelope['nonce'])
            tag = base64.b64decode(envelope['tag'])
            signature = base64.b64decode(envelope['signature'])
            original_filename = envelope['original_filename']

            aes_key = decrypt_key_rsa(encrypted_aes_key, private_key)
            decrypted_data = decrypt_file_aes(ciphertext, aes_key, nonce, tag)
            decrypted_data_hash = hash_data(decrypted_data)
            verify_signature(decrypted_data_hash, signature, public_key)

            flash(f'Success! Signature VERIFIED and file "{original_filename}" decrypted.', 'success')

            return send_file(
                BytesIO(decrypted_data),
                as_attachment=True,
                download_name=original_filename,
                mimetype='application/octet-stream'
            )
        except ValueError as e:
            flash(f'SECURITY ALERT: {e}', 'danger')
            intrusion_logger.warning(f"VERIFICATION FAILED for {selected_file}: {e}")
            return redirect(request.url)
        except Exception as e:
            flash(f'An unexpected error occurred: {e}', 'danger')
            intrusion_logger.error(f"Download error for {selected_file}: {e}")
            return redirect(request.url)

    return render_template('verify.html', files=files)