from flask import (Blueprint, render_template, request, current_app,
                   flash, redirect, url_for)
import os
import time
import base64
from logging import getLogger
import json

from client.crypto_utils import (
    generate_aes_key, encrypt_file_aes, encrypt_key_rsa,
    sign_data, hash_data, load_public_key, load_private_key
)

upload_bp = Blueprint('upload_bp', __name__, template_folder='../templates')

intrusion_logger = getLogger('intrusion')

@upload_bp.route('/upload', methods=['GET', 'POST'])
def upload_page():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            intrusion_logger.warning("Upload attempt with no file part")
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            intrusion_logger.warning("Upload attempt with empty filename")
            return redirect(request.url)

        if file:
            try:
                file_data = file.read()
                original_filename = file.filename

                public_key = load_public_key()
                private_key = load_private_key()

                aes_key = generate_aes_key()
                ciphertext, nonce, tag = encrypt_file_aes(file_data, aes_key)
                encrypted_aes_key = encrypt_key_rsa(aes_key, public_key)

                data_hash = hash_data(file_data)
                signature = sign_data(data_hash, private_key)

                envelope = {
                    'original_filename': original_filename,
                    'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                    'nonce': base64.b64encode(nonce).decode('utf-8'),
                    'tag': base64.b64encode(tag).decode('utf-8'),
                    'signature': base64.b64encode(signature).decode('utf-8'),
                    'timestamp': int(time.time())
                }
                
                # Unique filename to prevent overwrites
                base_filename = f"{original_filename}.{int(time.time())}"
                envelope_filename = f"{base_filename}.json"
                file_data_filename = f"{base_filename}.data"

                envelope_path = os.path.join(current_app.config['UPLOAD_FOLDER'], envelope_filename)
                with open(envelope_path, 'w') as f:
                    json.dump(envelope, f, indent=4)

                file_data_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_data_filename)
                with open(file_data_path, 'wb') as f:
                    f.write(ciphertext)

                flash(f'File "{original_filename}" securely encrypted and uploaded!', 'success')
                return redirect(url_for('download_bp.verify_page'))

            except Exception as e:
                flash(f'An error occurred during upload: {e}', 'danger')
                intrusion_logger.error(f"Upload failed: {e}")
                return redirect(request.url)

    return render_template('upload.html')