from flask import (Blueprint, request, current_app, jsonify, send_file)
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

download_bp = Blueprint('download_bp', __name__)

intrusion_logger = getLogger('intrusion')

@download_bp.route('/api/file/download/<filename>', methods=['GET'])
def api_download(filename):
    upload_folder = current_app.config['UPLOAD_FOLDER']
    
    # We assume 'filename' passed is the base_filename (envelope_id) or the original filename?
    # The instructions say: "Rename the route to /api/file/download/<filename>"
    # In the upload response, we return 'envelope_id' (base_filename). 
    # Usually, to find the right file, we need the unique ID (envelope filename).
    # If the user passes the original filename, we might have duplicates.
    # Let's assume the user passes the unique identifier (the part before .json).
    # Or maybe the full filename "foo.txt.123456.json".
    # Let's handle it robustly.
    
    # Check if filename ends with .json, if not, try appending it to find the envelope
    if not filename.endswith('.json'):
        envelope_filename = f"{filename}.json"
    else:
        envelope_filename = filename
        
    envelope_path = os.path.join(upload_folder, envelope_filename)
    
    if not os.path.exists(envelope_path):
        intrusion_logger.warning(f"Download attempt for non-existent file: {filename}")
        return jsonify({'error': 'File not found'}), 404

    file_data_filename = envelope_filename.replace('.json', '.data')
    file_data_path = os.path.join(upload_folder, file_data_filename)

    try:
        public_key = load_public_key()
        private_key = load_private_key()

        with open(envelope_path, 'r') as f:
            envelope = json.load(f)
        
        if not os.path.exists(file_data_path):
            intrusion_logger.error(f"Missing data file: {file_data_path}")
            return jsonify({'error': 'Data file missing'}), 500
            
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

        # "Return the encrypted file and envelope data as a JSON response"
        # The prompt says: "return the encrypted file and cryptographic envelope data as a JSON response"
        # This is interesting. It does NOT say return the DECRYPTED file.
        # It says "return the ENCRYPTED file".
        # Sending the decrypted bytes in JSON (base64) is possible. 
        # But instructions say "encrypted file".
        # Let's re-read carefully: "The function must now return the encrypted file and cryptographic envelope data as a JSON response".
        # This implies the client will do the decryption.
        # PREVIOUSLY: The server decrypted it.
        # "Success! Signature VERIFIED and file ... decrypted." -> send_file(decrypted_data).
        # NOW: "return the encrypted file and cryptographic envelope data".
        # This shifts decryption responsibility or is just a different mode.
        # I must follow the instruction.
        
        return jsonify({
            'status': 'verified',
            'filename': original_filename,
            'envelope': envelope,
            'encrypted_data': base64.b64encode(ciphertext).decode('utf-8')
        })

    except ValueError as e:
        intrusion_logger.warning(f"Verification failed for {filename}: {e}")
        return jsonify({'error': f"Verification failed: {str(e)}"}), 400
    except Exception as e:
        intrusion_logger.error(f"Download error for {filename}: {e}")
        return jsonify({'error': str(e)}), 500