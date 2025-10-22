# Hybrid Secure File Transfer System

This project is a secure, user-friendly file transfer system that ensures confidentiality, integrity, and authenticity through a combination of hybrid encryption, digital signatures, and an intrusion detection system (IDS).

## Features

- **Hybrid Encryption**: Uses AES-256-GCM for fast file encryption and RSA-2048 for secure exchange of the AES key.
- **Digital Signatures**: Employs RSA-PSS to sign file hashes, guaranteeing sender authenticity and data integrity.
- **Intrusion Detection**: A simple IDS monitors server logs for suspicious activities like failed verifications or 404 scans.
- **Web Dashboard**: A Flask-powered web interface allows for easy uploading, verification, and monitoring of security events.
- **Secure Logging**: Rotates logs to manage disk space and separates access logs from security-critical intrusion logs.


