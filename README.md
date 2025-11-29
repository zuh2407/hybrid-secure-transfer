# Hybrid Secure Transfer

A secure file transfer application using Flask and Cryptography.

## Setup & Running (Step-by-Step)

Follow these steps to get the application running from scratch.

### 1. Open Terminal
Open your terminal (Command Prompt or PowerShell) and navigate to the project folder:
```bash
cd c:\hybrid_secure_transfer
```

### 2. Set up Virtual Environment
It is recommended to use a virtual environment to manage dependencies.

**Create the virtual environment (if not exists):**
```bash
python -m venv venv
```

**Activate the virtual environment:**
*   **Windows (PowerShell):**
    ```powershell
    .\venv\Scripts\Activate
    ```
*   **Windows (Command Prompt):**
    ```cmd
    venv\Scripts\activate
    ```
*   **Mac/Linux:**
    ```bash
    source venv/bin/activate
    ```
*(You should see `(venv)` appear at the start of your command line)*

### 3. Install Dependencies
With the virtual environment activated, install the required packages:
```bash
pip install -r requirements.txt
```

### 4. Generate Keys
Run the key generation script to create the RSA key pair. This is required for encryption to work.
```bash
python client/keygen.py
```
*This will create `storage/server_private_key.pem` and `storage/server_public_key.pem`.*

### 5. Start the Server
Run the Flask application:
```bash
python server/app.py
```
The server will start on `http://127.0.0.1:5000`.

### 6. Access the App
Open your web browser and go to:
[http://127.0.0.1:5000](http://127.0.0.1:5000)

## Features
- Secure file upload with AES encryption (client-side simulation).
- RSA encryption for AES keys.
- Digital signatures for integrity.
- Secure logging.
