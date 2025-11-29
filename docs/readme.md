


<<<<<<< HEAD
```markdown
# 🛡️ Hybrid Secure File Transfer System

This repository contains the source code for a **secure file transfer application** built on a **hybrid encryption model**.  
The **main branch** holds the foundational baseline, and our collective mission is to evolve this proof-of-concept into a **production-ready, secure, and professional web application**.

---

## 📁 1. Project Directory Structure

A well-organized folder structure ensures effective collaboration and modular development.

```

hybrid-secure-transfer/
│
├── frontend/             # (Frontend Lead) React Single Page Application (SPA)
│   ├── public/
│   └── src/
│       ├── components/   # Reusable React components (FileUpload, FileList, etc.)
│       └── ...
│
├── server/               # Flask backend API
│   ├── **init**.py
│   ├── app.py            # (Backend Lead) Main Flask application entry point
│   ├── routes/           # (Backend Lead) API endpoint definitions
│   ├── security/         # (Security Lead) IDS, logging, and security modules
│   ├── utils/            # (Backend/Security) Shared utilities
│   ├── templates/        # (Obsolete after SPA)
│   └── static/           # (Obsolete after SPA)
│
├── storage/              # Stores encrypted file packages
│   └── encrypted_files/
│
├── client/               # Local client-side scripts
│   └── keygen.py         # Script to generate local RSA keys
│
├── logs/                 # (Security Lead) Structured application logs
│   └── app.log
│
└── README.md             # This file

````

---

## 🧠 2. System Architecture & Workflow

This application ensures **end-to-end file security** using a **hybrid encryption strategy**, combining:

- The **speed of symmetric encryption (AES)**
- The **security of asymmetric encryption (RSA)**

### 🔐 End-to-End Workflow

#### **Stage 1: The Sender (Client-Side Encryption)**

1. **Select & Hash:**  
   The user selects a file. A unique **SHA-256 hash** (file fingerprint) is created.
2. **Generate Keys:**  
   A new, single-use **256-bit AES key** is generated.
3. **Encrypt File:**  
   The file is encrypted with the AES key.
4. **Sign Hash:**  
   The hash is signed using the sender’s **private RSA key**, ensuring authenticity and integrity.
5. **Encrypt AES Key:**  
   The AES key is encrypted using the **server’s public RSA key**.
6. **Upload Package:**  
   The browser uploads a package containing:
   - Encrypted file  
   - Encrypted AES key  
   - Digital signature

---

#### **Stage 2: The Server (Validation & Storage)**

7. **Receive & Verify:**  
   The Flask server verifies the digital signature using the sender’s **public RSA key**.
8. **Decision Point:**
   - ❌ **Invalid Signature:** Log intrusion alert with sender IP → discard package.
   - ✅ **Valid Signature:** Confirm integrity → proceed to store.
9. **Secure Storage:**  
   The **still-encrypted** package is saved in `storage/` (zero-knowledge model).

---

#### **Stage 3: The Receiver (Client-Side Decryption)**

10. **Request & Download:**  
    The user requests a file; the server returns the encrypted package.
11. **Verify Signature:**  
    The browser re-verifies the digital signature.
12. **Decrypt AES Key:**  
    The receiver decrypts the AES key using their **private RSA key**.
13. **Restore File:**  
    The decrypted AES key is used to restore the original file.

---

## ⚙️ 3. Environment Setup & Running the Application

### **3.1. Initial Setup**

```bash
# 1. Clone the project from GitHub
git clone [URL_of_your_GitHub_repository]
cd hybrid-secure-transfer

# 2. Create and activate a Python virtual environment
python -m venv venv

# On Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# On macOS/Linux
source venv/bin/activate

# 3. Install required dependencies
pip install Flask cryptography pandas matplotlib

# 4. Generate your personal RSA key pair
python client/keygen.py
````

---

### **3.2. Running the Baseline App**

```bash
# Make sure your virtual environment is activated
python -m server.app
```

Navigate to 👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

---

## 🚀 4. Phase 2: Collaborative Development Plan

This phase focuses on **parallel development tracks** to decouple the architecture, build a modern frontend, and strengthen system security.

---

### 🧩 General Git Workflow

```bash
# Always start with the latest main branch
git checkout main
git pull origin main

# Create your own feature branch
git checkout -b feature/your-branch-name
```

Commit locally, then push and open a **Pull Request (PR)** for review.

---

## 👨‍💻 Team Roles & Missions

### 🧠 Member 1: Backend & API Lead

**Mission:**
Build the engine of the application — transform the Flask backend into a clean, fast **JSON API**.

**Branch Setup:**

```bash
git checkout -b feature/flask-json-api
```

#### **Development Tasks**

* Convert the Flask app to handle **JSON data** (no templates).
* Create endpoints like:

  * `GET /api/files` → List encrypted files
  * `POST /api/upload` → Handle encrypted package upload
* Integrate security modules from the Security Lead.

#### **Files to Focus On**

* `server/app.py`
* `server/routes/`

#### **Collaboration**

* **With Frontend Lead:**
  Create an `API.md` file documenting all endpoints (e.g., request/response formats).
* **With Security Lead:**
  Integrate logging, rate-limiting, and IDS modules.

---

### 🎨 Member 2: Frontend & UI/UX Lead

**Mission:**
Design a **professional, user-friendly** interface for secure file transfers.

**Branch Setup:**

```bash
git checkout -b feature/frontend-ux-choice
```

#### **Development Path Options**

**Option A: Classic Enhancement**

* Enhance Flask templates with **CSS + JavaScript (fetch API)**.
* Use the API for dynamic updates.

**Option B: Modern React SPA (Recommended)**

* Build from scratch using **React**.
* Develop core components like:

  * `FileUpload.js`
  * `FileList.js`
  * `IDSDashboard.js`

#### **Collaboration**

* **With Backend Lead:**
  Use `API.md` to make `fetch()` or `axios` calls to the Flask API.
* **With Security Lead:**
  Connect to `/api/ids/summary` for real-time IDS dashboard updates.

---

### 🔒 Member 3: IDS & Security Lead

**Mission:**
Guard the application by building an intelligent **Intrusion Detection System (IDS)** and strengthening security controls.

**Branch Setup:**

```bash
git checkout -b feature/ids-enhancements
```

#### **Development Tasks**

* Implement structured JSON logging.
* Develop an IDS that detects:

  * Repeated failed uploads
  * Suspicious IP patterns
* Create `/api/ids/summary` endpoint for real-time analytics.

#### **Files to Focus On**

* `server/security/logger.py`
* `server/security/ids.py`
* `logs/app.log`

#### **Collaboration**

* **With Backend Lead:**
  Provide ready-to-use security modules for integration into Flask.
* **With Frontend Lead:**
  Define the JSON structure for `/api/ids/summary` to support visual dashboards.

---

## 🧩 Summary

| Role          | Key Deliverable          | Output Type                               |
| ------------- | ------------------------ | ----------------------------------------- |
| Backend Lead  | Flask JSON API           | `/api/files`, `/api/upload`               |
| Frontend Lead | React SPA or Enhanced UI | Components & UX                           |
| Security Lead | IDS & Logger Modules     | `/api/ids/summary`, `logger.py`, `ids.py` |

---

## 📜 License

This project is currently for **academic and research purposes** only.
For production use, ensure compliance with organizational and security standards.

---

**Authors:**
Team Hybrid Secure Transfer
© 2025 — All Rights Reserved.

```

---

Would you like me to add a short **diagram (ASCII or Mermaid)** visualizing the encryption/decryption workflow inside this README? It would make the project presentation more professional.
```
=======
>>>>>>> 0163278d72b1b5f20aa3477bed643888dc099acd
