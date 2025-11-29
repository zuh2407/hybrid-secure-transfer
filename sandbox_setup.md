# Detonation Sandbox Setup Guide

This guide explains how to set up the Detonation Sandbox integration for the Active Threat Analysis Platform.

## Overview

The system is designed to integrate with **Cuckoo Sandbox** or **CAPE Sandbox** via their REST API. 
For development and testing without a live sandbox, a **Mock Mode** is available.

## Configuration

Configuration is managed via the `.env` file in the project root.

### 1. Mock Mode (Default)
To use the internal simulation (no external server required):
```ini
USE_MOCK_SANDBOX=true
```
In this mode:
- Files are "submitted" to a local database.
- Analysis takes ~5 seconds.
- Verdicts are randomly generated (80% Clean, 20% Malicious).

### 2. Live Sandbox Integration
To connect to a real Cuckoo/CAPE instance:

1.  **Install Cuckoo/CAPE**: Follow the official documentation for [Cuckoo](https://cuckoosandbox.org/) or [CAPE](https://capev2.readthedocs.io/).
2.  **Enable API**: Ensure the REST API server is running (usually on port 8090).
    ```bash
    cuckoo api --host 0.0.0.0 --port 8090
    ```
3.  **Update .env**:
    ```ini
    USE_MOCK_SANDBOX=false
    SANDBOX_API_URL=http://<your-sandbox-ip>:8090/tasks/create/file
    SANDBOX_API_TOKEN=<your-api-token-if-configured>
    ```

## API Endpoints

The Flask server exposes the following endpoints for the frontend/client:

-   **POST** `/api/upload`: Upload a file for analysis.
    -   Body: `multipart/form-data` with `file` field.
    -   Response: `{"task_id": "...", "status": "pending"}`

-   **GET** `/api/ids/report/<task_id>`: Check analysis status.
    -   Response: `{"status": "completed", "verdict": "clean|malicious", ...}`
