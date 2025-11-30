# E2E Messaging Demo (Flask)

## Overview
This project is a small Flask application that demonstrates the following cryptographic concepts:
- **SHA-256**: Simple password hashing (demo-only, not production-grade security).
- **Diffie-Hellman (DH)**: Browser-side key exchange for establishing shared secrets.
- **XOR-based encryption**: A simple symmetric encryption mechanism using XOR with a shared key and initialization vector (IV).
- **Custom HMAC-like function**: A lightweight message authentication mechanism for integrity.

## Quick Start (Local Use Only)
1. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   . venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Flask secret and run the application:**
   ```bash
   export FLASK_APP=app.py
   export FLASK_SECRET='replace-with-secure-value'
   python app.py
   ```

4. **Access the application:**
   Open [http://localhost:8000](http://localhost:8000) in your browser.

## Project Layout
- `app.py`: Flask backend handling routes, database, and API endpoints.
- `templates/`: HTML templates for the user interface (e.g., `login.html`, `chat.html`, `register.html`).
- `static/`: Contains JavaScript (`crypto.js`) and CSS (`styles.css`) files.
- `requirements.txt`: Lists Python dependencies.

## Recent Changes
- Removed unused `crypto_basic.js` file to streamline the project.
- Updated `debug.html` to remove unnecessary notes and ensure clarity.
- Implemented a simple AES-CBC-style block cipher and custom HMAC-like function. The active mode (AES-CBC vs XOR stream) is controlled by a `USE_AES` flag in `static/crypto.js`.

## License
This project is licensed under the MIT License.
