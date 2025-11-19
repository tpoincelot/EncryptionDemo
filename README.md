```markdown
# E2E Messaging Demo (Flask + WebCrypto)

Overview
- Small web app to demonstrate Argon2 password hashing, ECDH Diffie-Hellman in the browser to derive AES keys, AES-256-CBC encryption with per-message IV, and HMAC-SHA256 (Encrypt-then-MAC).

Quick start (Ubuntu)
1. Install Python 3.10+ and virtualenv.
2. git clone <repo>
3. python3 -m venv venv && . venv/bin/activate
4. pip install -r requirements.txt
5. export FLASK_APP=app.py; export FLASK_SECRET='replace-with-secure'
6. python app.py
7. Visit https://your-server:8000 or http://localhost:8000 (prefer HTTPS)

Notes on HTTPS
- For production or public demos use nginx + certbot for Let's Encrypt (or use a self-signed cert for local testing - explain in report).
```