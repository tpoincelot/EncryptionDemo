```markdown
# E2E Messaging Demo (Flask + WebCrypto)

Short description
- A small Flask app demonstrating Argon2 password hashing, browser-side ECDH (Diffie-Hellman), AES-256-CBC encryption with per-message IV, and HMAC-SHA256 (Encrypt-then-MAC) for client-side end-to-end encrypted messaging.

Quick start (local)
1. Create & activate venv:
   python3 -m venv venv
   . venv/bin/activate

2. Install:
   pip install -r requirements.txt

3. Set Flask secret and run:
   export FLASK_APP=app.py
   export FLASK_SECRET='replace-with-secure-value'
   python app.py

4. Open http://localhost:8000

Project layout
- app.py - Flask backend
- templates/ - HTML templates (login.html, chat.html, register.html)
- static/ - JS (crypto.js) and CSS
- requirements.txt - Python dependencies

License
- MIT (or choose another)
```
