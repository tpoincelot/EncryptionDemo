from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from argon2 import PasswordHasher
import os
import secrets

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_hex(16))

DB_PATH = 'data.db'
ph = PasswordHasher()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY,
                    sender TEXT,
                    recipient TEXT,
                    ciphertext BLOB,
                    iv BLOB,
                    hmac BLOB,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'username' in session:
        return redirect('/chat')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pw_hash = ph.hash(password)
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
            conn.commit()
        except Exception as e:
            conn.close()
            return f"Error: {e}", 400
        conn.close()
        return redirect('/')
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    conn.close()
    if not user:
        return "Invalid credentials", 403
    try:
        ph.verify(user['password_hash'], password)
    except:
        return "Invalid credentials", 403
    session['username'] = username
    return redirect('/chat')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect('/')
    return render_template('chat.html', username=session['username'])

# API endpoints for exchanging public keys and messages
@app.route('/api/public_key', methods=['POST'])
def upload_public_key():
    # Expects JSON: { to: username, from: username, public_key: base64 }
    data = request.get_json()
    # For simplicity, store in-memory (not persisted)
    return jsonify(success=True)

@app.route('/api/messages', methods=['POST'])
def post_message():
    # Expects JSON: { sender, recipient, ciphertext (b64), iv (b64), hmac (b64) }
    data = request.get_json()
    conn = get_db()
    conn.execute('INSERT INTO messages (sender, recipient, ciphertext, iv, hmac) VALUES (?, ?, ?, ?, ?)',
                 (data['sender'], data['recipient'], data['ciphertext'], data['iv'], data['hmac']))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/api/messages/<username>', methods=['GET'])
def get_messages(username):
    conn = get_db()
    rows = conn.execute('SELECT sender, ciphertext, iv, hmac, timestamp FROM messages WHERE recipient=? ORDER BY id ASC', (username,)).fetchall()
    conn.close()
    msgs = [dict(r) for r in rows]
    return jsonify(messages=msgs)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000, debug=True)