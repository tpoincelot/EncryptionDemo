from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from argon2 import PasswordHasher
import os
import secrets
import json
import random
import logging
import pathlib

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_hex(16))

LOG_PATH = pathlib.Path(__file__).resolve().parent / 'handshake_debug.log'
LOG_PATH.parent.mkdir(exist_ok=True)
logger = logging.getLogger('handshake')
logger.setLevel(logging.INFO)
handler = logging.FileHandler(LOG_PATH, mode='a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

DB_PATH = 'data.db'
ph = PasswordHasher()
PRIME_OPTIONS = [100003, 100019, 100043, 100049, 100057, 100069, 100103]

def pick_random_prime():
    return str(random.choice(PRIME_OPTIONS))

def pick_random_generator(p):
    try:
        max_val = int(p) - 2
    except (ValueError, TypeError):
        max_val = 10
    if max_val < 3:
        max_val = 3
    return str(random.randint(2, max_val))

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
    c.execute('''CREATE TABLE IF NOT EXISTS public_keys (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    public_key TEXT,
                    g TEXT,
                    p TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS key_logs (
                    id INTEGER PRIMARY KEY,
                    initiator TEXT,
                    recipient TEXT,
                    algorithm TEXT,
                    parameters TEXT,
                    role TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS dh_sessions (
                    id INTEGER PRIMARY KEY,
                    initiator TEXT,
                    recipient TEXT,
                    p TEXT,
                    g TEXT,
                    status TEXT DEFAULT 'pending',
                    created DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(initiator, recipient, status)
                )''')
    conn.commit()
    existing_public = [row['name'] for row in conn.execute("PRAGMA table_info(public_keys)").fetchall()]
    if 'g' not in existing_public:
        c.execute('ALTER TABLE public_keys ADD COLUMN g TEXT')
    if 'p' not in existing_public:
        c.execute('ALTER TABLE public_keys ADD COLUMN p TEXT')
    existing_logs = [row['name'] for row in conn.execute("PRAGMA table_info(key_logs)").fetchall()]
    if 'role' not in existing_logs:
        c.execute('ALTER TABLE key_logs ADD COLUMN role TEXT')
    conn.commit()
    c.execute('DELETE FROM key_logs')
    c.execute('DELETE FROM dh_sessions')
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
        try:
            pw_hash = ph.hash(password)
            conn = get_db()
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            return "Username already exists", 400
        except Exception as e:
            return f"Error: {e}", 500
        return redirect('/')
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    try:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        conn.close()
        if not user:
            return "Invalid credentials", 403
        ph.verify(user['password_hash'], password)
        session['username'] = username
        return redirect('/chat')
    except Exception as e:
        return f"Error: {e}", 500

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
    try:
        data = request.get_json()
        if not data or 'from' not in data or 'public_key' not in data or 'g' not in data or 'p' not in data:
            return jsonify(success=False, error="Invalid request format"), 400

        username = data['from']
        public_key = data['public_key']
        g_value = data['g']
        p_value = data['p']

        conn = get_db()
        conn.execute(
            'INSERT OR REPLACE INTO public_keys (username, public_key, g, p) VALUES (?, ?, ?, ?)',
            (username, public_key, g_value, p_value),
        )
        conn.commit()
        conn.close()
        logger.info('public_key uploaded by %s g=%s p=%s', username, g_value, p_value)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/public_key/<username>', methods=['GET'])
def get_public_key(username):
    try:
        conn = get_db()
        row = conn.execute('SELECT public_key, g, p FROM public_keys WHERE username=?', (username,)).fetchone()
        conn.close()
        if not row:
            return jsonify(success=False, error="Public key not found"), 404
        return jsonify(success=True, username=username, public_key=row['public_key'], g=row['g'], p=row['p'])
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/dh_sessions', methods=['POST'])
def create_dh_session():
    try:
        data = request.get_json()
        required = ['initiator', 'recipient']
        if not data or not all(k in data for k in required):
            return jsonify(success=False, error="Invalid request format"), 400
        initiator = data['initiator']
        recipient = data['recipient']
        conn = get_db()
        existing = conn.execute('SELECT id, initiator, recipient, p, g FROM dh_sessions WHERE initiator=? AND recipient=? AND status="pending"',
                                (initiator, recipient)).fetchone()
        if existing:
            conn.close()
            logger.info('existing session returned for %s -> %s', initiator, recipient)
            return jsonify(success=True, session=dict(existing))
        p = pick_random_prime()
        g = pick_random_generator(p)
        try:
            c = conn.cursor()
            c.execute('INSERT INTO dh_sessions (initiator, recipient, p, g) VALUES (?, ?, ?, ?)',
                      (initiator, recipient, p, g))
            session_id = c.lastrowid
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            existing = conn.execute('SELECT id, initiator, recipient, p, g FROM dh_sessions WHERE initiator=? AND recipient=? AND status="pending"',
                                    (initiator, recipient)).fetchone()
            conn.close()
            if existing:
                logger.info('integrity case returning existing session for %s -> %s', initiator, recipient)
                return jsonify(success=True, session=dict(existing))
            raise
        session = {'id': session_id, 'initiator': initiator, 'recipient': recipient, 'p': p, 'g': g}
        conn.close()
        logger.info('created DH session %s for %s -> %s (p=%s g=%s)', session_id, initiator, recipient, p, g)
        return jsonify(success=True, session=session)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/dh_sessions/<username>', methods=['GET'])
def get_dh_session(username):
    try:
        conn = get_db()
        row = conn.execute('SELECT id, initiator, recipient, p, g FROM dh_sessions WHERE recipient=? AND status="pending" ORDER BY id DESC LIMIT 1',
                           (username,)).fetchone()
        conn.close()
        if not row:
            return jsonify(success=False, error="Session not found"), 404
        return jsonify(success=True, session=dict(row))
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/dh_sessions/<int:session_id>/complete', methods=['POST'])
def complete_dh_session(session_id):
    try:
        conn = get_db()
        conn.execute('UPDATE dh_sessions SET status="done" WHERE id=?', (session_id,))
        conn.commit()
        conn.close()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/messages', methods=['POST'])
def post_message():
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ['sender', 'recipient', 'ciphertext', 'iv', 'hmac']):
            return jsonify(success=False, error="Invalid request format"), 400
        conn = get_db()
        conn.execute('INSERT INTO messages (sender, recipient, ciphertext, iv, hmac) VALUES (?, ?, ?, ?, ?)',
                     (data['sender'], data['recipient'], data['ciphertext'], data['iv'], data['hmac']))
        conn.commit()
        conn.close()
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(success=False, error="Database error"), 500
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/key_logs', methods=['POST'])
def log_key_exchange():
    try:
        data = request.get_json()
        required = ['initiator', 'recipient', 'algorithm', 'parameters', 'role']
        if not data or not all(k in data for k in required):
            return jsonify(success=False, error="Invalid request format"), 400
        conn = get_db()
        conn.execute('INSERT INTO key_logs (initiator, recipient, algorithm, parameters, role) VALUES (?, ?, ?, ?, ?)',
                     (data['initiator'], data['recipient'], data['algorithm'], data['parameters'], data['role']))
        conn.commit()
        conn.close()
        logger.info('key_log %s %s -> %s role=%s', data['algorithm'], data['initiator'], data['recipient'], data['role'])
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/reset_session', methods=['POST'])
def reset_session():
    try:
        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify(success=False, error="Missing username"), 400
        username = data['username']
        conn = get_db()
        conn.execute('DELETE FROM messages WHERE sender=? OR recipient=?', (username, username))
        conn.execute('DELETE FROM public_keys WHERE username=?', (username,))
        conn.execute('DELETE FROM key_logs WHERE initiator=? OR recipient=?', (username, username))
        conn.execute('DELETE FROM dh_sessions WHERE initiator=? OR recipient=?', (username, username))
        conn.commit()
        conn.close()
        logger.info('reset session for %s', username)
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/api/messages/<username>', methods=['GET'])
def get_messages(username):
    try:
        conn = get_db()
        rows = conn.execute('SELECT sender, ciphertext, iv, hmac, timestamp FROM messages WHERE recipient=? ORDER BY id ASC', (username,)).fetchall()
        conn.close()
        msgs = [dict(r) for r in rows]
        return jsonify(messages=msgs)
    except Exception as e:
        return jsonify(success=False, error=str(e)), 500

@app.route('/debug/db')
def debug_db():
    if 'username' not in session:
        return "Unauthorized access", 403

    conn = get_db()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    messages = conn.execute('SELECT id, sender, recipient, ciphertext, iv, hmac, timestamp FROM messages').fetchall()
    raw_logs = conn.execute('SELECT id, initiator, recipient, algorithm, parameters, role, timestamp FROM key_logs ORDER BY id DESC').fetchall()
    key_logs = []
    for row in raw_logs:
        entry = dict(row)
        params = {}
        try:
            if entry.get('parameters'):
                params = json.loads(entry['parameters'])
        except json.JSONDecodeError:
            params = {}
        entry['params'] = params
        key_logs.append(entry)
    conn.close()

    return render_template('debug.html', users=users, messages=messages, key_logs=key_logs)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000, debug=True)