# TCP Web App: Flask server to bridge TCP<->Web interface for W610 with Admin Panel
from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import socket
import threading
import os
import requests
import json

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'users.db'
EXTERNAL_URL = os.getenv('STREAM_URL')
external_buffer = []
BUFFER_FILE = 'external_buffer.jsonl'

if os.path.exists(BUFFER_FILE):
    with open(BUFFER_FILE, 'r', encoding='utf-8') as f:
        external_buffer.extend(line.strip() for line in f if line.strip())
    print(f"[External stream] Loaded {len(external_buffer)} buffered messages from disk.")

@app.route('/admin', methods=['GET', 'POST'])
@app.route('/admin/buffer', methods=['GET'])
@login_required
def admin_panel():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    msg = None
    if request.method == 'POST':
        if 'clear_buffer' in request.form:
            external_buffer.clear()
            with open(BUFFER_FILE, 'w', encoding='utf-8') as f:
                pass
            msg = "🧹 Buffer cleared."
        if 'flush_buffer' in request.form:
            flushed = 0
            try:
                while external_buffer:
                    cached = json.loads(external_buffer.pop(0))
                    requests.post(EXTERNAL_URL, json=cached, timeout=5, headers={
                            'Authorization': f"Bearer {os.getenv('STREAM_TOKEN', '')}"
                        })
                    flushed += 1
                with open(BUFFER_FILE, 'w', encoding='utf-8') as f:
                    pass
                msg = f"🚀 Flushed {flushed} messages from buffer."
            except Exception as e:
                msg = f"⚠️ Error while flushing buffer: {e}"
        if 'update_user' in request.form:
            to_update = request.form['update_user']
            new_pass = request.form['new_password']
            if new_pass:
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute("UPDATE users SET password = ? WHERE username = ?",
                                 (generate_password_hash(new_pass), to_update))
                msg = f"🔑 Password for '{to_update}' updated."
            else:
                msg = "❗ New password cannot be empty."
        if 'delete' in request.form:
            to_delete = request.form['delete']
            if to_delete != 'admin':
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute("DELETE FROM users WHERE username = ?", (to_delete,))
                msg = f"🗑️ User '{to_delete}' deleted."
            else:
                msg = "❌ You cannot delete the default admin."
        elif 'username' in request.form and 'password' in request.form and 'role' in request.form:
            new_user = request.form['username']
            password = request.form['password']
            role = request.form['role']
            if new_user and password:
                try:
                    with sqlite3.connect(DATABASE) as conn:
                        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                                     (new_user, generate_password_hash(password), role))
                    msg = f"✅ User '{new_user}' created."
                except sqlite3.IntegrityError:
                    msg = "❌ That username already exists."
    with sqlite3.connect(DATABASE) as conn:
        users = conn.execute("SELECT username, role FROM users").fetchall()
    buffer_status = {'count': len(external_buffer), 'path': BUFFER_FILE}
    return render_template('admin.html', users=users, msg=msg, buffer_status=buffer_status)

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        cursor = conn.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            import getpass
            print("✅ Users table found but no users exist.")
            print("⚙️  No users found. Let's set up the initial admin account.")
            while True:
                password = getpass.getpass("Set admin password: ")
                confirm = getpass.getpass("Confirm password: ")
                if password == confirm and password:
                    break
                print("❗ Passwords do not match or are empty. Try again.")
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         ('admin', generate_password_hash(password), 'admin'))
            print("✅ Admin user created successfully.")
        else:
            print("🔐 Admin user already exists. Skipping setup.")

class User(UserMixin):
    def __init__(self, id_, username, role):
        self.id = id_
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return User(row[0], row[1], row[2])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.execute("SELECT id, password, role FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row and check_password_hash(row[1], password):
                login_user(User(row[0], username, row[2]))
                return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

W610_IP = '192.168.0.115'
W610_PORT = 8899
TCP_TIMEOUT = 2.0
client_socket = None
connected = False

def tcp_receive_loop():
    global client_socket
    while connected:
        try:
            data = client_socket.recv(4096)
            timestamp = __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if not data:
                break
            socketio.emit('tcp_response', {
                'hex': data.hex(),
                'text': data.decode(errors='replace'),
                'timestamp': timestamp
            })
            if EXTERNAL_URL:
                try:
                    payload = {
                        "timestamp": timestamp,
                        "hex": data.hex(),
                        "text": data.decode(errors='replace')
                    }
                    response = requests.post(EXTERNAL_URL, json=payload, timeout=5, headers={
                        'Authorization': f"Bearer {os.getenv('STREAM_TOKEN', '')}"
                    })
                    response.raise_for_status()
                    if external_buffer:
                        print(f"[External stream] Flushing {len(external_buffer)} buffered messages...")
                        while external_buffer:
                            cached = json.loads(external_buffer.pop(0))
                            requests.post(EXTERNAL_URL, json=cached, timeout=5)
                        with open(BUFFER_FILE, 'w', encoding='utf-8') as f:
                            pass
                except Exception as e:
                    print(f"[External stream error] {e}")
                    try:
                        line = json.dumps(payload)
                        with open(BUFFER_FILE, 'a', encoding='utf-8') as f:
                            f.write(line + '\n')
                        external_buffer.append(line)
                        print(f"[External stream] Message buffered. Queue length: {len(external_buffer)}")
                    except Exception as write_error:
                        print(f"[Buffer write error] {write_error}")
        except Exception as e:
            print(f"[TCP recv error] {e}")
            break
    print("[TCP connection closed]")

@socketio.on('connect_tcp')
@login_required
def handle_connect_tcp():
    global client_socket, connected
    try:
        client_socket = socket.create_connection((W610_IP, W610_PORT), timeout=TCP_TIMEOUT)
        client_socket.settimeout(None)
        connected = True
        threading.Thread(target=tcp_receive_loop, daemon=True).start()
        emit('tcp_status', {'status': 'connected'})
    except Exception as e:
        emit('tcp_status', {'status': f'error: {e}'})

@socketio.on('disconnect_tcp')
@login_required
def handle_disconnect_tcp():
    global client_socket, connected
    connected = False
    if client_socket:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
        except:
            pass
    emit('tcp_status', {'status': 'disconnected'})


@socketio.on('send_data')
@login_required
def handle_send_data(data):
    global client_socket
    if not connected or not client_socket:
        emit('tcp_status', {'status': 'not connected'})
        return
    try:
        payload = bytes.fromhex(data['hex']) if data['type'] == 'hex' else data['text'].encode()
        client_socket.sendall(payload)
    except Exception as e:
        emit('tcp_status', {'status': f'error: {e}'})

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000)
