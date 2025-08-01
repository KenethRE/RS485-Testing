# TCP Web App: Flask server to bridge TCP<->Web interface for W610 with Admin Panel
from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import socket
import threading
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'users.db'

# --- Admin-only panel ---
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    msg = None
    if request.method == 'POST':
        if 'delete' in request.form:
            to_delete = request.form['delete']
            if to_delete != 'admin':
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute("DELETE FROM users WHERE username = ?", (to_delete,))
                msg = f"🗑️ User '{to_delete}' deleted."
            else:
                msg = "❌ You cannot delete the default admin."
        else:
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
    return render_template('admin.html', users=users, msg=msg)

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        # Prompt for admin password if no users exist
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

# TCP config
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
            socketio.emit('tcp_response', {'hex': data.hex(), 'text': data.decode(errors='replace'), 'timestamp': timestamp})
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
        client_socket.settimeout(None)  # Disable timeout for recv()
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
    with open('templates/login.html', 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>Login</title>
  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
</head>
<body class='bg-light'>
  <div class='container mt-5'>
    <div class='card shadow'>
      <div class='card-body'>
        <h2 class='card-title'>Login</h2>
        {% if error %}<div class='alert alert-danger'>{{ error }}</div>{% endif %}
        <form method='post'>
          <div class='mb-3'>
            <label class='form-label'>Username</label>
            <input type='text' name='username' class='form-control'>
          </div>
          <div class='mb-3'>
            <label class='form-label'>Password</label>
            <input type='password' name='password' class='form-control'>
          </div>
          <button type='submit' class='btn btn-primary'>Login</button>
        </form>
      </div>
    </div>
  </div>
</body>
</html>""")

    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>W610 TCP Web Console</title>
  <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
  <script src='https://cdn.socket.io/4.5.4/socket.io.min.js'></script>
  <style>
    #logContainer {
      height: 300px;
      overflow-y: auto;
      font-family: monospace;
      white-space: pre-wrap;
      background-color: #f8f9fa;
      border: 1px solid #dee2e6;
      padding: 1em;
    }
  </style>
</head>
<body class='bg-light'>
  <div class='container mt-4'>
    <div class='d-flex justify-content-between align-items-center mb-3'>
      <h2>W610 TCP Web Console</h2>
      <a href='/logout' class='btn btn-outline-danger btn-sm'>Logout</a>
    </div>
    <div class='mb-3'>
      <strong>Status:</strong> <span id='status' class='text-muted'>disconnected</span>
      <button onclick='connectTCP()' class='btn btn-success btn-sm ms-3'>Connect</button>
      <button onclick='disconnectTCP()' class='btn btn-warning btn-sm ms-1'>Disconnect</button>
    </div>
    <div id='logContainer' class='mb-4'></div>
    <div class='row g-2'>
      <div class='col-auto'>
        <select id='dataType' class='form-select'>
          <option value='text'>Text</option>
          <option value='hex'>Hex</option>
        </select>
      </div>
      <div class='col'>
        <input type='text' id='inputData' class='form-control' placeholder='Enter text or hex'>
      </div>
      <div class='col-auto'>
        <button onclick='sendData()' class='btn btn-primary'>Send</button>
      </div>
    </div>
  </div>
  <script>
    const socket = io();
    const logContainer = document.getElementById('logContainer');

    socket.on('tcp_status', msg => {
      document.getElementById('status').innerText = msg.status;
    });

    socket.on('tcp_response', msg => {
      const logLine = `[${msg.timestamp}]\n[HEX] ${msg.hex}\n${msg.text}\n`;
      const div = document.createElement('div');
      div.textContent = logLine;
      logContainer.appendChild(div);
      logContainer.scrollTop = logContainer.scrollHeight;
    });

    function connectTCP() {
      socket.emit('connect_tcp');
    }

    function disconnectTCP() {
      socket.emit('disconnect_tcp');
    }

    function sendData() {
      const type = document.getElementById('dataType').value;
      const data = document.getElementById('inputData').value;
      if (!data) return;
      socket.emit('send_data', { type, text: data, hex: data });
    }
  </script>
</body>
</html>""")
    socketio.run(app, host='0.0.0.0', port=5000)
