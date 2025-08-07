# Serial Data Receiver API
from flask import Flask, request, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
DATABASE = 'serial_data.db'

# Ensure database exists
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS serial_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            hex TEXT NOT NULL,
            text TEXT NOT NULL
        )''')

@app.route('/stream', methods=['POST'])
def receive_stream():
    data = request.get_json()
    if not data or 'timestamp' not in data or 'hex' not in data or 'text' not in data:
        return jsonify({'error': 'Invalid payload'}), 400

    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute("INSERT INTO serial_logs (timestamp, hex, text) VALUES (?, ?, ?)",
                         (data['timestamp'], data['hex'], data['text']))
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/data', methods=['GET'])
def get_all_data():
    try:
        with sqlite3.connect(DATABASE) as conn:
            rows = conn.execute("SELECT id, timestamp, hex, text FROM serial_logs ORDER BY id DESC LIMIT 100").fetchall()
        logs = [{'id': row[0], 'timestamp': row[1], 'hex': row[2], 'text': row[3]} for row in rows]
        return jsonify(logs), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/data/<int:last_id>', methods=['GET'])
def get_data_since(last_id):
    try:
        with sqlite3.connect(DATABASE) as conn:
            rows = conn.execute("SELECT id, timestamp, hex, text FROM serial_logs WHERE id > ? ORDER BY id ASC", (last_id,)).fetchall()
        logs = [{'id': row[0], 'timestamp': row[1], 'hex': row[2], 'text': row[3]} for row in rows]
        return jsonify(logs), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=9000)