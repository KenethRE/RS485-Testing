from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/usr-w610', methods=['POST'])
def handle_usr_w610():
    data = request.get_json(force=True)
    # Process data from USR-W610 device
    # For demonstration, just echo back the received data
    print("Received data:", data)
    return jsonify({"status": "success", "received": data}), 200

@app.route('/')
def index():
    print("Request data:", request.data)
    return app.send_static_file('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)