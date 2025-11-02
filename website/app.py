# app.py
#
# -- UPDATED to be a standalone server --
# This version of the Flask app now serves both the API endpoints
# and the index.html frontend. No Nginx needed for testing.
#
# To run:
#   pip install Flask flask-cors
#   python3 app.py
#
# Then access from your browser at http://<your_server_ip>:5000
#
import subprocess
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
# CORS is still good practice, though less critical now
CORS(app)

# The name of our custom iptables chain
CHAIN_NAME = "MyCustomFirewall"

def run_command(command):
    """Executes a shell command and returns its output."""
    try:
        result = subprocess.run(
            command,
            check=True,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e.stderr.strip()}")
        return None

def setup_firewall_chain():
    """Ensure our custom iptables chain exists."""
    existing_chains = run_command("sudo iptables -L -n | grep " + CHAIN_NAME)
    if not existing_chains:
        print(f"Creating new chain: {CHAIN_NAME}")
        run_command(f"sudo iptables -N {CHAIN_NAME}")
        run_command(f"sudo iptables -I INPUT 1 -j {CHAIN_NAME}")

# --- NEW ROUTE TO SERVE THE FRONTEND ---
@app.route('/')
def serve_index():
    # This tells Flask to find 'index.html' in the same directory as app.py
    # and send it to the browser.
    print("Serving index.html")
    return send_from_directory('.', 'index.html')

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Fetch and parse the current rules from our custom chain."""
    setup_firewall_chain()
    output = run_command(f"sudo iptables -L {CHAIN_NAME} -n --line-numbers")
    if output is None:
        return jsonify({"error": "Failed to list iptables rules"}), 500

    rules = []
    lines = output.split('\n')[2:] 
    for line in lines:
        if not line:
            continue
        parts = line.split()
        rule = {
            "id": parts[0],
            "target": parts[1],
            "protocol": parts[2],
            "source": parts[4],
            "destination": "anywhere",
        }
        rules.append(rule)
    return jsonify(rules)


@app.route('/api/rules', methods=['POST'])
def add_rule():
    """Add a new rule to our custom chain."""
    data = request.json
    ip = data.get('ip')
    action = data.get('action', 'DROP').upper()

    if not ip or action not in ['ACCEPT', 'DROP', 'REJECT']:
        return jsonify({"error": "Invalid input. 'ip' and 'action' are required."}), 400

    command = f"sudo iptables -I {CHAIN_NAME} 1 -s {ip} -j {action}"
    if run_command(command) is not None:
        print(f"Added rule: {action} traffic from {ip}")
        return jsonify({"message": "Rule added successfully"}), 201
    else:
        return jsonify({"error": "Failed to add rule"}), 500

@app.route('/api/rules', methods=['DELETE'])
def delete_rule():
    """Delete a rule from our custom chain by its ID (line number)."""
    data = request.json
    rule_id = data.get('id')
    if not rule_id:
        return jsonify({"error": "Invalid input. 'id' is required."}), 400

    command = f"sudo iptables -D {CHAIN_NAME} {rule_id}"
    if run_command(command) is not None:
        print(f"Deleted rule with ID: {rule_id}")
        return jsonify({"message": "Rule deleted successfully"}), 200
    else:
        return jsonify({"error": "Failed to delete rule"}), 500

if __name__ == '__main__':
    setup_firewall_chain()
    # Host 0.0.0.0 makes it accessible on the local network
    app.run(host='0.0.0.0', port=5000, debug=True)


