
import time
import json
import subprocess
import requests

LOG_FILE = "/var/log/suricata/eve.json"
API_URL = "http://127.0.0.1:5000/api/rules"
SEEN_IPS = set()

WHITELIST_IPS = {
    "127.0.0.1"
    # add more whitelisted IPs here....
}

def follow(thefile):
    """Generator function that yields new lines in a file."""
    print("--> DEBUG: Seeking to the end of the file.")
    thefile.seek(0, 2)  # Go to the end of a file
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)  # Sleep briefly
            continue
        yield line

def block_ip(ip):
    """Adds the IP to the blocklist via the Flask API, checking the whitelist first."""
    if ip in WHITELIST_IPS:
        print(f"\n--> WHITELIST: Detected alert from trusted IP {ip}. Ignoring.\n")
        return

    if ip in SEEN_IPS:
        print(f"--> INFO: IP {ip} has already been blocked recently. Skipping.")
        return
    
    print(f"--> ACTION: Attempting to block IP: {ip}")
    try:
        payload = {"ip": ip, "action": "DROP"}
        headers = {"Content-Type": "application/json"}
        response = requests.post(API_URL, json=payload, headers=headers)
        if response.status_code == 201:
            print(f"--> SUCCESS: API accepted block rule for {ip}.")
            SEEN_IPS.add(ip)
        else:
            print(f"--> ERROR: API returned status {response.status_code}. Response: {response.text}")
    except requests.exceptions.ConnectionError as e:
        print(f"--> FATAL ERROR: Could not connect to the API at {API_URL}. Is app.py running?")
    except Exception as e:
        print(f"--> UNKNOWN ERROR: An exception occurred: {e}")

if __name__ == "__main__":
    print(f"Starting IDS monitor on log file: {LOG_FILE}")
    print(f"--> INFO: Whitelisted IPs: {WHITELIST_IPS}")
    try:
        with open(LOG_FILE, 'r') as logfile:
            print("--> DEBUG: Successfully opened log file.")
            loglines = follow(logfile)
            for line in loglines:
                try:
                    data = json.loads(line)
                    
                    # json pretty-print
                    pretty_json = json.dumps(data, indent=4)
                    print("\n----------------------------------------------------")
                    print(f"--> DEBUG: Read new JSON object from log:")
                    print(pretty_json)
                    print("----------------------------------------------------\n")

                    if data.get("event_type") == "alert":
                        src_ip = data.get("src_ip")
                        alert_signature = data.get("alert", {}).get("signature", "N/A")
                        
                        print("\n===================================")
                        print("      >>> ALERT DETECTED <<<     ")
                        print(f"Threat: {alert_signature}")
                        print(f"Source IP: {src_ip}")
                        print("===================================\n")
                        
                        if src_ip:
                            block_ip(src_ip)
                except json.JSONDecodeError:
                    print(f"--> DEBUG: Read non-JSON line from log: {line.strip()}")
                except Exception as e:
                    print(f"--> ERROR: An error occurred processing a line: {e}")

    except FileNotFoundError:
        print(f"--> FATAL ERROR: Log file not found at {LOG_FILE}. Is Suricata running and logging?")
    except PermissionError:
        print(f"--> FATAL ERROR: Permission denied to read {LOG_FILE}. Please run this script with 'sudo'.")
    except Exception as e:
        print(f"--> FATAL ERROR: An unexpected error occurred: {e}")


