# Linux Firewall with Web UI and IDS Integration
by Vibhaansh Bhardwaj(24BCE1401) & Mudit J. Palvadi(24BCE1510)

This project is a comprehensive, multi-layer network security system created for a college project. It combines a low-level C-based firewall with a high-level web interface for rule management and integrates a professional-grade Intrusion Detection System (IDS) for automated threat response.

A key feature of this project is that it's designed to run on a Tailscale network, filtering traffic that arrives on the tailscale0 virtual interface.

## What is Tailscale?

Tailscale is a modern VPN service that makes it easy to create secure, private networks. Think of it as a virtual private LAN (VLAN) that connects all your devices (laptops, servers, phones) together, no matter where they are in the world.

How it works: It creates a peer-to-peer mesh network, meaning your devices connect directly to each other instead of going through a central server.

Zero-Config: It works through complex firewalls and NATs without any manual configuration.

The "Why" for this Project: This firewall is built to protect a server within this private Tailscale network. It inspects traffic coming from your other trusted devices (like your laptop or phone) on the tailscale0 interface, rather than just blocking traffic from the public internet.

## Architecture Overview

The system operates in several concurrent layers.

iptables (Netfilter): The kernel's firewall acts as the main traffic controller. A custom chain (MyCustomFirewall) is created to process all incoming traffic.

Web UI (HTML/JS + Python Flask): The user manages high-level ACCEPT/DROP rules via a web interface. The Flask backend (app.py) translates these into iptables rules.

C Firewall Core (firewall_core.c): Any traffic not matching a rule in the web UI (but originating from the Tailscale network) is sent to a user-space queue (NFQUEUE). This C program reads from the queue, performs deep packet inspection (in our demo, it blocks 8.8.8.8), and sends a verdict (ACCEPT/DROP) back to the kernel.

IDS (Suricata): The Suricata engine runs in the background, sniffing all traffic on the tailscale0 interface for known threat signatures.

IDS Monitor (ids_monitor.py): This script "follows" the Suricata alert log (eve.json). When a new alert appears, it parses the attacker's IP and uses the Flask API to automatically add a new DROP rule, effectively creating an Intrusion Prevention System (IPS).

## Core Components

- firewall_core.c: The firewall written in C. Uses libnetfilter_queue.
- app.py: The Python Flask web server. Provides a JSON API to manage iptables rules.
- index.html: A single-page, responsive web interface built with Tailwind CSS for managing the firewall.
- ids_monitor.py: The Python script that links Suricata to the web API for automated blocking.
- requirements.txt: Python dependencies for the project.

## Prerequisites

Before you begin, you must have the following installed on your Debian-based Linux server:

- Tailscale: Installed and configured on your server and at least one other "client" machine for testing.
- Build Tools: sudo apt-get install build-essential
- C Libraries: sudo apt-get install libnetfilter-queue-dev libnfnetlink-dev
- Python: sudo apt-get install python3-pip python3-venv
- IDS: sudo apt-get install suricata suricata-update

## Setup and Installation

Follow these steps precisely to set up the entire system.

### 1. Clone the Repository

```
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2. Install Python Dependencies

It's recommended to use a virtual environment.

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Suricata (Crucial!)

You must tell Suricata to watch your Tailscale interface.

Find your Tailscale interface (usually tailscale0) and your network's IP range (e.g., 192.168.1.0/24).

Edit the Suricata configuration file:

```
sudo nano /etc/suricata/suricata.yaml
```

Find the HOME_NET variable and add your Tailscale network. It should look something like this (replace with your IPs):

```
HOME_NET: "[192.168.1.0/24, 100.X.X.X/32]"
```

Find the interface variable (under af-packet) and change it to tailscale0:

```
interface: tailscale0
```

Save and exit the file.

### 4. Update IDS Rules

Download the latest threat signatures for Suricata:

```
sudo suricata-update
```

### 5. Compile the C Firewall

Compile the C program to create the executable:

```
gcc -o firewall firewall_core.c -lnetfilter_queue -lnfnetlink
```

### 6. Whitelist Your Trusted IP (CRITICAL)

Add whatever IPs you need for testing to be in the whitelist

Edit the monitor script:

```
nano ids_monitor.py
```

Find the WHITELIST_IPS set and add your trusted IP:

```
WHITELIST_IPS = {
    "127.0.0.1",
    "100.12.34.56"  # <-- Change this to your trusted IP
}
```

Save and exit the file.

## How to Run the System

You will need 5 separate terminals on your firewall server to run all components.

### Terminal 1: Apply the iptables Rules

This is the most important step. Run this entire script to create the MyCustomFirewall chain and safely route traffic.

```bash
#!/bin/bash
echo "--- Starting Firewall Setup ---"

echo "--- Cleaning up old chains... ---"
sudo iptables -F MyCustomFirewall 2>/dev/null
sudo iptables -D INPUT -j MyCustomFirewall 2>/dev/null
sudo iptables -X MyCustomFirewall 2>/dev/null

echo "--- Creating and linking new chain 'MyCustomFirewall'... ---"
sudo iptables -N MyCustomFirewall
sudo iptables -I INPUT 1 -j MyCustomFirewall

echo "--- Adding core ACCEPT rules (Order is critical!)... ---"
# 1. Allow established connections
sudo iptables -A MyCustomFirewall -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# 2. Allow SSH (Port 22)
sudo iptables -A MyCustomFirewall -p tcp --dport 22 -j ACCEPT
# 3. Allow Tailscale control traffic
sudo iptables -A MyCustomFirewall -p udp --dport 41641 -j ACCEPT
# 4. Allow our Web UI (Port 5000)
sudo iptables -A MyCustomFirewall -p tcp --dport 5000 -j ACCEPT

echo "--- Adding NFQUEUE rule for C program... ---"
# 5. Send other Tailscale traffic to our C program for inspection
sudo iptables -A MyCustomFirewall -s 100.64.0.0/10 -j NFQUEUE --queue-num 0

echo "--- Setup complete. Final rules: ---"
sudo iptables -L MyCustomFirewall -n --line-numbers
```

### Terminal 2: Run the Web Backend

(Make sure your Python venv is active if you used one)

```
python3 app.py
```

You should see it running on 0.0.0.0:5000.

### Terminal 3: Run the C Firewall Core

This must be run with sudo.

```
sudo ./firewall
```

You should see it bind to queue '0' and wait for packets.

### Terminal 4: Run the IDS Engine

Start the Suricata service in the background.

```
sudo systemctl start suricata
```

### Terminal 5: Run the IDS Monitor

This must be run with sudo to read the system logs.

```
sudo python3 ids_monitor.py
```

You should see it "Starting IDS monitor..." and waiting.

## How to Test the Firewall

Your complete system is now running.

### Test 1: Web UI Manual Block

From your other Tailscale machine, start a continuous ping to your firewall's Tailscale IP.

```
ping <firewall_tailscale_ip>
```

On that same machine, open a browser and go to http://<firewall_tailscale_ip>:5000.

You should see the control panel.

In the "Add Rule" form, enter the IP address of the machine you are on and select DROP.

Click "Add Rule".

Observe your ping terminal. The pings should immediately start to fail.

Go back to the web UI, delete the rule, and watch the pings instantly resume.

### Test 2: C Firewall Custom Block

From your firewall server's terminal (a new one), try to ping Google's DNS.

```
ping 8.8.8.8
```

Observe the terminal running your C program (./firewall). You will see it detect and print "DROPPING" for packets from 8.8.8.8.

The ping command will fail.

### Test 3: Automated IDS/IPS Block

This is the final test of the complete system.

From your whitelisted test machine, run the test attack:

```
curl http://<firewall_tailscale_ip>:5000/?file=../../etc/passwd
```

Observe the IDS Monitor terminal. You should see it detect the alert and then print: --> WHITELIST: Detected alert from trusted IP... Ignoring. You will not be blocked.

Now, perform the test from a different, non-whitelisted Tailscale device (like your phone).

Run the same curl command from that device.

Observe the IDS Monitor terminal. Within seconds, it will print:

```
>>> ALERT DETECTED <<<
Threat: ET WEB_SERVER ../../ Directory Traversal
Source IP: <attacker_ip>
--> ACTION: Attempting to block IP: <attacker_ip>
--> SUCCESS: API accepted block rule for <attacker_ip>.
```

Refresh the web UI. You will see a new DROP rule for the attacker's IP, added automatically by the system. That device is now blocked.

## Common Troubleshooting

- **Error: Error during nfq_create_queue()**  
  Cause: The kernel module isn't loaded or no iptables rule is pointing to the queue.  
  Solution: Run sudo modprobe nfnetlink_queue and re-run the iptables setup script from Terminal 1.

- **Error: Error during nfq_unbind_pf()**  
  Cause: You ran the C program without sudo.  
  Solution: Run with sudo ./firewall.

- **Error: ids_monitor.py shows Permission denied.**  
  Cause: You ran the monitor script without sudo.  
  Solution: Run with sudo python3 ids_monitor.py.

- **Error: app.py fails with "Address already in use".**  
  Cause: Old instances of the app are stuck.  
  Solution: Run sudo fuser -k 5000/tcp to kill all processes on that port, then restart app.py.
