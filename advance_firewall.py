from flask import Flask, request, jsonify
from threading import Thread
from scapy.all import sniff, TCP, Raw, IP
import re
import time
import logging

# === Logger Setup ===
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# === Malicious Payload Patterns for DPI ===
patterns = {
    "SQL Injection": r"(?:')|(?:--)|(/\*(?:.|[\n\r])*?\*/)|(\b(OR|AND)\b\s+\w+\s*=\s*\w+)",
    "XSS": r"<script.*?>.*?</script>",
    "Sensitive Keywords": r"\b(password|admin|root)\b"
}

# === Packet Inspection Logic ===
def inspect_packet(packet):
    if packet.haslayer(Raw) and packet.haslayer(TCP) and packet.haslayer(IP):
        payload = packet[Raw].load.decode(errors='ignore')
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # === HTTP Filtering ===
        for threat, pattern in patterns.items():
            if re.search(pattern, payload, re.IGNORECASE):
                msg = f"[HTTP] {threat} detected from {src_ip} — Payload: {payload}"
                print(msg)
                logging.warning(msg)
                return

        # === FTP Filtering (port 21) ===
        if dst_port == 21:
            if re.search(r"(?i)(USER|PASS|STOR|RETR|MKD|RMD|DELE|SITE)", payload):
                msg = f"[FTP] Command detected from {src_ip} — Payload: {payload}"
                print(msg)
                logging.warning(msg)
                return

        # === DNS Filtering (port 53) ===
        if dst_port == 53:
            # Look for long, suspicious subdomains that may indicate tunneling or base64 payloads
            if re.search(r"(?:[a-zA-Z0-9]{10,}\.){2,}", payload):
                msg = f"[DNS] Suspicious DNS payload from {src_ip} — Payload: {payload}"
                print(msg)
                logging.warning(msg)
                return

def start_sniffing():
    print("[*] Packet sniffing started...")
    sniff(filter="tcp port 5000", prn=inspect_packet, store=0)

# === Flask API ===
app = Flask(__name__)

# In-memory User DB
users = {
    "user1": {"api_key": "secure-key-123", "role": "admin"},
    "user2": {"api_key": "secure-key-456", "role": "viewer"}
}

# Rate limiting tracker
rate_limit = {}

@app.before_request
def check_auth_and_rate_limit():
    api_key = request.headers.get("X-API-Key")
    user = next((u for u, v in users.items() if v['api_key'] == api_key), None)

    if not user:
        msg = "Blocked unauthorized request."
        print(msg)
        logging.warning(msg)
        return jsonify({"error": "Unauthorized"}), 401

    now = time.time()
    last_time = rate_limit.get(api_key, 0)

    if now - last_time < 0:
        msg = f"Rate limited request from {user}"
        print(msg)
        logging.warning(msg)
        return jsonify({"error": "Rate limit exceeded"}), 429

    rate_limit[api_key] = now

@app.route('/api/data', methods=['GET', 'POST'])
def get_data():
    # Combine GET query and POST body
    post_data = request.get_data(as_text=True)
    get_query = request.args.get('q', '')
    combined_payload = get_query + " " + post_data

    # === SQL Injection Detection ===
    sqli_pattern = r"(?:')|(?:--)|(/\*(?:.|[\n\r])*?\*/)|(\b(OR|AND)\b\s+\w+\s*=\s*\w+)"
    if re.search(sqli_pattern, combined_payload, re.IGNORECASE):
        msg = f"[Flask-SQLi] SQL Injection attempt detected — Payload: {combined_payload}"
        print(msg)
        logging.warning(msg)
        return jsonify({"error": "SQL Injection blocked"}), 403

    # === XSS Detection ===
    if re.search(r"<script.*?>.*?</script>", combined_payload, re.IGNORECASE):
        msg = f"[Flask-XSS] XSS attempt detected — Payload: {combined_payload}"
        print(msg)
        logging.warning(msg)
        return jsonify({"error": "XSS attack blocked"}), 403

    # === FTP Command Detection ===
    if re.search(r"(?i)(USER|PASS|STOR|RETR|MKD|RMD|DELE|SITE)", combined_payload):
        msg = f"[Flask-FTP] FTP command detected — Payload: {combined_payload}"
        print(msg)
        logging.warning(msg)
        return jsonify({"error": "FTP command blocked"}), 403

    # === DNS Tunneling Detection ===
    if re.search(r"(?:[a-zA-Z0-9]{10,}\.){2,}", combined_payload):
        msg = f"[Flask-DNS] Suspicious DNS pattern — Payload: {combined_payload}"
        print(msg)
        logging.warning(msg)
        return jsonify({"error": "DNS tunneling blocked"}), 403

    # === If all checks pass ===
    msg = f"Access granted — API key: {request.headers.get('X-API-Key')}"
    print(msg)
    logging.info(msg)
    return jsonify({"message": "Access granted to secure data."})


# === Main Function ===
if __name__ == '__main__':
    # Run packet sniffer in a background thread
    sniffer_thread = Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()

    # Run Flask API server
    print("[*] Starting API server on http://localhost:5000")
    app.run(port=5000)







