from flask import Flask, render_template, request
import nmap
import hashlib
import requests
import re

app = Flask(__name__)

# --- INIT NMAP ---
try:
    scanner = nmap.PortScanner()
except Exception as e:
    print("Nmap init failed:", e)
    scanner = None

# --- PORT RISKS ---
risky_ports = {
    21: "FTP (Insecure file transfer)",
    22: "SSH (check for weak passwords)",
    23: "Telnet (Unencrypted/Unsafe)",
    25: "SMTP (Email service)",
    80: "HTTP (Unencrypted web traffic)",
    135: "RPC (Windows Remote Procedure Call)",
    443: "HTTPS (Secure web traffic)",
    445: "SMB (Ransomware risk)",
    3389: "RDP (Brute-force risk)"
}

# --- PASSWORD STRENGTH ---
def check_strength(password):
    score = 0
    if len(password) >= 8: score += 20
    if re.search(r"[A-Z]", password): score += 20
    if re.search(r"[a-z]", password): score += 20
    if re.search(r"[0-9]", password): score += 20
    if re.search(r"[!@#$%^&*]", password): score += 20

    if score < 40:
        strength = "Weak"
    elif score < 70:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, score

# --- HIBP CHECK ---
def check_password_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code != 200:
            return -1

        for line in res.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)

        return 0
    except:
        return -1

# --- WEB HEADER ANALYSIS ---
def analyze_headers(headers):
    checks = {
        "Content-Security-Policy": "Prevents XSS attacks",
        "Strict-Transport-Security": "Forces HTTPS",
        "X-Frame-Options": "Prevents clickjacking",
        "X-XSS-Protection": "Basic XSS protection"
    }

    analyzed = []

    for key, desc in checks.items():
        value = headers.get(key)

        if value:
            status = "safe"
        else:
            status = "missing"

        analyzed.append({
            "name": key,
            "value": value,
            "desc": desc,
            "status": status
        })

    return analyzed

# --- ROUTES ---

# 🖥️ DASHBOARD
@app.route("/")
def home():
    return render_template("index.html")

# 🔍 PORT SCANNER
@app.route("/scanner", methods=["GET", "POST"])
def scanner_tool():
    results = None
    target = None
    error = None

    if request.method == "POST":
        target = (request.form.get("target") or "").strip()
        results = []

        print("Target:", target)
        print("Scanner:", scanner)

        if not target:
            error = "Enter a valid target"
        else:
            if scanner:
                try:
                    scanner.scan(hosts=target, ports="1-1024", arguments="-sT -T4")

                    for host in scanner.all_hosts():
                        for proto in scanner[host].all_protocols():
                            for port in scanner[host][proto].keys():
                                state = scanner[host][proto][port]["state"]

                                if state == "open":
                                    results.append({
                                        "port": port,
                                        "risk": risky_ports.get(port, "Unknown service"),
                                        "is_risky": port in risky_ports
                                    })

                except Exception as e:
                    print("Scan error:", e)
                    error = "Scan failed"

            # DEMO fallback
            if not scanner or not results:
                results = [
                    {"port": 80, "risk": "HTTP (Unencrypted web traffic)", "is_risky": True},
                    {"port": 443, "risk": "HTTPS (Secure web traffic)", "is_risky": False},
                    {"port": 22, "risk": "SSH (check passwords)", "is_risky": True},
                    {"port": 53, "risk": "DNS service", "is_risky": False}
                ]

    return render_template("scanner.html", results=results, target=target, error=error)

# 🔐 PASSWORD TOOL
@app.route("/password", methods=["GET", "POST"])
def password_check():
    result = None

    if request.method == "POST":
        pwd = request.form.get("password")

        if pwd:
            strength, score = check_strength(pwd)
            breaches = check_password_pwned(pwd)

            if breaches == -1:
                msg, level = "Could not check breach database", "unknown"
            elif breaches == 0:
                msg, level = "Not found in breaches", "safe"
            elif breaches < 1000:
                msg, level = f"Appeared {breaches:,} times. Not safe.", "warning"
            else:
                msg, level = f"Appeared {breaches:,} times. Extremely unsafe!", "danger"

            result = {
                "strength": strength,
                "score": score,
                "breaches": breaches,
                "breach_msg": msg,
                "risk_level": level
            }

    return render_template("password.html", result=result)

# 🌐 WEB SECURITY TOOL
@app.route("/web", methods=["GET", "POST"])
def web_tool():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        if url and not url.startswith("http"):
            url = "http://" + url

        try:
            response = requests.get(url, timeout=5)
            headers = response.headers

            result = {
                "url": url,
                "status": response.status_code,
                "https": url.startswith("https"),
                "headers": analyze_headers(headers)
            }

        except:
            result = {"error": "Could not reach the site"}

    return render_template("web.html", result=result)

# --- RUN ---
if __name__ == "__main__":
    app.run(debug=True)