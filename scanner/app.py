from flask import Flask, render_template, request
import nmap

app = Flask(__name__)
scanner = nmap.PortScanner()

# Common ports and their meanings
risky_ports = {
    21: "FTP (Insecure file transfer)",
    22: "SSH (Secure Shell - check for weak passwords)",
    23: "Telnet (Unencrypted/Unsafe)",
    25: "SMTP (Email service)",
    80: "HTTP (Unencrypted web traffic)",
    135: "RPC (Windows Remote Procedure Call)",
    443: "HTTPS (Secure web traffic)",
    445: "SMB (Common ransomware entry point)",
    3389: "RDP (Remote Desktop - brute force risk)"
}

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    target = None

    if request.method == "POST":
        target = request.form.get("target")
        results = []
        
        try:
            # Scanning common ports 1-1024
            scanner.scan(target, "1-1024")

            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        state = scanner[host][proto][port]["state"]

                        if state == "open":
                            risk_desc = risky_ports.get(port, "Unknown service")
                            results.append({
                                "port": port,
                                "risk": risk_desc,
                                "is_risky": port in risky_ports
                            })
        except Exception as e:
            print(f"Error during scan: {e}")
            # results remains an empty list if error occurs

    return render_template("index.html", results=results, target=target)

if __name__ == "__main__":
    app.run()