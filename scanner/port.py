import nmap
from colorama import Fore, Style, init
from datetime import datetime

init()

scanner = nmap.PortScanner()

target = input(Fore.MAGENTA + "Enter target IP: " + Style.RESET_ALL)

print(Fore.YELLOW + f"\nScanning {target}...\n" + Style.RESET_ALL)

scanner.scan(target, '1-1024')

risky_ports = {
    21: "FTP (insecure, sends data in plain text)",
    22: "SSH (secure but check for weak passwords)",
    23: "Telnet (very insecure, avoid using)",
    25: "SMTP (can be abused for spam)",
    53: "DNS (possible DNS attacks)",
    80: "HTTP (not encrypted)",
    110: "POP3 (email, often insecure)",
    139: "NetBIOS (Windows file sharing risk)",
    143: "IMAP (email service)",
    443: "HTTPS (secure communication)",
    445: "SMB (ransomware target)",
    3389: "RDP (remote access, brute-force risk)"
}

with open("scan_report.txt", "w") as report:
    report.write("=== Vulnerability Scan Report ===\n")
    report.write(f"Target: {target}\n\n")

    for host in scanner.all_hosts():
        print(Fore.CYAN + f"Host: {host}" + Style.RESET_ALL)
        report.write(f"Host: {host}\n")

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()

            for port in ports:
                state = scanner[host][proto][port]['state']

                if state == "open":
                    print(Fore.GREEN + f"Port {port} is OPEN" + Style.RESET_ALL)
                    report.write(f"Port {port} is OPEN\n")

                    if port in risky_ports:
                        print(Fore.RED + f" Risk: {risky_ports[port]}" + Style.RESET_ALL)
                        report.write(f"Risk: {risky_ports[port]}\n")
                    else:
                        print(Fore.BLUE + "Unknown service" + Style.RESET_ALL)
                        report.write("Unknown service\n")

print(Fore.MAGENTA + "\nTXT report saved" + Style.RESET_ALL)

time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

html_content = f"""
<html>
<head>
    <title>Vulnerability Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #1e1b4b, #0f0a2a);
            color: #e9d5ff;
            padding: 30px;
        }}

        h1 {{
            text-align: center;
            color: #c084fc;
        }}

        .target {{
            text-align: center;
            margin-bottom: 25px;
            color: #ddd6fe;
        }}

        .card {{
            background: #2e1065;
            padding: 20px;
            margin: 20px auto;
            border-radius: 15px;
            width: 80%;
            box-shadow: 0 0 20px rgba(192,132,252,0.3);
            transition: transform 0.2s;
        }}

        .card:hover {{
            transform: scale(1.03);
        }}

        .port {{
            margin: 8px 0;
        }}

        .badge {{
            padding: 4px 10px;
            border-radius: 8px;
            font-size: 12px;
            margin-left: 10px;
        }}

        .open {{ color: #a78bfa; }}
        .risk {{ color: #fb7185; }}
        .info {{ color: #c4b5fd; }}

        .badge-open {{
            background: #4c1d95;
            color: #a78bfa;
        }}

        .badge-risk {{
            background: #7f1d1d;
            color: #fb7185;
        }}

        .badge-info {{
            background: #312e81;
            color: #c4b5fd;
        }}
    </style>
</head>
<body>

<h1>Natalie’s Vulnerability Scanner</h1>
<div class="target">
    Target: <b>{target}</b> <br>
    Scan Time: {time_now}
</div>
"""

for host in scanner.all_hosts():
    html_content += f"<div class='card'><h2>Host: {host}</h2>"

    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()

        for port in ports:
            state = scanner[host][proto][port]['state']

            if state == "open":
                html_content += f"<div class='port open'> Port {port} is OPEN <span class='badge badge-open'>OPEN</span></div>"

                if port in risky_ports:
                    html_content += f"<div class='port risk'>{risky_ports[port]} <span class='badge badge-risk'>RISK</span></div>"
                else:
                    html_content += f"<div class='port info'>Unknown service <span class='badge badge-info'>INFO</span></div>"

    html_content += "</div>"

html_content += "</body></html>"

with open("scan_report.html", "w") as f:
    f.write(html_content)

print(Fore.MAGENTA + "\nHTML report saved as scan_report.html" + Style.RESET_ALL)