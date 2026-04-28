import nmap

scanner = nmap.PortScanner()

target = input("Enter target IP: ")

print(f"Scanning {target}...\n")

scanner.scan(target, '1-1024')

for host in scanner.all_hosts():
    print(f"Host: {host}")
    
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        
        for port in ports:
            state = scanner[host][proto][port]['state']
            print(f"Port {port}: {state}")