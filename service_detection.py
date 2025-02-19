import nmap

def service_scan(target, port_range="1-1024"):
    scanner = nmap.PortScanner()
    print(f"\nScanning {target} for services on ports {port_range}...\n")

    scanner.scan(target, port_range, arguments="-sV") 

    if target in scanner.all_hosts():
        for proto in scanner[target].all_protocols():
            print(f"\n🔹 Protocol: {proto.upper()}")
            for port in sorted(scanner[target][proto].keys()):
                service = scanner[target][proto][port]
                print(f"  🔘 Port {port}: {service['state'].upper()} - {service['name']} ({service['product']} {service['version']})")
    else:
        print("❌ Target not responding.")

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    port_range = input("Enter port range (default: 1-1024): ") or "1-1024"
    service_scan(target, port_range)
