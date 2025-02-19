import nmap

target = input("Enter target IP or hostname: ")
port_range = input("Enter port range (default: 1-1024): ") or "1-1024"

scanner = nmap.PortScanner()

print(f"\n🚀 Scanning {target} for ports {port_range}...\n")

try:
    scanner.scan(target, arguments=f"-p {port_range} -sV")  
    if target not in scanner.all_hosts():
        print("❌ Target is not responding or unreachable.")
    else:
        print(f"\n✅ Host: {target} ({scanner[target].hostname()})")
        print(f"🔹 State: {scanner[target].state()}")

        for proto in scanner[target].all_protocols():
            print(f"\n📌 Protocol: {proto.upper()}")

            scanned_ports = scanner[target][proto].keys()
            
            if scanned_ports:
                for port in sorted(scanned_ports):
                    state = scanner[target][proto][port]['state']
                    print(f"  🔘 Port {port}: {state.upper()}") 
            else:
                print("  ❌ No open ports detected in the scanned range.")

except Exception as e:
    print(f"⚠️ Error: {e}")

print("\n✅ Scanning complete.")
