import nmap

def os_detection(target):
    scanner = nmap.PortScanner()
    print(f"\nPerforming OS detection on {target}...\n")

    scanner.scan(target, arguments="-O") 

    if target in scanner.all_hosts():
        os_guess = scanner[target]['osmatch'][0]['name'] if 'osmatch' in scanner[target] and scanner[target]['osmatch'] else "Unknown OS"
        print(f"✅ Target OS: {os_guess}")
    else:
        print("❌ Target not responding or OS detection failed.")

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    os_detection(target)


