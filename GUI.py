import tkinter as tk
from tkinter import scrolledtext, messagebox
import nmap
import threading

scanner = nmap.PortScanner()

def run_scan(scan_function, target, port_range=None):
    thread = threading.Thread(target=scan_function, args=(target, port_range))
    thread.start()

# Function for Port Scanning
def port_scan(target, port_range="1-1024"):
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"\n🚀 Scanning {target} for ports {port_range}...\n")
    
    try:
        scanner.scan(target, arguments=f"-p {port_range} -sV")  

        if target not in scanner.all_hosts():
            output_box.insert(tk.END, "❌ Target is not responding or unreachable.\n")
        else:
            output_box.insert(tk.END, f"\n✅ Host: {target} ({scanner[target].hostname()})\n")
            output_box.insert(tk.END, f"🔹 State: {scanner[target].state()}\n")

            for proto in scanner[target].all_protocols():
                output_box.insert(tk.END, f"\n📌 Protocol: {proto.upper()}\n")
                for port in sorted(scanner[target][proto].keys()):
                    state = scanner[target][proto][port]['state']
                    output_box.insert(tk.END, f"  🔘 Port {port}: {state.upper()}\n")
    
    except Exception as e:
        output_box.insert(tk.END, f"⚠️ Error: {e}\n")
    
    output_box.insert(tk.END, "\n✅ Scanning complete.\n")

# Function for Service Detection
def service_scan(target, port_range="1-1024"):
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"\nScanning {target} for services on ports {port_range}...\n")

    try:
        scanner.scan(target, port_range, arguments="-sV")  

        if target in scanner.all_hosts():
            for proto in scanner[target].all_protocols():
                output_box.insert(tk.END, f"\n🔹 Protocol: {proto.upper()}\n")
                for port in sorted(scanner[target][proto].keys()):
                    service = scanner[target][proto][port]
                    output_box.insert(tk.END, f"  🔘 Port {port}: {service['state'].upper()} - {service['name']} ({service['product']} {service['version']})\n")
        else:
            output_box.insert(tk.END, "❌ Target not responding.\n")

    except Exception as e:
        output_box.insert(tk.END, f"⚠️ Error: {e}\n")

    output_box.insert(tk.END, "\n✅ Service scan complete.\n")

# Function for OS Detection
def os_detection(target, port_range=None):
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"\nPerforming OS detection on {target}...\n")

    try:
        scanner.scan(target, arguments="-O")  

        if target in scanner.all_hosts():
            os_guess = scanner[target]['osmatch'][0]['name'] if 'osmatch' in scanner[target] and scanner[target]['osmatch'] else "Unknown OS"
            output_box.insert(tk.END, f"✅ Target OS: {os_guess}\n")
        else:
            output_box.insert(tk.END, "❌ Target not responding or OS detection failed.\n")

    except Exception as e:
        output_box.insert(tk.END, f"⚠️ Error: {e}\n")

    output_box.insert(tk.END, "\n✅ OS Detection complete.\n")

# Function for Vulnerability Scan
def vulnerability_scan(target, port_range=None):
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, f"\n🚀 Running vulnerability scan on {target}...\n")

    try:
        scanner.scan(target, arguments="--script vuln")

        for host in scanner.all_hosts():
            output_box.insert(tk.END, f"\n✅ Target: {host}\n")
            for port in scanner[host]['tcp']:
                output_box.insert(tk.END, f"  🔘 Port {port}: {scanner[host]['tcp'][port]['state']}\n")
                if 'script' in scanner[host]['tcp'][port]:
                    output_box.insert(tk.END, f"   ⚠️ Possible Vulnerabilities: {scanner[host]['tcp'][port]['script']}\n")
    
    except Exception as e:
        output_box.insert(tk.END, f"⚠️ Error: {e}\n")

    output_box.insert(tk.END, "\n✅ Vulnerability scan complete.\n")

# GUI Setup
root = tk.Tk()
root.title("Nmap GUI Scanner")
root.geometry("750x550")

# Labels
tk.Label(root, text="Target IP / Domain:").grid(row=0, column=0, padx=10, pady=5)
tk.Label(root, text="Port Range (Optional, e.g., 1-1024):").grid(row=1, column=0, padx=10, pady=5)

# Entry fields
target_entry = tk.Entry(root, width=40)
target_entry.grid(row=0, column=1, padx=10, pady=5)
port_entry = tk.Entry(root, width=40)
port_entry.grid(row=1, column=1, padx=10, pady=5)

# Buttons
tk.Button(root, text="Port Scan", command=lambda: run_scan(port_scan, target_entry.get(), port_entry.get()), bg="lightblue").grid(row=2, column=0, padx=10, pady=5)
tk.Button(root, text="Service Detection", command=lambda: run_scan(service_scan, target_entry.get(), port_entry.get()), bg="lightgreen").grid(row=2, column=1, padx=10, pady=5)
tk.Button(root, text="OS Detection", command=lambda: run_scan(os_detection, target_entry.get()), bg="lightyellow").grid(row=3, column=0, padx=10, pady=5)
tk.Button(root, text="Vulnerability Scan", command=lambda: run_scan(vulnerability_scan, target_entry.get()), bg="salmon").grid(row=3, column=1, padx=10, pady=5)

# Output Box
output_box = scrolledtext.ScrolledText(root, width=90, height=20)
output_box.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
