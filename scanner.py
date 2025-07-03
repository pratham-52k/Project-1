import os
import socket
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import csv
import threading

# Default subnet
default_subnet = "192.168.1."

# Common ports and simple vulnerability mapping
common_ports = [21, 22, 23, 80, 443]
vulnerable_ports = {
    21: "FTP - May allow anonymous login",
    23: "Telnet - Insecure protocol",
    80: "HTTP - No encryption"
}

# Global stop flag
stop_scan = False

def ping(ip):
    response = os.system(f"ping -n 1 -w 100 {ip} > nul")
    return response == 0

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

def threaded_scan(output_box, subnet_entry):
    global stop_scan
    stop_scan = False
    subnet = subnet_entry.get()
    if not subnet:
        messagebox.showerror("Error", "Please enter a subnet (e.g., 192.168.1.)")
        return

    live_hosts = []
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"[+] Scanning subnet: {subnet}0/24\n")
    output_box.insert(tk.END, "[+] Scanning for live hosts...\n")

    for i in range(1, 255):
        if stop_scan:
            output_box.insert(tk.END, "\n[!] Scan stopped by user.\n")
            return
        ip = subnet + str(i)
        output_box.insert(tk.END, f"Pinging {ip}...\n")
        output_box.see(tk.END)
        if ping(ip):
            output_box.insert(tk.END, f"[+] Host active: {ip}\n")
            live_hosts.append(ip)

    output_box.insert(tk.END, "\n[+] Scanning open ports and vulnerabilities...\n")

    report_data = []

    for ip in live_hosts:
        if stop_scan:
            output_box.insert(tk.END, "\n[!] Scan stopped by user.\n")
            return
        ports = scan_ports(ip, common_ports)
        output_box.insert(tk.END, f"\n{ip} has open ports: {ports}\n")
        row = [ip, ', '.join(map(str, ports))]
        for port in ports:
            if port in vulnerable_ports:
                vuln_info = vulnerable_ports[port]
                output_box.insert(tk.END, f"⚠️  Vulnerable: {vuln_info}\n")
                row.append(f"Port {port}: {vuln_info}")
        report_data.append(row)

    output_box.insert(tk.END, "\n[+] Scan complete.\n")
    save_report(report_data)
    messagebox.showinfo("Scan Complete", "Scan complete. Report has been saved.")

def save_report(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save Report")
    if file_path:
        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Open Ports", "Vulnerabilities"])
            for row in data:
                writer.writerow(row)

def stop_scan_thread():
    global stop_scan
    stop_scan = True

def main():
    root = tk.Tk()
    root.title("Network Vulnerability Scanner")
    root.geometry("750x600")

    tk.Label(root, text="Network Vulnerability Scanner", font=("Arial", 16)).pack(pady=10)

    frame = tk.Frame(root)
    frame.pack(pady=5)
    tk.Label(frame, text="Enter Subnet (e.g., 192.168.1.):", font=("Arial", 12)).pack(side=tk.LEFT)
    subnet_entry = tk.Entry(frame, font=("Arial", 12), width=15)
    subnet_entry.insert(0, default_subnet)
    subnet_entry.pack(side=tk.LEFT, padx=5)

    output_box = scrolledtext.ScrolledText(root, width=90, height=25, font=("Consolas", 10))
    output_box.pack(padx=10, pady=10)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    def start_thread():
        threading.Thread(target=threaded_scan, args=(output_box, subnet_entry), daemon=True).start()

    scan_button = tk.Button(button_frame, text="Start Scan", command=start_thread, bg="green", fg="white", font=("Arial", 12))
    scan_button.pack(side=tk.LEFT, padx=10)

    stop_button = tk.Button(button_frame, text="Stop Scan", command=stop_scan_thread, bg="red", fg="white", font=("Arial", 12))
    stop_button.pack(side=tk.LEFT, padx=10)

    root.mainloop()

if __name__ == "__main__":
    main()
