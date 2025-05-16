import socket
import requests
import threading
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk, messagebox

# -----------------------------
# Scan the Network
# -----------------------------
def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)
        vendor = get_vendor(mac)
        devices.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})

    return devices

# -----------------------------
# Get Hostname from IP
# -----------------------------
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

# -----------------------------
# Get Vendor from MAC address
# -----------------------------
def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"

# -----------------------------
# Run scan and update GUI
# -----------------------------
def run_scan():
    ip_range = ip_entry.get()
    if not ip_range:
        messagebox.showerror("Error", "Please enter a valid IP range.")
        return

    result_text.delete(*result_text.get_children())

    def scan_thread():
        try:
            devices = scan_network(ip_range)
            for device in devices:
                result_text.insert("", "end", values=(
                    device['ip'], device['mac'], device['hostname'], device['vendor']))
        except Exception as e:
            messagebox.showerror("Error", f"Scan failed:\n{e}")

    threading.Thread(target=scan_thread, daemon=True).start()

# -----------------------------
# GUI Setup
# -----------------------------
root = tk.Tk()
root.title("Network Device Scanner")
root.geometry("750x400")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#2e2e2e", fieldbackground="#2e2e2e", foreground="white")
style.configure("TLabel", background="#1e1e1e", foreground="white", font=('Arial', 11))
style.configure("TButton", background="#333", foreground="white")

# Entry and Button
frame = ttk.Frame(root)
frame.pack(pady=10)
ttk.Label(frame, text="Enter IP Range (e.g., 192.168.1.1/24):").pack(side=tk.LEFT, padx=5)
ip_entry = ttk.Entry(frame, width=25)
ip_entry.pack(side=tk.LEFT, padx=5)
scan_btn = ttk.Button(frame, text="Scan Network", command=run_scan)
scan_btn.pack(side=tk.LEFT, padx=5)

# Table
columns = ("IP Address", "MAC Address", "Hostname", "Vendor")
result_text = ttk.Treeview(root, columns=columns, show="headings", height=15)
for col in columns:
    result_text.heading(col, text=col)
    result_text.column(col, width=150)
result_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

# Start GUI
root.mainloop()
