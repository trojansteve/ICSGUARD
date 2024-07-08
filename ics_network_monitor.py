// MIT License
//
// Copyright (c) 2024 Stephen  Haruna
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, sr1
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp
import logging
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# Define critical networks that should not be scanned
CRITICAL_NETWORKS = ['192.168.1.0/24']  # Example of critical networks

# Configure logging
logging.basicConfig(filename='ics_network_monitor.log', level=logging.INFO,
                    format='%(asctime)s %(message)s')

def log_event(event):
    """Log the event to a file."""
    logging.info(event)
    print(event)

def host_discovery(network):
    """
    Discover active hosts in a given network using ARP requests.
    
    :param network: The network range to scan (e.g., '192.168.1.0/24')
    :return: A list of active hosts with their IP and MAC addresses
    """
    log_event(f"Scanning network {network} for active hosts...")
    arp = ARP(pdst=network)  # Create an ARP request
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Create an Ethernet frame
    packet = ether/arp  # Combine the ARP request with the Ethernet frame

    # Send the packet and get the response
    result = srp(packet, timeout=2, verbose=False)[0]
    active_hosts = []
    for sent, received in result:
        active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
        log_event(f"Host found: IP={received.psrc}, MAC={received.hwsrc}")

    return active_hosts

def port_scan(host, ports):
    """
    Scan specific ports on a given host using TCP SYN scan.
    
    :param host: The IP address of the host to scan
    :param ports: A list of ports to scan
    :return: A list of open ports
    """
    log_event(f"Scanning host {host} for open ports...")
    open_ports = []
    for port in ports:
        pkt = IP(dst=host)/TCP(dport=port, flags="S")  # Create a TCP SYN packet
        resp = sr1(pkt, timeout=1, verbose=False)  # Send the packet and wait for response
        if resp is not None and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            open_ports.append(port)  # Port is open if SYN-ACK is received
            sr1(IP(dst=host)/TCP(dport=port, flags="R"), timeout=1, verbose=False)  # Send RST to close connection
            log_event(f"Open port {port} on host {host}")
    
    return open_ports

def modbus_scan(host):
    """
    Scan Modbus protocol on a given host by attempting a TCP connection on port 502.
    
    :param host: The IP address of the host to scan
    """
    try:
        master = modbus_tcp.TcpMaster(host)  # Create a Modbus TCP master
        master.open()  # Open the connection
        log_event(f"Modbus connection successful on {host}")
        # Example of reading holding registers
        response = master.execute(1, cst.READ_HOLDING_REGISTERS, 0, 10)
        log_event(f"Modbus registers on {host}: {response}")
    except Exception as e:
        log_event(f"Modbus scan failed on {host}: {e}")

def ethernet_ip_scan(host):
    """
    Scan for EtherNet/IP and CIP protocol on a given host.
    
    :param host: The IP address of the host to scan
    """
    try:
        # Send a specific EtherNet/IP packet and analyze response
        cip_packet = IP(dst=host)/UDP(dport=44818)/b'\x6f\x00\x00\x00'  # Example of a CIP request packet
        response = sr1(cip_packet, timeout=2, verbose=False)
        if response:
            log_event(f"EtherNet/IP and CIP detected on {host}")
        else:
            log_event(f"No response for EtherNet/IP and CIP on {host}")
    except Exception as e:
        log_event(f"EtherNet/IP and CIP scan failed on {host}: {e}")

def passive_scan(interface):
    """
    Perform passive network scanning to detect ICS protocols by sniffing traffic.
    
    :param interface: The network interface to listen on
    """
    def packet_callback(packet):
        # Check for Modbus traffic (default port 502)
        if packet.haslayer(TCP) and packet.dport == 502:
            log_event(f"Modbus traffic detected from {packet[IP].src} to {packet[IP].dst}")
        # Check for EtherNet/IP traffic (default port 44818)
        if packet.haslayer(UDP) and packet.dport == 44818:
            log_event(f"EtherNet/IP and CIP traffic detected from {packet[IP].src} to {packet[IP].dst}")

    log_event(f"Starting passive scan on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)  # Start sniffing on the specified interface

def safety_check(network):
    """
    Check if the network is critical and should not be scanned.
    
    :param network: The network range to check
    :return: True if the network is safe to scan, False otherwise
    """
    for critical_network in CRITICAL_NETWORKS:
        if network.startswith(critical_network[:-4]):  # Simple check for subnet match
            log_event(f"Network {network} is critical and cannot be scanned.")
            return False
    return True

class ICSNetworkMonitorApp(tk.Tk):
    def _init_(self):
        super()._init_()

        self.title("ICS Network Monitor")
        self.geometry("800x600")

        self.network_label = ttk.Label(self, text="Network to Scan:")
        self.network_label.pack(pady=5)
        self.network_entry = ttk.Entry(self)
        self.network_entry.pack(pady=5)

        self.ports_label = ttk.Label(self, text="Ports to Scan (comma-separated):")
        self.ports_label.pack(pady=5)
        self.ports_entry = ttk.Entry(self)
        self.ports_entry.pack(pady=5)

        self.interface_label = ttk.Label(self, text="Network Interface for Passive Scanning:")
        self.interface_label.pack(pady=5)
        self.interface_entry = ttk.Entry(self)
        self.interface_entry.pack(pady=5)

        self.scan_button = ttk.Button(self, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=20)

        self.log_text = tk.Text(self, height=20, width=80)
        self.log_text.pack(pady=5)

        self.figure, self.ax = plt.subplots(figsize=(5, 4))
        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
        self.canvas.get_tk_widget().pack(pady=5)

    def start_scan(self):
        network = self.network_entry.get()
        ports = list(map(int, self.ports_entry.get().split(',')))
        interface = self.interface_entry.get()

        if not safety_check(network):
            messagebox.showerror("Error", "Network is critical and cannot be scanned.")
            return

        active_hosts = host_discovery(network)
        self.log_text.insert(tk.END, "Active hosts found:\n")
        for host in active_hosts:
            self.log_text.insert(tk.END, f"IP: {host['ip']}, MAC: {host['mac']}\n")

        open_ports_data = []
        for host in active_hosts:
            open_ports = port_scan(host['ip'], ports)
            self.log_text.insert(tk.END, f"Open ports on {host['ip']}: {open_ports}\n")
            open_ports_data.append((host['ip'], open_ports))
            if 502 in open_ports:  # Modbus default port
                modbus_scan(host['ip'])
            if 44818 in open_ports:  # EtherNet/IP default port
                ethernet_ip_scan(host['ip'])

        if interface:
            passive_scan(interface)

        # Plot the open ports data
        self.ax.clear()
        for ip, ports in open_ports_data:
            self.ax.bar(ip, len(ports), label=f"{ip} - {ports}")
        self.ax.set_xlabel("Hosts")
        self.ax.set_ylabel("Number of Open Ports")
        self.ax.legend()
        self.canvas.draw()

if _name_ == "_main_":
    app = ICSNetworkMonitorApp()
    app.mainloop()
