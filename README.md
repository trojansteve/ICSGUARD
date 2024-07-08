# ICSGUARD

This project is an Industrial Control System (ICS) Network Monitor tool built using Python and the Tkinter library. It allows users to scan a network for active hosts, perform port scanning, and detect specific ICS protocols. The tool also includes a graphical user interface (GUI) for ease of use.

## Features

- *Host Discovery*: Discover active hosts in a given network using ARP requests.
- *Port Scanning*: Scan specific ports on discovered hosts using TCP SYN scan.
- *Modbus Protocol Scan*: Check for Modbus protocol on hosts by attempting TCP connections on port 502.
- *EtherNet/IP and CIP Protocol Scan*: Scan for EtherNet/IP and CIP protocol on hosts.
- *Passive Network Scanning*: Detect ICS protocols by sniffing network traffic.
- *Critical Network Safety Check*: Ensure critical networks are not scanned to prevent disruptions.
- *Graphical User Interface*: User-friendly interface to input scan parameters and display results.

## Installation

1. *Clone the repository:*
   git clone https://github.com/yourusername/ics_network_monitor.git
   cd ics_network_monitor
   

2. *Install the required dependencies:*
   pip install -r requirements.txt
   

3. *Run the application:*
   python3 ics_network_monitor.py
   

## Usage

1. *Network to Scan*: Enter the network range to scan (e.g., 192.168.1.0/24).
2. *Ports to Scan*: Enter the ports to scan, separated by commas (e.g., 22,80,502).
3. *Network Interface for Passive Scanning*: Enter the network interface to listen on for passive scanning (e.g., eth0).
4. *Start Scan*: Click the "Start Scan" button to begin scanning.

## Code Overview

### Main Application Class

- *ICSNetworkMonitorApp*: Inherits from tk.Tk and sets up the GUI components including labels, entries, buttons, text area for logs, and a matplotlib plot for visualizing results.

### Functions

- *log_event(event)*: Logs events to a file and prints them to the console.
- *host_discovery(network)*: Performs ARP requests to discover active hosts in the specified network.
- *port_scan(host, ports)*: Scans specific ports on a given host using TCP SYN scan.
- *modbus_scan(host)*: Scans for the Modbus protocol on a given host.
- *ethernet_ip_scan(host)*: Scans for EtherNet/IP and CIP protocol on a given host.
- *passive_scan(interface)*: Performs passive network scanning by sniffing traffic on the specified interface.
- *safety_check(network)*: Checks if the specified network is critical and should not be scanned.

### Critical Networks

- *CRITICAL_NETWORKS*: A list of networks that should not be scanned to prevent disruptions.

## Dependencies

- tkinter: For building the GUI.
- scapy: For network scanning and packet manipulation.
- modbus-tk: For Modbus protocol operations.
- matplotlib: For plotting scan results.

## Logging

Logs are saved in the ics_network_monitor.log file with timestamps for each event.

## Safety Notice

This tool performs network scanning which can be intrusive and potentially disruptive. Ensure you have permission to scan the network and avoid scanning critical infrastructure without proper authorization.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgements

- Built using the Tkinter library for the GUI.
- Uses Scapy for network packet manipulation and scanning.
- Utilizes Modbus-TK for Modbus protocol operations.
- Employs Matplotlib for plotting scan results.

For further information or contributions, please refer to the [repository](https://github.com/trojansteve/ICSGUARD).
