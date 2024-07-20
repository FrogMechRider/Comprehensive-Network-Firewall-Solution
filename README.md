# Firewall Solution

The Advanced Python Firewall is a comprehensive network security solution designed to enhance network protection and traffic management. Developed using Python, 
this project integrates packet capturing and filtering, rule management, intrusion detection, and logging functionalities. 
The firewall provides both a command-line interface (CLI) and a web-based interface for ease of use and flexibility. For best performance use on a Unix system

# Features
Packet Capturing and Filtering: Capture and filter network packets based on predefined rules using Scapy and NetfilterQueue.

### Rule Management: 
Add, remove, and list firewall rules through both CLI and web interfaces.

### Intrusion Detection: 
Detect potential intrusions such as SYN floods and port scans, and log alerts for further analysis.

### Rate Limiting: 
Implement rate limiting to prevent abuse from excessive traffic from a single IP address.

### Detailed Logging: 
Maintain detailed logs of all actions, including rule additions, packet drops, and detected intrusions.

### Web Interface: 
Provides a Flask-based web interface for easier rule management and monitoring of firewall activity.

### Command-Line Interface: 
Offers a robust CLI for advanced users to interact with the firewall directly from the terminal.
# Installation

### Install iptables
```
sudo apt-get install iptables
```
### Install Python pip (If not already installed)
```
sudo apt-get install python3-pip
```
### Install required Python modules
```
sudo pip install scapy
sudo pip install NetfilterQueue
sudo pip install flask
```


# Usage

#### python3 Firewall.py (option)

-h --help

--start

--add-rule (src IP) (dst IP) (sport) (dport) (protocol)

--remove-rule (index)

--list-rules

--web

# Logging

Logs are maintained in firewall.log and include detailed information about:

Rule additions and removals

Packet drops

Detected intrusions

Rate limiting events
