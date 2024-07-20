import os
import logging
from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
from flask import Flask, request, jsonify, render_template
from datetime import datetime
from collections import defaultdict
from time import time
import json

logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')


def log_event(event_type, message):
    if event_type == 'warning':
        logging.info("Potential danger")
    elif event_type == 'error':
        logging.info("Error")

class Firewall:
    def __init__(self):
        self.connections = {} 
        self.alerts = []
        self.connections = defaultdict(lambda: {'count': 0, 'timestamp' : time()})
        self.rules = self.load_rules()
        self.rate_limit = 100
        self.time_window = 60
        self.ip_counts = defaultdict(lambda: {'count': 0, 'timestamp': time()})
    def rate_limit_check(self, ip):
        current_time = time()
        if current_time - self.ip_counts[ip]['timestamp'] > self.time_window:
            self.ip_counts[ip] = {'count': 1, 'timestamp': current_time}
        else:
            self.ip_counts[ip]['count'] += 1
        return self.ip_counts[ip]['count'] <= self.rate_limit
    
    def packet_handler(self, packet):
        scapy_packet = IP(packet.get_payload())
        ip_src = scapy_packet[IP].src
        if not self.rate_limit_check(ip_src):
            logging.warning(f"Rate limit exceeded for IP {ip_src}")
            packet.drop()
        else:
            if self.check_rules(packet):
                self.detect_intrusion(packet)
                logging.info(f"Dropped: {packet.get_payload()}")
                packet.drop()
            else:
                logging.info(f"Allowed: {packet.get_payload()}")
                packet.accept()
    def load_rules(self):
        try:
            with open('rules.json', 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return []
    
    def save_rules(self):
        with open('rules.json', 'w') as file:
            json.dump(self.rules, file, indent=4)
    
    
    def add_rule(self, src=None, dst=None, sport=None, dport=None, protocol=None):
        rule = {'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'protocol': protocol}
        self.rules.append(rule)
        self.save_rules()
        print(f"Rule added: {rule}")
    
    def remove_rule(self, index):
        if 0 <= index < len(self.rules):
            rule = self.rules.pop(index)
            logging.info(f"Rule removed:{rule}")
            self.save_rules()
        else:
            logging.warning("Invalid rule index")
    
    def list_rules(self):
        return self.rules
    
    def check_rules(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(TCP) or scapy_packet.haslayer(UDP):
            ip_src = scapy_packet[IP].src
            ip_dst = scapy_packet[IP].dst
            sport = scapy_packet[TCP].sport if scapy_packet.haslayer(TCP) else scapy_packet[UDP].sport
            dport = scapy_packet[TCP].dport if scapy_packet.haslayer(TCP) else scapy_packet[UDP].dport
            protocol = 'TCP' if scapy_packet.haslayer(TCP) else 'UDP'

            for rule in self.rules:
                if ((rule['src'] is None or rule['src'] == ip_src) and
                    (rule['dst'] is None or rule['dst'] == ip_dst) and
                    (rule['sport'] is None or rule['sport'] == sport) and
                    (rule['dport'] is None or rule['dport'] == dport) and
                    (rule['protocol'] is None or rule['protocol'] == protocol)):
                    return True
        return False
    
    def packet_handler(self, packet):
        if self.check_rules(packet):
            self.detect_intrusion(packet)
            logging.info(f"Dropped: {packet.get_payload()}")
            packet.drop()
        else:
            logging.info(f"Allowed: {packet.get_payload()}")
            packet.accept()
    
    def detect_intrustion(self, packet):
        scapy_packet = IP(packet.get_payload())
        ip_src = scapy_packet[IP].src
        if scapy_packet.haslayer(TCP) and scapy_packet[TCP].flags == 'S':
            self.alerts.append(f"Possible SYN Flood from {scapy_packet[IP].src}")
            logging.warning(f"Possible SYN Flood from {scapy_packet[IP].src}")
        if self.check_port_scanning(ip_src):
            self.alerts.append(f"Possible port scan from {ip_src}")
            logging.warning(f"Possible port scan from {ip_src}")
    
    def chec_port_scanning(self, ip):
        current_time = time()
        if current_time - self.connections[ip]['timestamp'] > 60:
            self.connections[ip] = {'count': 1, 'timestamp': current_time}
        else:
            self.connections[ip]['count'] += 1
        return self.connections[ip]['count'] > 100
    def get_alerts(self):
        return self.alerts
#Flask Web Interface

app = Flask(__name__)
firewall = Firewall()

@app.route('/')
def index():
    return render_template('index.html', rules=firewall.list_rules(), alerts=firewall.get_alerts())

@app.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.json
    firewall.add_rule(data['src'], data['dst'], data['sport'], data['dport'], data['protocol'])
    return jsonify({"status": "Rule added"}), 200

@app.route('/remove_rule/<int:index>', methods=['DELETE'])
def remove_rule(index):
    firewall.remove_rule(index)
    return jsonify({"status": "Rule removed"}), 200

@app.route('/list_rules', methods=['GET'])
def list_rules():
    return jsonify(firewall.list_rules()), 200

@app.route('/alerts', methods=['GET'])
def alerts():
    return jsonify(firewall.get_alerts()), 200

def main():
    parser = argparse.ArgumentParser(description="CLI Firewall with Web Interface")
    parser.add_argument('--add-rule', nargs=5, metavar=('SRC', 'DST', 'SPORT', 'DPORT', 'PROTOCOL'),
                        help="Add a rule: src, dst, sport, dport, protocol")
    parser.add_argument('--remove-rule', type=int, metavar='INDEX', help="Remove a rule by index")
    parser.add_argument('--list-rules', action='store_true', help="List all rules")
    parser.add_argument('--start', action='store_true', help="Start the firewall")
    parser.add_argument('--web', action='store_true', help="Start the web interface")
    args = parser.parse_args()

    if args.add_rule:
         src, dst, sport, dport, protocol = args.add_rule
         sport = int(sport) if sport.isdigit() else None
         dport = int(dport) if dport.isdigit() else None
         firewall.add_rule(src, dst, sport, dport, protocol)
    
    if args.remove_rule is not None:
        firewall.remove_rule(args.remove_rule)

    if args.list_rules:
        rules = firewall.list_rules()
        if not rules:
            print("No rules defined.")
        for rule in rules:
            print(rule)


    if args.start:
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, firewall.packet_handler)
        try:
            print("Starting firewall")
            nfqueue.run()
        except KeyboardInterrupt:
                pass
        finally:
            os.system("iptables -D FORWARD -j NFQUEUE --queue-num 0")
            print("Firewall stopped.")
    if args.web:
        print("http://localhost:5000")
        app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
     main()
