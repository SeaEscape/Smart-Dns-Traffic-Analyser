from scapy.all import sniff, DNS, DNSRR
import math
from collections import Counter, defaultdict
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import logging
from colorama import init, Fore, Style
import winsound
import argparse
import time

# Initialize colorama
init()

class SmartDNSAnalyzer:
    def __init__(self, log_file="dns_threats.log", entropy_threshold=3.8, length_threshold=35, ttl_threshold=10, freq_threshold=5):
        logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s")
        self.logger = logging.getLogger()
        self.model = self.train_model()
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.ttl_threshold = ttl_threshold
        self.freq_threshold = freq_threshold
        self.query_counts = defaultdict(list)  # Track query frequency
        self.allowlist = self.load_list("allowlist.txt")
        self.blocklist = self.load_list("blocklist.txt")

    def load_list(self, filename):
        try:
            with open(filename, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def calculate_entropy(self, query):
        if not query:
            return 0
        length = len(query)
        counts = Counter(query)
        return -sum((count/length) * math.log2(count/length) for count in counts.values())

    def extract_features(self, packet):
        if packet.haslayer(DNS):
            dns = packet[DNS]
            query = dns.qd.qname.decode('utf-8') if dns.qd and dns.qr == 0 else ""
            features = {
                "query": query,
                "length": len(query),
                "entropy": self.calculate_entropy(query),
                "subdomains": query.count(".") - 1 if query else 0,
                "ttl": dns.an.ttl if dns.an and dns.qr == 1 else None,
                "timestamp": time.time()
            }
            return features
        return None

    def train_model(self):
        data = [
            [14, 2.5, 2, 0],  # Normal
            [20, 2.8, 3, 0],  # Normal
            [35, 3.8, 4, 1],  # Tunneling
            [50, 4.0, 5, 1]   # Tunneling
        ]
        df = pd.DataFrame(data, columns=["length", "entropy", "subdomains", "label"])
        X = df.drop("label", axis=1)
        y = df["label"]
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        return model

    def predict(self, features):
        X = pd.DataFrame([[features["length"], features["entropy"], features["subdomains"]]], 
                       columns=["length", "entropy", "subdomains"])
        pred = self.model.predict(X)[0]
        if features["entropy"] > self.entropy_threshold or features["length"] > self.length_threshold:
            return "Tunneling"
        return "Tunneling" if pred == 1 else "Normal"

    def detect_spoofing(self, features):
        return features["ttl"] is not None and features["ttl"] < self.ttl_threshold

    def get_frequency(self, query):
        current_time = time.time()
        self.query_counts[query] = [t for t in self.query_counts[query] if current_time - t < 10]  # 10-sec window
        self.query_counts[query].append(current_time)
        return len(self.query_counts[query])

    def dns_monitor(self, packet):
        features = self.extract_features(packet)
        if not features:
            return

        if features["query"]:  # Query packet
            query = features["query"]
            ml_result = self.predict(features)
            freq = self.get_frequency(query)
            spoofing = False
        else:  # Response packet
            query = "RESPONSE"
            ml_result = None
            freq = 0
            spoofing = self.detect_spoofing(features)

        # Apply allowlist/blocklist
        if query in self.allowlist:
            status = "Normal (Allowlisted)"
            color = Fore.WHITE
        elif query in self.blocklist:
            status = "Blocked (Blocklisted)"
            color = Fore.RED
            winsound.Beep(1500, 300)
        elif spoofing:
            status = "Spoofing Detected"
            color = Fore.RED
            winsound.Beep(1500, 300)
        elif ml_result == "Tunneling" or freq > self.freq_threshold:
            status = "Suspicious (Tunneling/Frequent)"
            color = Fore.YELLOW
            winsound.Beep(1000, 200)
        else:
            status = "Normal"
            color = Fore.WHITE

        # Block output
        block = [
            f"DNS Query: {features['query']}",
            f"Findings:",
            f"  Length: {features['length']}",
            f"  Entropy: {features['entropy']:.2f}",
            f"  Subdomains: {features['subdomains']}",
            f"  TTL: {features['ttl']}",
            f"  Frequency (10s): {freq}",
            f"  Prediction: {status}"
        ]
        print(color + "\n".join(block) + Style.RESET_ALL)
        print("-" * 50)
        self.logger.info("\n".join(block))

def main():
    parser = argparse.ArgumentParser(description="Smart DNS Traffic Analyzer")
    parser.add_argument("--entropy", type=float, default=3.8, help="Entropy threshold")
    parser.add_argument("--length", type=int, default=35, help="Length threshold")
    parser.add_argument("--ttl", type=int, default=10, help="TTL threshold")
    parser.add_argument("--freq", type=int, default=5, help="Frequency threshold")
    args = parser.parse_args()

    analyzer = SmartDNSAnalyzer(entropy_threshold=args.entropy, 
                                length_threshold=args.length, 
                                ttl_threshold=args.ttl, 
                                freq_threshold=args.freq)
    print(Fore.CYAN + "Smart DNS Traffic Analyzer - Monitoring live traffic (Press Ctrl+C to stop)" + Style.RESET_ALL)
    print(Fore.CYAN + f"Thresholds: Entropy>{args.entropy}, Length>{args.length}, TTL<{args.ttl}, Freq>{args.freq}" + Style.RESET_ALL)
    print(f"{Fore.WHITE}Normal{Style.RESET_ALL} | {Fore.YELLOW}Suspicious{Style.RESET_ALL} | {Fore.RED}Critical{Style.RESET_ALL}")
    try:
        sniff(filter="udp port 53", prn=analyzer.dns_monitor, store=0)  # Add iface="Wi-Fi" if needed
    except PermissionError:
        print(Fore.RED + "Error: Run this script as Administrator!" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()