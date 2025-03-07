import threading
from scapy.all import sniff, DNS
import math
from collections import Counter, defaultdict
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import logging
import tkinter as tk
from tkinter import scrolledtext, ttk
import time
import winsound
import datetime

class SmartDNSAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart DNS Traffic Analyzer")
        self.root.geometry("800x600")
        self.running = False
        self.stop_event = threading.Event()
        self.analyzer = SmartDNSAnalyzer()
        self.filter_status = {"normal": True, "suspicious": True, "spoofing": True}
        self.packet_log = []  # Store packets for report and display
        
        self.create_widgets()
        
    def create_widgets(self):
        # Threshold Frame
        threshold_frame = ttk.LabelFrame(self.root, text="Threshold Settings")
        threshold_frame.pack(padx=10, pady=5, fill="x")
        
        ttk.Label(threshold_frame, text="Entropy:").grid(row=0, column=0, padx=5, pady=5)
        self.entropy_var = tk.DoubleVar(value=3.8)
        ttk.Entry(threshold_frame, textvariable=self.entropy_var).grid(row=0, column=1, padx=5)
        
        ttk.Label(threshold_frame, text="Length:").grid(row=0, column=2, padx=5)
        self.length_var = tk.IntVar(value=35)
        ttk.Entry(threshold_frame, textvariable=self.length_var).grid(row=0, column=3, padx=5)
        
        ttk.Label(threshold_frame, text="TTL:").grid(row=1, column=0, padx=5, pady=5)
        self.ttl_var = tk.IntVar(value=10)
        ttk.Entry(threshold_frame, textvariable=self.ttl_var).grid(row=1, column=1, padx=5)
        
        ttk.Label(threshold_frame, text="Freq:").grid(row=1, column=2, padx=5)
        self.freq_var = tk.IntVar(value=5)
        ttk.Entry(threshold_frame, textvariable=self.freq_var).grid(row=1, column=3, padx=5)
        
        # Filter Frame
        filter_frame = ttk.LabelFrame(self.root, text="Filter Status")
        filter_frame.pack(padx=10, pady=5, fill="x")
        
        self.normal_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Normal", variable=self.normal_var, 
                       command=self.update_filter).grid(row=0, column=0, padx=5, pady=5)
        
        self.suspicious_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Suspicious", variable=self.suspicious_var, 
                       command=self.update_filter).grid(row=0, column=1, padx=5, pady=5)
        
        self.spoofing_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Spoofing", variable=self.spoofing_var, 
                       command=self.update_filter).grid(row=0, column=2, padx=5, pady=5)
        
        # Control Buttons
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=5)
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        self.report_btn = ttk.Button(control_frame, text="Generate Report", command=self.generate_report)
        self.report_btn.pack(side="left", padx=5)
        
        # Output Display
        self.output_text = scrolledtext.ScrolledText(self.root, height=25, width=90, wrap=tk.WORD)
        self.output_text.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Color tags
        self.output_text.tag_config("normal", foreground="white", background="black")
        self.output_text.tag_config("suspicious", foreground="yellow", background="black")
        self.output_text.tag_config("spoofing", foreground="red", background="black")
        self.output_text.tag_config("header", foreground="cyan", background="black")
        
        self.output_text.insert(tk.END, "Smart DNS Traffic Analyzer - Ready to monitor\n", "header")
        self.output_text.insert(tk.END, "Normal (White) | Suspicious (Yellow) | Spoofing (Red)\n", "header")

    def update_filter(self):
        """Update filter status and refresh display."""
        self.filter_status["normal"] = self.normal_var.get()
        self.filter_status["suspicious"] = self.suspicious_var.get()
        self.filter_status["spoofing"] = self.spoofing_var.get()
        self.refresh_display()

    def start_monitoring(self):
        if not self.running:
            self.running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.analyzer.entropy_threshold = self.entropy_var.get()
            self.analyzer.length_threshold = self.length_var.get()
            self.analyzer.ttl_threshold = self.ttl_var.get()
            self.analyzer.freq_threshold = self.freq_var.get()
            
            self.output_text.insert(tk.END, f"Started monitoring with thresholds: Entropy>{self.analyzer.entropy_threshold}, "
                                          f"Length>{self.analyzer.length_threshold}, TTL<{self.analyzer.ttl_threshold}, "
                                          f"Freq>{self.analyzer.freq_threshold}\n", "header")
            self.refresh_display()
            
            self.stop_event.clear()
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_monitoring(self):
        if self.running:
            self.running = False
            self.stop_event.set()
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.output_text.insert(tk.END, "Monitoring stopped\n", "header")
            self.refresh_display()

    def sniff_packets(self):
        try:
            def packet_handler(packet):
                if self.stop_event.is_set():
                    raise StopIteration
                self.process_packet(packet)

            sniff(filter="udp port 53", prn=packet_handler, store=0)
        except StopIteration:
            pass
        except PermissionError:
            self.output_text.insert(tk.END, "Error: Run this script as Administrator!\n", "spoofing")
            self.refresh_display()
        except Exception as e:
            self.output_text.insert(tk.END, f"An error occurred: {e}\n", "spoofing")
            self.refresh_display()

    def play_alert(self, tag):
        if tag == "suspicious":
            winsound.Beep(1000, 200)
        elif tag == "spoofing":
            winsound.Beep(1500, 300)

    def process_packet(self, packet):
        features = self.analyzer.extract_features(packet)
        if not features:
            return

        if features["query"]:
            query = features["query"]
            ml_result = self.analyzer.predict(features)
            freq = self.analyzer.get_frequency(query)
            spoofing = False
        else:
            query = "RESPONSE"
            ml_result = None
            freq = 0
            spoofing = self.analyzer.detect_spoofing(features)

        if query in self.analyzer.allowlist:
            status = "Normal (Allowlisted)"
            tag = "normal"
        elif query in self.analyzer.blocklist:
            status = "Blocked (Blocklisted)"
            tag = "spoofing"
        elif spoofing:
            status = "Spoofing Detected"
            tag = "spoofing"
        elif ml_result == "Tunneling" or freq > self.analyzer.freq_threshold:
            status = "Suspicious (Tunneling/Frequent)"
            tag = "suspicious"
        else:
            status = "Normal"
            tag = "normal"

        packet_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "query": features["query"],
            "length": features["length"],
            "entropy": features["entropy"],
            "subdomains": features["subdomains"],
            "ttl": features["ttl"],
            "freq": freq,
            "status": status,
            "tag": tag
        }
        self.packet_log.append(packet_data)

        if self.filter_status[tag]:
            self.display_packet(packet_data)
        if tag in ["suspicious", "spoofing"]:
            self.play_alert(tag)

    def display_packet(self, packet_data):
        """Display a single packet (used for real-time updates)."""
        block = [
            f"DNS Query: {packet_data['query']}",
            f"Findings:",
            f"  Length: {packet_data['length']}",
            f"  Entropy: {packet_data['entropy']:.2f}",
            f"  Subdomains: {packet_data['subdomains']}",
            f"  TTL: {packet_data['ttl']}",
            f"  Frequency (10s): {packet_data['freq']}",
            f"  Prediction: {packet_data['status']}",
            "-" * 50
        ]
        self.output_text.insert(tk.END, "\n".join(block) + "\n", packet_data["tag"])
        self.output_text.see(tk.END)

    def refresh_display(self):
        """Refresh the entire display based on current filter settings."""
        self.output_text.delete(1.0, tk.END)  # Clear current display
        self.output_text.insert(tk.END, "Smart DNS Traffic Analyzer - Ready to monitor\n", "header")
        self.output_text.insert(tk.END, "Normal (White) | Suspicious (Yellow) | Spoofing (Red)\n", "header")
        
        if self.running:
            self.output_text.insert(tk.END, f"Started monitoring with thresholds: Entropy>{self.analyzer.entropy_threshold}, "
                                          f"Length>{self.analyzer.length_threshold}, TTL<{self.analyzer.ttl_threshold}, "
                                          f"Freq>{self.analyzer.freq_threshold}\n", "header")
        elif not self.running and len(self.packet_log) > 0:
            self.output_text.insert(tk.END, "Monitoring stopped\n", "header")

        for packet_data in self.packet_log:
            if self.filter_status[packet_data["tag"]]:
                self.display_packet(packet_data)

    def generate_report(self):
        if not self.packet_log:
            self.output_text.insert(tk.END, "No data to generate report.\n", "header")
            self.refresh_display()
            return

        filename = f"dns_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write("Smart DNS Traffic Analyzer Report\n")
            f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Thresholds: Entropy>{self.analyzer.entropy_threshold}, Length>{self.analyzer.length_threshold}, "
                    f"TTL<{self.analyzer.ttl_threshold}, Freq>{self.analyzer.freq_threshold}\n")
            f.write("-" * 50 + "\n\n")
            
            status_counts = Counter(packet["status"] for packet in self.packet_log)
            f.write("Summary:\n")
            for status, count in status_counts.items():
                f.write(f"  {status}: {count}\n")
            f.write("\nDetailed Log:\n")
            
            for packet in self.packet_log:
                f.write(f"Time: {packet['timestamp']}\n")
                f.write(f"DNS Query: {packet['query']}\n")
                f.write(f"  Length: {packet['length']}\n")
                f.write(f"  Entropy: {packet['entropy']:.2f}\n")
                f.write(f"  Subdomains: {packet['subdomains']}\n")
                f.write(f"  TTL: {packet['ttl']}\n")
                f.write(f"  Frequency (10s): {packet['freq']}\n")
                f.write(f"  Status: {packet['status']}\n")
                f.write("-" * 50 + "\n")

        self.output_text.insert(tk.END, f"Report generated: {filename}\n", "header")
        self.refresh_display()

class SmartDNSAnalyzer:
    def __init__(self, log_file="dns_threats.log", entropy_threshold=3.8, length_threshold=35, ttl_threshold=10, freq_threshold=5):
        logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s")
        self.logger = logging.getLogger()
        self.model = self.train_model()
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.ttl_threshold = ttl_threshold
        self.freq_threshold = freq_threshold
        self.query_counts = defaultdict(list)
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
        self.query_counts[query] = [t for t in self.query_counts[query] if current_time - t < 10]
        self.query_counts[query].append(current_time)
        return len(self.query_counts[query])

def main():
    root = tk.Tk()
    app = SmartDNSAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()