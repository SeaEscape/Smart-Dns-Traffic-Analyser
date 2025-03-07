# Smart-Dns-Traffic-Analyser

A real-time DNS traffic monitoring tool that detects spoofing, suspicious, and normal traffic using a Command-Line Interface (CLI) and GUI (Tkinter).

## Features
- Real-time DNS monitoring
- Threat detection (spoofing, tunneling, suspicious queries)
- CLI & GUI modes (Tkinter-based UI)
- Customizable thresholds (Entropy, Length, TTL, Frequency)
- Logging of flagged DNS queries

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-repo/smart-dns-analyzer.git
cd smart-dns-analyzer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the analyzer

#### Run the CLI version
```bash
python smart_dns_analyser.py
```

#### Run the GUI version
```bash
python tkinter_gui.py
```

## How It Works

1. Captures live DNS traffic using Scapy.
2. Analyzes queries based on:
   - Entropy
   - Length
   - TTL
   - Frequency
   - Subdomains
3. Predicts if the traffic is Normal, Suspicious, or Spoofing.
4. Logs flagged DNS queries for further analysis.

## Customization

Modify detection thresholds in tkinter_gui.py or smart_dns_analyser.py to fit your needs:
```python
THRESHOLD_ENTROPY = 3.8
THRESHOLD_LENGTH = 35
THRESHOLD_TTL = 10
THRESHOLD_FREQ = 5
```

## Technologies Used

- Python (Core Programming)
- Scapy (Packet Sniffing)
- Tkinter (GUI Development)
- Pandas (Data Processing)
- Machine Learning (Random Forest) (Anomaly Detection)

## Future Enhancements

- Integration with Threat Intelligence (VirusTotal, OpenDNS)
- Advanced detection for Fast-Flux Botnets & DNS Amplification
- SIEM Compatibility (Splunk, ELK, Open Threat Exchange)

## Contributors
- Pallavi Kadam – Implemented DNS packet sniffing using Scapy
- Manish Pandey – GUI development using Tkinter
- Harshil Shiroya – Machine learning model integration for anomaly detection
- Vaishnavi Chavan – Logging and reporting system
- Organization: Digisuraksha Parhari Foundation

## License
MIT License – Open for contributions and improvements.

