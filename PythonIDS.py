from scapy.all import sniff, IP, TCP,conf
import smtplib
from datetime import datetime
conf.sniff_promisc=True
conf.bufsize=2**20
your_email=""
other_email=""
your_password=""
# Function to detect malicious traffic (e.g., SYN flood)
def detect_malicious_traffic(packet):
    # Example suspicious IPs
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            if packet[TCP].flags == 'S':  # SYN flag
                log_alert(f"SYN packet detected: {src_ip} -> {dst_ip}")
                return True
    return False

# Function to log alerts
def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    print(log_message)
    with open("nids_alerts.log", "a") as log_file:
        log_file.write(log_message + "\n")
        send_alert(log_message)

# Function to send email alerts
def send_alert(message):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(your_email, your_password)
        server.sendmail(your_email, other_email, message)  
        server.quit()
        print("Alert sent!")
    except Exception as e:
        print(f"Failed to send alert: {e}")

# Callback function for sniffed packets
def packet_callback(packet):
    if detect_malicious_traffic(packet):
        print("Potential threat detected!")

# Main function to start the N-IDS
def start_nids():
    print("Listening for packets")
    sniff(prn=packet_callback, store=0,iface="Ethernet",filter="tcp[tcpflags] & tcp-syn != 0")  # Start sniffing

if __name__ == "__main__":
    start_nids()