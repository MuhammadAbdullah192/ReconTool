# nmap_scan.py
import os
import re
from logger import logger
from datetime import datetime

def is_valid_ip(ip):
    return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip) is not None

def is_valid_domain(domain):
    return re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", domain) is not None

def run_nmap_scan(target, report_file="recon_report.txt"):
    if not (is_valid_ip(target) or is_valid_domain(target)):
        print("[!] Invalid IP or domain format!")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Running Nmap scan on {target}")

    command = f"nmap -sV -T5 {target}"
    print(f"[+] Running: {command}")
    
    output = os.popen(command).read()

    print(output)

    # Save output to report file
    with open(report_file, "a") as f:
        f.write(f"\n===== Nmap Scan for {target} =====\n")
        f.write(f"Time: {timestamp}\n")
        f.write(output)
        f.write("\n==================================\n")

    print(f"[+] Nmap scan saved to {report_file}")
