import os
import re
from logger import logger
from datetime import datetime

# Domain validator
def is_valid_domain(domain):
    domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(domain_regex, domain)

# WHOIS function
def whois_lookup(domain, report_file):
    if not is_valid_domain(domain):
        print("[!] Invalid domain format.")
        logger.warning(f"Invalid WHOIS domain input: {domain}")
        return
    try:
        result = os.popen(f"whois {domain}").read()
        print(f"\n[+] WHOIS Information for {domain}:\n")
        print(result)
        logger.info(f"WHOIS lookup performed for {domain}")
        with open(report_file, "a") as f:
            f.write(f"\n[{datetime.now()}] WHOIS Information for {domain}:\n")
            f.write(result)
            f.write("\n" + "="*40 + "\n")
    except Exception as e:
        print("[!] WHOIS lookup failed.")
        logger.error(f"WHOIS lookup failed for {domain}: {str(e)}")
