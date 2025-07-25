import requests
import logging
from logger import logger

def subdomain(domain):
    logger = logging.getLogger("ReconTool")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0'}  
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        subdomains = set()

        for entry in data:
            for sub in entry['name_value'].split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        print("\nSubdomains Found:")

        report_lines = [f"\nSubdomains for {domain}:"]
        for sub in sorted(subdomains):
            print(sub)
            report_lines.append(sub)

        with open("recon_report.txt", "a") as f:
            f.write("\n".join(report_lines) + "\n")

    except Exception as e:
        logger.error(f"Error during subdomain enumeration: {e}")
        print("[!] Error fetching subdomains.")
