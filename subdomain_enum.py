import requests
from logger import logger

def subdomain(domain, report_file):
    logger = logging.getLogger("ReconTool")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        subdomains = set()
        for entry in data:
            for sub in entry['name_value'].split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())

        logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        print("\nSubdomains Found:")
        with open(report_file, "a") as f:
            f.write("Subdomains:\n")
            for sub in sorted(subdomains):
                print(sub)
                f.write(sub + "\n")
    except Exception as e:
        logger.error(f"Error during subdomain enumeration: {e}")
        print("[!] Error fetching subdomains.")
