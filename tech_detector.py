import os
from logger import logger
from datetime import datetime

def tech_detect_whatweb(domain):
    url = input("Enter URL (e.g., https://example.com): ").strip()

    if not url.startswith("http"):
        url = "http://" + url

    try:
        print(f"\n[+] Running WhatWeb on {url}...\n")
        result = os.popen(f"whatweb {url} --no-errors").read()
        print(result)

        logger.info(f"WhatWeb scan completed for {url}")

        with open("recon_report.txt", "a") as f:
            f.write(f"\n[{datetime.now()}] WhatWeb Report for {url}:\n")
            f.write(result)
            f.write("="*40 + "\n")

    except Exception as e:
        print(f"[!] Error running WhatWeb: {e}")
        logger.error(f"WhatWeb failed on {url}: {e}")
