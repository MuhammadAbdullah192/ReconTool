import dns.resolver
import re
from logger import logger
from datetime import datetime

def is_valid_domain(domain):
    return re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", domain)

def dns_lookup(domain):
    domain = input("Enter domain for DNS enumeration: ").strip()
    if not is_valid_domain(domain):
        print("[!] Invalid domain format.")
        logger.warning(f"Invalid domain input: {domain}")
        return

    print(f"\n[+] DNS Records for {domain}:\n")
    report_lines = [f"\n===== DNS Records for {domain} =====", f"Time: {datetime.now()}"]

    for record_type in ["A", "MX", "TXT", "NS"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            print(f"  {record_type} Records:")
            report_lines.append(f"\n  {record_type} Records:")
            for r in answers:
                text = f"    - {r.to_text()}"
                print(text)
                report_lines.append(text)
        except Exception as e:
            error_msg = f"  {record_type} Record Error: {e}"
            print(error_msg)
            report_lines.append(error_msg)

    report_lines.append("==================================\n")
    logger.info(f"DNS Enumeration completed for {domain}")

    with open("recon_report.txt", "a") as f:
        f.write("\n".join(report_lines))
