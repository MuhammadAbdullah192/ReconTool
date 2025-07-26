import socket
import re
from logger import logger 

def is_valid_target(target):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(ip_regex, target) or re.match(domain_regex, target)

def grab_banner(ip_address, port):
    if not is_valid_target(ip_address):
        print("[!] Invalid IP or domain.")
        logger.warning(f"Invalid target entered for banner grab: {ip_address}")
        return ''

    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip_address, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()

        print(f"[+] Banner from {ip_address}:{port}:\n")
        logger.info(f"Banner grabbed from {ip_address}:{port}: {banner}")
        return banner

    except Exception as e:
        print(f"[!] Could not grab banner: {e}")
        logger.error(f"Error grabbing banner from {ip_address}:{port}: {e}")
        return 
