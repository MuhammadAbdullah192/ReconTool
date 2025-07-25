import argparse
from logger import logger
import dns_enum
import whois
import subdomain_enum
import portscan
import banner_grabber
import tech_detector
import sys

def interactive_menu():
    while True:
        print("\nMain Menu:")
        print("******************** Passive Recon ********************")
        print("1. WHOIS Lookup")
        print("2. DNS Enumeration")
        print("3. Subdomain Enumeration")
        print("\n******************** Active Recon *********************")
        print("4. Port Scanning")
        print("5. Banner Grabbing")
        print("6. Technology Detection")
        print("\n********************* Reporting ***********************")
        print("7. View Log File")
        print("8. Exit\n")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            domain = input("Enter domain for WHOIS: ").strip()
            if whois.is_valid_domain(domain):
                whois.whois_lookup(domain, "recon_report.txt")

        elif choice == '2':
            domain = input("Enter domain for DNS_Enum: ").strip()
            if dns_enum.is_valid_domain(domain):
                dns_enum.dns_lookup(domain)

        elif choice == '3':
            domain = input("Enter domain for subdomain: ").strip()
            subdomain_enum.subdomain_lookup(domain)

        elif choice == '4':
            target = input("Enter IP or domain: ").strip()
            if portscan.is_valid_target(target):
                portscan.run_nmap_scan(target)

        elif choice == '5':
            ip = input("Enter IP for banner grabbing: ").strip()
            port = int(input("Enter port: ").strip())
            banner = banner_grabber.grab_banner(ip, port)
            print(f"Banner:\n{banner.decode(errors='ignore')}")

        elif choice == '6':
            domain = input("Enter domain for tech detection: ").strip()
            tech_detector.tech_detect_whatweb(domain)

        elif choice == '7':
            try:
                with open("recon.log", "r") as log_file:
                    print(log_file.read())
            except FileNotFoundError:
                print("Log file not found.")
        
        elif choice == '8':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter again.")

def cli_handler():
    parser = argparse.ArgumentParser(description=" Recon Tool")
    parser.add_argument("--dns", help="Perform DNS enumeration on a domain")
    parser.add_argument("--whois", help="Perform WHOIS lookup on a domain")
    parser.add_argument("--subs", help="Perform subdomain enumeration")
    parser.add_argument("--nmap", help="Run Nmap port scan on target")
    parser.add_argument("--banner", nargs=2, metavar=("IP", "PORT"), help="Grab banner from IP and port")
    parser.add_argument("--tech", help="Detect technology stack of domain")
    parser.add_argument("--log", action="store_true", help="View log file")

    args = parser.parse_args()

    if args.dns:
        if dns_enum.is_valid_domain(args.dns):
            dns_enum.dns_lookup(args.dns)
    elif args.whois:
        if whois.is_valid_domain(args.whois):
            whois.whois_lookup(args.whois, "recon_report.txt")
    elif args.subs:
        subdomain_enum.subdomain_lookup(args.subs)
    elif args.nmap:
        if portscan.is_valid_target(args.nmap):
            portscan.run_nmap_scan(args.nmap)
    elif args.banner:
        ip, port = args.banner
        banner = banner_grabber.grab_banner(ip, int(port))
        print(f"Banner:\n{banner.decode(errors='ignore')}")
    elif args.tech:
        tech_detector.tech_detect_whatweb(args.tech)
    elif args.log:
        try:
            with open("recon.log", "r") as log_file:
                print(log_file.read())
        except FileNotFoundError:
            print("Log file not found.")
    else:
        interactive_menu()

if __name__ == "__main__":
    try:
        cli_handler()
    except KeyboardInterrupt:
        print("\n Keyboard interrupt")
