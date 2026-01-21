# Keycloak Brute-Force PoC Tool

A penetration testing tool for demonstrating password brute-force vulnerabilities in Keycloak SSO implementations. This tool is designed to support security assessments by proving the need for multi-factor authentication (MFA) enforcement.

## Overview

This tool automates the Keycloak login flow by:

1. Generating PKCE (Proof Key for Code Exchange) parameters for OAuth 2.0
2. Fetching a fresh session code before each login attempt
3. Submitting credentials and analyzing the response
4. Supporting multi-threaded execution for faster testing

## Requirements

- Python 3.7+
- requests library

Install dependencies:

```
pip install requests
```

## Usage

```
usage: keycloak_bruteforce.py [-h] -u URL -U USERNAME -r REALM -c CLIENT_ID
                              [-w WORDLIST] [-p PASSWORD] [-t THREADS] [-d DELAY]
                              [-v] [--no-ssl-verify] [--redirect-uri REDIRECT_URI]

Keycloak Password Brute-Force PoC Tool (Authorized Testing Only)

required arguments:
  -u URL, --url URL           Base URL of Keycloak server
  -U USERNAME, --username USERNAME
                              Target username to brute-force
  -r REALM, --realm REALM     Keycloak realm name
  -c CLIENT_ID, --client-id CLIENT_ID
                              OAuth client ID

optional arguments:
  -w WORDLIST, --wordlist WORDLIST
                              Path to password wordlist file
  -p PASSWORD, --password PASSWORD
                              Single password to test
  -t THREADS, --threads THREADS
                              Number of threads (default: 1)
  -d DELAY, --delay DELAY     Delay between attempts in seconds (default: 0)
  -v, --verbose               Enable verbose output
  --no-ssl-verify             Disable SSL certificate verification
  --redirect-uri REDIRECT_URI
                              OAuth redirect URI
```

## Examples

Test a single password:

```
python keycloak_bruteforce.py -u https://example.com -U admin -r REALM -c CLIENT_ID -p "password123"
```

Brute-force with wordlist (single thread):

```
python keycloak_bruteforce.py -u https://example.com -U admin -r REALM -c CLIENT_ID -w passwords.txt
```

Brute-force with 10 threads:

```
python keycloak_bruteforce.py -u https://example.com -U admin -r REALM -c CLIENT_ID -w passwords.txt -t 10
```

Verbose output with delay:

```
python keycloak_bruteforce.py -u https://example.com -U admin -r REALM -c CLIENT_ID -w passwords.txt -v -d 0.5
```

## Output

The tool displays timestamped progress for each attempt:

```
[2026-01-21 10:41:51.325] [*] Starting brute-force attack against user 'admin'
[2026-01-21 10:41:51.325] [*] Loaded 24 passwords from wordlist
[2026-01-21 10:41:51.325] [*] Target: https://example.com
[2026-01-21 10:41:51.326] [*] Threads: 10
----------------------------------------------------------------------
[2026-01-21 10:41:51.329] [D] [1/24] password - Invalid credentials
[2026-01-21 10:41:51.330] [D] [2/24] 123456 - Invalid credentials
...
[2026-01-21 10:41:57.101] [+] PASSWORD FOUND: PASSWORD
```

Attack summary is printed upon completion:

```
======================================================================
ATTACK SUMMARY
======================================================================
Target URL:      https://example.com
Realm:           REALM
Client ID:       CLIENT_ID
Username:        admin
Threads:         10
Total attempts:  24
Duration:        5.79 seconds
Average rate:    4.14 attempts/second
Start time:      2026-01-21 10:41:51
End time:        2026-01-21 10:41:57
Result:          SUCCESS
Found password:  PASSWORD
======================================================================
```

## How It Works

### Session Code Refresh

Keycloak uses a `session_code` parameter that is tied to each authentication session. This tool fetches a new session code before each login attempt by calling the OAuth authorization endpoint with PKCE parameters.

### Authentication Flow

1. GET `/realms/{realm}/protocol/openid-connect/auth` with PKCE challenge
2. Parse `loginAction` URL from response to extract session parameters
3. POST credentials to `/realms/{realm}/login-actions/authenticate`
4. Check response for success (302 redirect to admin console) or failure

### Detection Methods

The tool identifies the following responses:

| Response | Meaning |
|----------|---------|
| 302 redirect with `code=` | Successful login |
| 200 with "Invalid username or password" | Invalid credentials |
| 200 with "Account is disabled" | Disabled account |
| 200 with "Account is locked" | Locked account |

## Vulnerability Indicators

A successful brute-force attack indicates the following security gaps:

1. No account lockout policy after failed attempts
2. No rate limiting on login requests
3. No MFA requirement for authentication
4. Session codes can be refreshed indefinitely

## Recommendations

Based on findings from this tool, consider implementing:

1. Multi-factor authentication (TOTP, WebAuthn, SMS)
2. Account lockout after 5-10 failed attempts
3. Rate limiting per IP address and username
4. Login attempt monitoring and alerting
5. CAPTCHA after multiple failed attempts

## Legal Disclaimer

This tool is intended for authorized penetration testing and security research only. Unauthorized access to computer systems is illegal. Users are responsible for obtaining proper authorization before testing any systems they do not own.

## Author

wargaintibumi
