# Blind SQL Injection (Boolean/Conditional Response) PoC

A Python proof-of-concept for exploiting **boolean-based blind SQL injection**
via conditional HTTP responses, written against PortSwigger's Web Security
Academy lab: *"Blind SQL injection with conditional responses."*

## How it works

The target application is backed by an Oracle database and reflects a
`TrackingId` cookie value into a SQL query. The app always returns an
HTTP 200 status code, so you can't distinguish a true condition from a
false one by status code alone — but the **response body length differs**
depending on whether the injected condition evaluates to true or false.

The script:

1. Sends a request with a condition it knows is false (`'1'='2'`) to
   establish a baseline response length.
2. For each character position in the password, tries every character in
   `[a-z0-9]` by injecting:
   ```sql
   ' AND (SELECT SUBSTR(password,<position>,1) FROM users WHERE username='administrator')='<character>
   ```
3. If the response length differs from the baseline, that character is
   correct for that position, and the script moves to the next position.
4. Repeats until the full (20-character) password is recovered.

## Usage

```bash
pip install -r requirements.txt

python blind_sqli_boolean.py \
    --url https://YOUR-LAB-ID.web-security-academy.net \
    --session YOUR_SESSION_COOKIE \
    --tracking-id YOUR_TRACKING_ID_BASE
```

- `--url`: your personal lab instance URL
- `--session`: the `session` cookie value from your logged-in lab session
- `--tracking-id`: the base `TrackingId` cookie value issued to your session

Both cookie values can be grabbed from your browser's DevTools
(Application → Cookies) or from Burp Suite's proxy history after visiting
your lab instance.

## Scope and authorization

This tool is built for, and tested against, PortSwigger Web Security
Academy labs — free, disposable environments explicitly provided for
practicing these techniques. **Do not run this against any system you do
not own or do not have explicit written authorization to test.**
Unauthorized access to computer systems is illegal in most jurisdictions.

## Background reading

- [PortSwigger: Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

## License

MIT — see [LICENSE](LICENSE).
