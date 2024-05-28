#pyhthon
import requests
from bs4 import BeautifulSoup

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    # Send a sample SQL injection payload and check the response
    payload = "' OR '1'='1"
    injected_url = f"{url}?id={payload}"

    response = requests.get(injected_url)

    if "Error" in response.text:
        print("SQL Injection vulnerability found!")
    else:
        print("No SQL Injection vulnerability detected.")

# Function to check for XSS vulnerability
def check_xss(url):
    # Send a sample XSS payload and check the response
    payload = "<script>alert('XSS Vulnerability')</script>"
    injected_url = f"{url}?input={payload}"

    response = requests.get(injected_url)

    if payload in response.text:
        print("XSS vulnerability found!")
    else:
        print("No XSS vulnerability detected.")

# Function to check for Directory Traversal vulnerability
def check_directory_traversal(url):
    # Send a sample Directory Traversal payload and check the response
    payload = "../../../../../../../../../etc/passwd"
    injected_url = f"{url}?file={payload}"

    response = requests.get(injected_url)

    if "root:" in response.text:
        print("Directory Traversal vulnerability found!")
    else:
        print("No Directory Traversal vulnerability detected.")

# Function to check for Command Injection vulnerability
def check_command_injection(url):
    # Send a sample Command Injection payload and check the response
    payload = ";ls"
    injected_url = f"{url};{payload}"

    response = requests.get(injected_url)

    if "file1" in response.text:
        print("Command Injection vulnerability found!")
    else:
        print("No Command Injection vulnerability detected.")

# Function to check for CSRF vulnerability
def check_csrf(url):
    # Send a sample CSRF payload and check the response
    payload = "attacker-controlled-data"
    # Placeholder for CSRF check logic
    pass

# Function to check for Remote Code Execution vulnerability
def check_remote_code_execution(url):
    # Send a sample RCE payload and check the response
    payload = "attacker-controlled-command"
    # Placeholder for RCE check logic
    pass

# Function to check for Sensitive Data Exposure vulnerability
def check_sensitive_data_exposure(url):
    # Send a sample sensitive data exposure payload and check the response
    payload = "sensitive-data"
    # Placeholder for sensitive data exposure check logic
    pass

# Function to check for XML External Entity (XXE) vulnerability
def check_xxe(url):
    # Send a sample XXE payload and check the response
    payload = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
    # Placeholder for XXE check logic
    pass

# Function to check for Server-Side Request Forgery (SSRF) vulnerability
def check_ssrf(url):
    # Send a sample SSRF payload and check the response
    payload = "http://localhost:8080/private"
    # Placeholder for SSRF check logic
    pass

# Function to check for Remote File Inclusion (RFI) vulnerability
def check_rfi(url):
    # Send a sample RFI payload and check the response
    payload = "http://attacker.com/malicious.php"
    # Placeholder for RFI check logic
    pass

# Function to check for Local File Inclusion (LFI) vulnerability
def check_lfi(url):
    # Send a sample LFI payload and check the response
    payload = "../../../../../../../../../etc/passwd"
    # Placeholder for LFI check logic
    pass

# Function to check for Cross-Site Script Inclusion (XSSI) vulnerability
def check_xssi(url):
    # Send a sample XSSI payload and check the response
    payload = "<script>alert('XSSI Vulnerability')</script>"
    # Placeholder for XSSI check logic
    pass

# Function to check for Blind SQL Injection vulnerability
def check_sql_injection_blind(url):
    # Send a sample Blind SQL Injection payload and check the response
    payload = "' AND SLEEP(5) --"
    # Placeholder for Blind SQL Injection check logic
    pass

# Function to check for CORS Misconfiguration vulnerability
def check_cors_misconfiguration(url):
    # Send a sample CORS Misconfiguration payload and check the response
    # Placeholder for CORS Misconfiguration check logic
    pass

# Function to check for Insecure Direct Object References (IDOR) vulnerability
def check_idor(url):
    # Send a sample IDOR payload and check the response
    payload = "user_id=1"
   def check_idor(url):
    # Send a sample request with an ID to check if it's possible to access another user's data
    user_id = 1  # Sample user ID
    injected_url = f"{url}?user_id={user_id}"  # Injected URL with user ID parameter

    response = requests.get(injected_url)

    if "Unauthorized" in response.text:
        print("IDOR vulnerability found!")
    else:
        print("No IDOR vulnerability detected.")
    pass

# Function to check for Insecure Authentication vulnerability
def check_insecure_authentication(url):
    # Send a sample Insecure Authentication payload and check the response
    payload = "attacker"
    # Placeholder for Insecure Authentication check logic
    pass

# Function to check for Server-Side Template Injection (SSTI) vulnerability
def check_ssti(url):
    # Send a sample SSTI payload and check the response
    payload = "{{7*7}}"
    # Placeholder for SSTI check logic
    pass

# Function to check for Remote Code Execution (RCE) vulnerability
def check_rce(url):
    # Send a sample RCE payload and check the response
    payload = "system('ls')"
    # Placeholder for RCE check logic
    pass

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
    print("Scanning for Server -Side Template Injection (SSTI) vulnerability...")
    check_ssti(url)
    print("Scanning for Remote Code Execution (RCE) vulnerability...")
    check_rce(url)

# scan_all_vulnerabilities("http://example.com")

# Function to scan the website for vulnerabilities
def scan_website(target_url, auto_scan=False):
    print("Scanning website:", target_url)
    print("Checking for vulnerabilities...")

    # Automatically scan for all vulnerabilities if auto_scan is True
    if auto_scan:
        for vuln in vulnerabilities:
            print(f"Checking for {vuln['name']} vulnerability: {vuln['description']}")
            vuln['check_function'](target_url)
    else:
        # Placeholder for vulnerability detection logic
        for vuln in vulnerabilities:
            print(f"Checking for {vuln['name']} vulnerability: {vuln['description']}")
            vuln['check_function'](target_url)

# Main function
def main():
    parser = argparse.ArgumentParser(description="sarbaz gomnam - Web Vulnerability Scanner")
    parser.add_argument("target_url", help="Target website URL")
    parser.add_argument("--auto", action="store_true", help="Automatically scan for all vulnerabilities")

    args = parser.parse_args()

    scan_website(args.target_url, args.auto)

if __name__ == "__main__":
    main()
