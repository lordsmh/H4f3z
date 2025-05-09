
# H4f3z: Web Vulnerability Scanner

H4f3z is a Python-based web vulnerability scanner designed to help identify common security weaknesses in web applications. It automates the process of testing for various vulnerabilities, providing a starting point for web security assessments.

## Features

- **Comprehensive Vulnerability Checks:** Scans for a wide range of vulnerabilities including:
    -   SQL Injection
    -   Cross-Site Scripting (XSS)
    -   Directory Traversal
    -   Command Injection
    -   Cross-Site Request Forgery (CSRF)
    -   Remote Code Execution (RCE)
    -   Sensitive Data Exposure
    -   XML External Entity (XXE)
    -   Server-Side Request Forgery (SSRF)
    -   Remote File Inclusion (RFI)
    -   Local File Inclusion (LFI)
    -   Cross-Site Script Inclusion (XSSI)
    -   Blind SQL Injection
    -   CORS Misconfiguration
    -   Insecure Direct Object References (IDOR)
    -   Insecure Authentication
    -   Server-Side Template Injection (SSTI)
- **Automated Scanning:** Option to automatically scan for all supported vulnerabilities.
- **Specific Vulnerability Checks:** Ability to target and scan for individual vulnerabilities.

## Prerequisites

- Python 3.x

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/lordsmh/H4f3z.git
    cd H4f3z
    ```

2. **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To use H4f3z, run the following command, replacing `<URL>` with the target website URL:

```bash
python H4f3z.py <URL>
```

### Switches

- `-a`, `--auto`: Automatically scan for all vulnerabilities.
- `-h`, `--help`: Display help information.

### Examples

#### Automatic Scan

To automatically scan for all vulnerabilities:

```bash
python H4f3z.py -a http://example.com
```

#### Display Help

To display help information:

```bash
python H4f3z.py -h
```

## Detectable Vulnerabilities

1. **SQL Injection**
2. **Cross-Site Scripting (XSS)**
3. **Directory Traversal**
4. **Command Injection**
5. **Cross-Site Request Forgery (CSRF)**
6. **Remote Code Execution (RCE)**
7. **Sensitive Data Exposure**
8. **XML External Entity (XXE)**
9. **Server-Side Request Forgery (SSRF)**
10. **Remote File Inclusion (RFI)**
11. **Local File Inclusion (LFI)**
12. **Cross-Site Script Inclusion (XSSI)**
13. **Blind SQL Injection**
14. **CORS Misconfiguration**
15. **Insecure Direct Object References (IDOR)**
16. **Insecure Authentication**
17. **Server-Side Template Injection (SSTI)**

## Help

For more detailed help and usage instructions, run:

```bash
python H4f3z.py -h
```

## Author

Tool developed by `lord_smh`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

