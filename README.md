

 

# Sarbaz Gomnam: Web Vulnerability Scanner

Sarbaz Gomnam is a web penetration testing and security tool designed to detect common vulnerabilities in websites. This tool can identify several critical security flaws, making it a valuable resource for both novice and professional penetration testers.

## Features

- Detects multiple major security vulnerabilities including:

            ''''some one Not complete yet''''

  - SQL Injection +
  - Cross-Site Scripting (XSS) +
  - Directory Traversal +
  - Command Injection -
  - Cross-Site Request Forgery (CSRF) -
  - Remote Code Execution (RCE) -
  - Sensitive Data Exposure - 
  - XML External Entity (XXE) -
  - Server-Side Request Forgery (SSRF) -
  - Remote File Inclusion (RFI) -
  - Local File Inclusion (LFI) -
  - Cross-Site Script Inclusion (XSSI) -
  - Blind SQL Injection -
  - CORS Misconfiguration -
  - Insecure Direct Object References (IDOR) +
  - Insecure Authentication -
  - Server-Side Template Injection (SSTI) -

## Prerequisites

- Python 3.x
- Install the required Python libraries using the command `pip install -r requirements.txt`

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/lordsmh/sarbaz_gomnam.git
    cd sarbaz_gomnam
    ```

2. **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To use Sarbaz Gomnam, run the following command, replacing `<URL>` with the target website URL:

```bash
python sarbaz_gomnam.py <URL>
```

### Switches

- `-a`, `--auto`: Automatically scan for all vulnerabilities.
- `-h`, `--help`: Display help information.

### Examples

#### Automatic Scan

To automatically scan for all vulnerabilities:

```bash
python sarbaz_gomnam.py -a http://example.com
```

#### Display Help

To display help information:

```bash
python sarbaz_gomnam.py -h
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
python sarbaz_gomnam.py -h
```

## Author

Tool developed by `lord_smh`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

