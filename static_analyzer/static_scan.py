import re

def scan_code(file_path):
    vulnerabilities = []

    try:
        with open(file_path, 'r', errors='ignore') as f:
            code = f.read()
    except:
        return []

    # SQL Injection
    if re.search(r"SELECT.*\+", code, re.IGNORECASE):
        vulnerabilities.append({
            "issue": "Possible SQL Injection",
            "severity": "High",
            "description": "SQL query built using string concatenation"
        })

    # Hardcoded Password
    if re.search(r"password\s*=\s*['\"]", code, re.IGNORECASE):
        vulnerabilities.append({
            "issue": "Hardcoded Password",
            "severity": "High",
            "description": "Hardcoded password found in source code"
        })

    # Insecure Function
    if "eval(" in code:
        vulnerabilities.append({
            "issue": "Insecure Function Usage",
            "severity": "Medium",
            "description": "Use of eval() detected"
        })

    return vulnerabilities
