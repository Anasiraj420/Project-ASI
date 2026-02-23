import requests

def scan_url(url):
    vulnerabilities = []

    try:
        response = requests.get(url, timeout=5)
    except:
        return vulnerabilities

    # Security Headers Check
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security"
    ]

    for header in required_headers:
        if header not in response.headers:
            vulnerabilities.append({
                "issue": "Missing Security Header",
                "severity": "Low",
                "description": f"{header} header is missing"
            })

    # Simple XSS Test
    xss_payload = "<script>alert(1)</script>"
    try:
        test = requests.get(url, params={"q": xss_payload}, timeout=5)
        if xss_payload in test.text:
            vulnerabilities.append({
                "issue": "Possible XSS",
                "severity": "High",
                "description": "Reflected XSS detected"
            })
    except:
        pass

    return vulnerabilities
