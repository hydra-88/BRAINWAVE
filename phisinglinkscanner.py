#!/usr/bin/env python3
import requests
import urllib.parse
import re
import time
from typing import Tuple

# List of known legitimate domains (extend as needed)
LEGITIMATE_DOMAINS = [
    "www.google.com",
    "www.facebook.com",
    "www.linkedin.com",
    "www.twitter.com",
    "www.paypal.com",
    "www.amazon.com"
]

# List of common URL shortener domains
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "tiny.cc"
]

def analyze_url(url: str) -> Tuple[bool, str, int]:
    """
    Analyzes a URL for phishing characteristics, including keywords and URL shorteners.
    Returns: (is_phishing: bool, message: str, risk_score: int)
    """
    risk_score = 0
    message = []

    try:
        # Parse URL components
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme
        path = parsed_url.path

        # Check 1: HTTPS usage
        if scheme != "https":
            risk_score += 30
            message.append("Non-HTTPS URL detected (risky).")

        # Check 2: IP address in URL
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if hostname and re.match(ip_pattern, hostname):
            risk_score += 40
            message.append("IP address in URL (highly suspicious).")

        # Check 3: URL length
        if len(url) > 75:
            risk_score += 20
            message.append("Long URL length (>75 chars).")

        # Check 4: Subdomain count
        if hostname:
            subdomains = hostname.split(".")
            if len(subdomains) > 3:  # e.g., sub.sub.domain.com
                risk_score += 25
                message.append("Excessive subdomains detected.")

        # Check 5: Domain similarity to legitimate ones
        if hostname:
            for legit_domain in LEGITIMATE_DOMAINS:
                if legit_domain in hostname and hostname != legit_domain:
                    risk_score += 35
                    message.append(f"Domain resembles {legit_domain} (possible typo-squatting).")
                    break

        # Check 6: Suspicious keywords in path or query
        suspicious_keywords = [
            "login", "secure", "verify", "account", "update",
            "bank", "password", "signin", "authentication", "billing",
            "payment", "access", "reset", "confirm", "admin"
        ]
        if any(keyword in (path.lower() + parsed_url.query.lower()) for keyword in suspicious_keywords):
            risk_score += 20
            message.append("Suspicious keywords detected in URL path or query.")

        # Check 7: URL shortener detection
        if hostname and any(shortener in hostname for shortener in URL_SHORTENERS):
            risk_score += 30
            message.append("URL shortener detected (often used to hide phishing links).")

        # Fetch headers to check server response
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code >= 400:
                risk_score += 20
                message.append("URL returns error status (e.g., 404).")
        except requests.RequestException:
            risk_score += 30
            message.append("URL is unreachable or invalid.")

        # Determine if phishing based on risk score
        is_phishing = risk_score > 50
        if not message:
            message.append("No phishing risks detected.")
        return is_phishing, "\n".join(message), risk_score

    except Exception as e:
        return True, f"Error analyzing URL: {str(e)}", 100

def main():
    print("=== Phishing Link Scanner ===")
    url = input("Enter URL to scan (e.g., https://example.com): ").strip()
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    print("Scanning URL...")
    start_time = time.time()
    
    is_phishing, message, risk_score = analyze_url(url)
    
    end_time = time.time()
    scan_duration = end_time - start_time
    
    print("\n=== Scan Results ===")
    print(f"URL: {url}")
    print(f"Result: {'THIS MAY BE A PHISHING ATTEMPT' if is_phishing else 'SAFE'}")
    print(f"Scan Duration: {scan_duration:.2f} seconds")
    print(f"Details:\n{message}")

if __name__ == "__main__":
    main()
