import re

def check_url(url):
    risk = 0
    reasons = []

    # Long URL
    if len(url) > 75:
        risk += 20
        reasons.append("URL is unusually long")

    # HTTPS Check
    if not url.startswith("https://"):
        risk += 15
        reasons.append("URL does not use HTTPS")

    # IP Address Check
    ip_pattern = r'\d+\.\d+\.\d+\.\d+'

    if re.search(ip_pattern, url):
        risk += 25
        reasons.append("Uses IP address instead of domain name")

    # Suspicious Keywords
    keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "signin",
        "password"
    ]

    for word in keywords:
        if word in url.lower():
            risk += 10
            reasons.append(f"Contains suspicious keyword: {word}")

    # Too many subdomains
    if url.count(".") > 4:
        risk += 15
        reasons.append("Too many subdomains")

    # Classification
    if risk <= 30:
        status = "SAFE"
    elif risk <= 60:
        status = "SUSPICIOUS"
    else:
        status = "PHISHING"

    return {
        "risk": min(risk, 100),
        "status": status,
        "reasons": reasons
    }