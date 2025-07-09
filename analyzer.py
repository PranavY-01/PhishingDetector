import re
from urllib.parse import urlparse

def analyze_email(msg):
    score = 0
    flags = []

    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    # 1. Mismatch in sender headers
    if reply_to and reply_to not in from_addr:
        score += 20
        flags.append("Mismatch between From and Reply-To addresses.")
    if return_path and return_path not in from_addr:
        score += 20
        flags.append("Return-Path differs from sender email.")

    # 2. Check for suspicious links
    urls = extract_urls(msg)
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc and is_suspicious_domain(parsed.netloc):
            score += 30
            flags.append(f"Suspicious domain detected: {parsed.netloc}")

    # 3. Keywords in body
    body = extract_text_body(msg).lower()
    phishing_keywords = ["verify", "urgent", "click here", "password", "reset"]
    for kw in phishing_keywords:
        if kw in body:
            score += 10
            flags.append(f"Keyword '{kw}' found in body.")

    verdict = "Safe"
    if score >= 70:
        verdict = "Malicious"
    elif score >= 30:
        verdict = "Suspicious"

    return {
        "score": score,
        "verdict": verdict,
        "flags": list(set(flags))
    }

def extract_text_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode(errors='ignore')
    else:
        return msg.get_payload(decode=True).decode(errors='ignore')
    return ""

def extract_urls(msg):
    body = extract_text_body(msg)
    return re.findall(r'https?://[^\s"\'>]+', body)

def is_suspicious_domain(domain):
    # Add simple logic here (or load from threat list)
    suspicious_keywords = ["login", "verify", "secure", "update"]
    return any(word in domain for word in suspicious_keywords)
