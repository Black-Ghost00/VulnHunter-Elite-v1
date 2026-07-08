#!/usr/bin/env python3
"""
VulnHunter Elite v1.0 - CLI Edition
Website Security Auditor for Beginners
"""

import sys
import urllib.request
import ssl
import socket


def print_banner():
    print("=" * 60)
    print("  VULNHUNTER ELITE v1.0")
    print("  CLI Edition - Website Security Auditor")
    print("=" * 60)
    print()


def analyze_url(url):
    print("[1] URL SAFETY CHECK")
    print("-" * 40)

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    parts = domain.split('.')

    risk = 0
    issues = []

    if any(char.isdigit() for char in domain.replace("www.", "")):
        risk += 20
        issues.append("Numbers found in domain")

    suspicious = ['login', 'verify', 'secure', 'update', 'confirm', 'security', 'bank', 'account']
    for word in suspicious:
        if word in domain.lower():
            risk += 15
            issues.append(f"Suspicious word: '{word}'")

    similar = {'0': 'o', '1': 'l', '5': 's'}
    for fake, real in similar.items():
        if fake in domain:
            risk += 15
            issues.append(f"Similar character: '{fake}' looks like '{real}'")

    if len(parts) > 2:
        subdomain = '.'.join(parts[:-2])
        known_brands = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'bank']
        for brand in known_brands:
            if brand in subdomain.lower() and brand not in parts[-2]:
                risk += 30
                issues.append(f"SUBDOMAIN PHISHING: '{brand}' in subdomain")

    if len(domain) > 30:
        risk += 10
        issues.append("Very long domain")

    if not url.startswith("https"):
        risk += 25
        issues.append("Not using HTTPS")

    final_score = min(risk, 100)

    if issues:
        for issue in issues:
            print(f"  !  {issue}")
    else:
        print("  OK  No suspicious patterns")

    print(f"  Risk Score: {final_score}/100")
    print()

    return 100 - final_score


def analyze_headers(url):
    print("[2] SECURITY HEADERS")
    print("-" * 40)

    score = 0
    total = 6

    try:
        req = urllib.request.Request(url, method='HEAD')
        response = urllib.request.urlopen(req, timeout=10)
        headers = dict(response.headers)

        checks = {
            'Strict-Transport-Security': 'HSTS (HTTPS Force)',
            'Content-Security-Policy': 'CSP (XSS Protection)',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Referrer-Policy': 'Privacy Protection',
            'Permissions-Policy': 'Feature Control'
        }

        for header, name in checks.items():
            if header in headers:
                print(f"  OK  {name}")
                score += 1
            else:
                print(f"  X   {name}")

    except Exception as e:
        print(f"  X   Error checking headers: {str(e)[:50]}")

    final_score = int((score / total) * 100)
    print(f"  Header Score: {final_score}%")
    print()

    return final_score


def analyze_certificate(url):
    print("[3] CERTIFICATE STATUS")
    print("-" * 40)

    if not url.startswith("https"):
        print("  X   No HTTPS - Certificate not applicable")
        print("  X   Risk: HIGH")
        print()
        return 0

    try:
        hostname = url.replace("https://", "").split("/")[0]
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

                print(f"  OK  Certificate valid")
                print(f"  OK  TLS Version: {version}")

                if version in ['TLSv1.3', 'TLSv1.2']:
                    print(f"  OK  Strong encryption")
                    score = 100
                else:
                    print(f"  !   Weak encryption detected")
                    score = 50

    except Exception as e:
        print(f"  X   Certificate error")
        score = 0

    print(f"  Certificate Score: {score}%")
    print()

    return score


def final_report(scores):
    print("=" * 60)
    print("  FINAL REPORT")
    print("=" * 60)

    avg_score = int(sum(scores) / len(scores))

    if avg_score >= 80:
        risk = "EXCELLENT"
    elif avg_score >= 60:
        risk = "GOOD"
    elif avg_score >= 40:
        risk = "FAIR"
    else:
        risk = "CRITICAL"

    print(f"
  OVERALL SCORE: {avg_score}/100")
    print(f"  STATUS: {risk}")

    print(f"
  BREAKDOWN:")
    print(f"     URL Safety:       {scores[0]}%")
    print(f"     Security Headers: {scores[1]}%")
    print(f"     Certificate:      {scores[2]}%")

    print(f"
  RECOMMENDATIONS:")
    if avg_score >= 80:
        print("  OK  This website appears safe to use")
        print("  OK  Standard precautions recommended")
    elif avg_score >= 60:
        print("  !   Exercise caution with sensitive data")
        print("  !   Verify website legitimacy independently")
    elif avg_score >= 40:
        print("  !   Avoid entering passwords or payment info")
        print("  !   Consider using alternative websites")
    else:
        print("  X   High risk detected - avoid this website")
        print("  X   Do not enter any personal information")

    print(f"
{'=' * 60}
")


def main():
    print_banner()

    if len(sys.argv) < 2:
        url = input("Enter website URL (https://example.com): ").strip()
    else:
        url = sys.argv[1]

    if not url.startswith("http"):
        url = "https://" + url

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    print(f"Target: {url}")
    print(f"Domain: {domain}
")

    scores = []
    scores.append(analyze_url(url))
    scores.append(analyze_headers(url))
    scores.append(analyze_certificate(url))

    final_report(scores)


if __name__ == "__main__":
    main()
