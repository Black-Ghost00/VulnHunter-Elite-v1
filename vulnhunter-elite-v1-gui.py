#!/usr/bin/env python3
"""
VulnHunter Elite v1.0 - GUI Edition
Website Security Auditor for Beginners
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import urllib.request
import ssl
import socket


class VulnHunterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnHunter Elite v1.0 - GUI Edition")
        self.root.geometry("800x700")
        self.root.configure(bg="#1a1a2e")
        self.create_widgets()

    def create_widgets(self):
        # Title
        tk.Label(self.root, text="VULNHUNTER ELITE v1.0",
                font=("Helvetica", 24, "bold"),
                bg="#1a1a2e", fg="#00d4ff").pack(pady=20)

        tk.Label(self.root, text="Website Security Auditor - GUI Edition",
                font=("Helvetica", 12),
                bg="#1a1a2e", fg="#888888").pack()

        # URL Input
        input_frame = tk.Frame(self.root, bg="#1a1a2e")
        input_frame.pack(pady=30, padx=50, fill="x")

        tk.Label(input_frame, text="Target URL:", bg="#1a1a2e", fg="#00d4ff",
                font=("Helvetica", 12)).pack(side="left", padx=5)

        self.url_entry = tk.Entry(input_frame, font=("Helvetica", 14), width=40,
                                 bg="#16213e", fg="white", insertbackground="white")
        self.url_entry.pack(side="left", padx=10, fill="x", expand=True)
        self.url_entry.insert(0, "https://")

        # Scan Button
        tk.Button(self.root, text="START SCAN",
                 font=("Helvetica", 14, "bold"),
                 bg="#00d4ff", fg="#1a1a2e",
                 command=self.start_scan).pack(pady=20)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, length=600, mode='determinate')
        self.progress.pack(pady=10)

        # Results Area
        self.results = scrolledtext.ScrolledText(
            self.root, width=80, height=25,
            font=("Courier", 11),
            bg="#16213e", fg="#00d4ff"
        )
        self.results.pack(padx=30, pady=10, fill="both", expand=True)

        # Score Label
        self.score_label = tk.Label(self.root, text="",
                                   font=("Helvetica", 18, "bold"),
                                   bg="#1a1a2e", fg="white")
        self.score_label.pack(pady=10)

    def log(self, text):
        self.results.insert("end", text + "\n")
        self.results.see("end")
        self.root.update()

    def get_risk_text(self, score):
        if score >= 80:
            return "EXCELLENT"
        elif score >= 60:
            return "GOOD"
        elif score >= 40:
            return "FAIR"
        else:
            return "CRITICAL"

    def analyze_url(self, url):
        self.log("=" * 50)
        self.log("[1] URL SAFETY CHECK")
        self.log("-" * 40)

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
                self.log(f"  !  {issue}")
        else:
            self.log("  OK  No suspicious patterns")

        self.log(f"  Risk Score: {final_score}/100")
        self.log("")

        return 100 - final_score

    def analyze_headers(self, url):
        self.log("[2] SECURITY HEADERS")
        self.log("-" * 40)

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
                    self.log(f"  OK  {name}")
                    score += 1
                else:
                    self.log(f"  X   {name}")

        except Exception as e:
            self.log(f"  X   Error: {str(e)[:50]}")

        final_score = int((score / total) * 100)
        self.log(f"  Header Score: {final_score}%")
        self.log("")

        return final_score

    def analyze_certificate(self, url):
        self.log("[3] CERTIFICATE STATUS")
        self.log("-" * 40)

        if not url.startswith("https"):
            self.log("  X   No HTTPS")
            self.log("")
            return 0

        try:
            hostname = url.replace("https://", "").split("/")[0]
            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()

                    self.log(f"  OK  Certificate valid")
                    self.log(f"  OK  TLS Version: {version}")

                    if version in ['TLSv1.3', 'TLSv1.2']:
                        self.log(f"  OK  Strong encryption")
                        score = 100
                    else:
                        self.log(f"  !   Weak encryption")
                        score = 50

        except Exception as e:
            self.log(f"  X   Certificate error")
            score = 0

        self.log(f"  Certificate Score: {score}%")
        self.log("")

        return score

    def start_scan(self):
        url = self.url_entry.get().strip()

        if not url.startswith("http"):
            url = "https://" + url

        self.results.delete(1.0, "end")
        self.progress['value'] = 0
        self.score_label.config(text="")

        self.log(f"Target: {url}")
        self.log("")

        scores = []

        self.progress['value'] = 20
        scores.append(self.analyze_url(url))

        self.progress['value'] = 50
        scores.append(self.analyze_headers(url))

        self.progress['value'] = 80
        scores.append(self.analyze_certificate(url))

        self.progress['value'] = 100

        avg_score = int(sum(scores) / len(scores))
        risk = self.get_risk_text(avg_score)

        self.log("=" * 50)
        self.log("FINAL REPORT")
        self.log("=" * 50)
        self.log(f"OVERALL SCORE: {avg_score}/100")
        self.log(f"STATUS: {risk}")

        if avg_score >= 80:
            color = "#2ecc71"
        elif avg_score >= 60:
            color = "#f39c12"
        else:
            color = "#e74c3c"

        self.score_label.config(text=f"{avg_score}/100 - {risk}", fg=color)


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnHunterGUI(root)
    root.mainloop()
