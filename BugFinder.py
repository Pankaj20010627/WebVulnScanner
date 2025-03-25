import requests
import tkinter as tk
from tkinter import scrolledtext, messagebox
import re
import socket
from bs4 import BeautifulSoup

def scan_website(event=None):
    url = url_entry.get()
    results_text.delete(1.0, tk.END)
    
    if not url.startswith("http"):
        url = "http://" + url
    
    results_text.insert(tk.END, f"Scanning: {url}\n\n", "header")
    
    try:
        response = requests.get(url)
        headers = response.headers
    except requests.exceptions.RequestException as e:
        results_text.insert(tk.END, f"Error: {e}\n", "error")
        return
    
    security_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
    missing_headers = [h for h in security_headers if h not in headers]
    if missing_headers:
        results_text.insert(tk.END, f"Missing Security Headers: {', '.join(missing_headers)}\n", "warning")
    else:
        results_text.insert(tk.END, "All Security Headers are Present!\n", "success")
    
    xss_payload = "<script>alert('XSS')</script>"
    xss_test_url = f"{url}?q={xss_payload}"
    xss_response = requests.get(xss_test_url)
    if xss_payload in xss_response.text:
        results_text.insert(tk.END, "XSS Vulnerability Found!\n", "error")
    else:
        results_text.insert(tk.END, "No XSS Vulnerability Found.\n", "success")
    
    sqli_payload = "' OR '1'='1"
    sqli_test_url = f"{url}?id={sqli_payload}"
    sqli_response = requests.get(sqli_test_url)
    if "SQL syntax" in sqli_response.text or "mysql_fetch" in sqli_response.text:
        results_text.insert(tk.END, "SQL Injection Vulnerability Found!\n", "error")
    else:
        results_text.insert(tk.END, "No SQL Injection Vulnerability Found.\n", "success")
    
    if "X-Frame-Options" not in headers:
        results_text.insert(tk.END, "Clickjacking Vulnerability Found!\n", "warning")
    else:
        results_text.insert(tk.END, "No Clickjacking Vulnerability Found.\n", "success")
    
    if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
        results_text.insert(tk.END, "CORS Misconfiguration Found!\n", "warning")
    else:
        results_text.insert(tk.END, "No CORS Misconfiguration Found.\n", "success")
    
    common_subdomains = ["www", "admin", "mail", "test", "dev"]
    for sub in common_subdomains:
        subdomain = f"{sub}.{url.replace('http://', '').replace('https://', '').split('/')[0]}"
        try:
            ip = socket.gethostbyname(subdomain)
            results_text.insert(tk.END, f"Found Subdomain: {subdomain} ({ip})\n", "info")
        except:
            pass
    
    # Fetch public information about the website
    fetch_website_info(url)

def fetch_website_info(url):
    results_text.insert(tk.END, "\nFetching public website info...\n", "header")
    
    try:
        ip_address = socket.gethostbyname(url.replace("http://", "").replace("https://", "").split("/")[0])
        results_text.insert(tk.END, f"IP Address: {ip_address}\n", "info")
    except socket.gaierror:
        results_text.insert(tk.END, "Could not resolve IP address.\n", "error")
    
    whois_url = f"https://www.whois.com/whois/{url.replace('http://', '').replace('https://', '').split('/')[0]}"
    results_text.insert(tk.END, f"WHOIS Lookup: {whois_url}\n", "info")
    
    results_text.insert(tk.END, "Public information retrieved successfully!\n", "success")

def reset_scan():
    url_entry.delete(0, tk.END)
    results_text.delete(1.0, tk.END)

def create_gui():
    global url_entry, results_text
    
    root = tk.Tk()
    root.title("Web Vulnerability Scanner & Info Finder")
    root.geometry("700x550")
    root.configure(bg="#2C3E50")
    
    tk.Label(root, text="Enter Website URL:", font=("Arial", 12), bg="#2C3E50", fg="white").pack(pady=5)
    url_entry = tk.Entry(root, width=50, font=("Arial", 12))
    url_entry.pack(pady=5)
    url_entry.bind("<KeyRelease>", scan_website)  # Trigger scan on input change
    
    button_frame = tk.Frame(root, bg="#2C3E50")
    button_frame.pack(pady=5)
    
    scan_button = tk.Button(button_frame, text="Scan Website", font=("Arial", 12), command=scan_website, bg="#27AE60", fg="white", width=15)
    scan_button.grid(row=0, column=0, padx=5)
    
    reset_button = tk.Button(button_frame, text="Reset", font=("Arial", 12), command=reset_scan, bg="#E74C3C", fg="white", width=15)
    reset_button.grid(row=0, column=1, padx=5)
    
    results_text = scrolledtext.ScrolledText(root, width=80, height=25, font=("Courier", 10), bg="#ECF0F1")
    results_text.pack(pady=10)
    
    results_text.tag_config("header", foreground="blue", font=("Arial", 12, "bold"))
    results_text.tag_config("error", foreground="red", font=("Arial", 10, "bold"))
    results_text.tag_config("warning", foreground="orange", font=("Arial", 10))
    results_text.tag_config("success", foreground="green", font=("Arial", 10))
    results_text.tag_config("info", foreground="purple", font=("Arial", 10))
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
