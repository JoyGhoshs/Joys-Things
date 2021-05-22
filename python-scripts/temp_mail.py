#!/usr/bin/env python3
__author__      = "Joy Ghosh"
__copyright__   = "Copyright 2021, SYSTEM00 SECURITY"
from requests import get
from colorama import Fore, Back, Style
import json
import argparse
import time
print(f'''

*
|_
(O)
|#|
'-' [Joy Ghosh]
------
{Fore.RED}Temp_mail{Fore.WHITE}
-----

''')
def get_msg(user):
    send=get(f'https://www.1secmail.com/api/v1/?action=getMessages&login={user}&domain=1secmail.com')
    send_data=send.json()
    send_dump=json.dumps(send_data)
    send_loads=json.loads(send_dump)
    for mails in send_loads:
        print(f'{Fore.RED}----------------------{Fore.WHITE}')
        id=mails['id']
        read_mail=get(f'https://www.1secmail.com/api/v1/?action=readMessage&login={user}&domain=1secmail.com&id={id}')
        read_dump=json.dumps(read_mail.json())
        read_loads=json.loads(read_dump)
        print(f'''
{Fore.GREEN}[  MSG ID   ] : {Fore.WHITE} { read_loads['id'] }
{Fore.GREEN}[   From    ] : {Fore.WHITE} { read_loads['from'] }
{Fore.GREEN}[  Subject  ] : {Fore.WHITE} { read_loads['subject'] }
{Fore.GREEN}[   Date    ] : {Fore.WHITE} { read_loads['date'] }
{Fore.GREEN}[   Body    ] : {Fore.WHITE} { read_loads['body'] }
{Fore.GREEN}[ Text body ] : {Fore.WHITE} { read_loads['textBody'] }
        ''')
        print(f'{Fore.RED}----------------------{Fore.WHITE}')
try:
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="enter username to generate email address [ex: -u hackerone] ", type=str)
    args = parser.parse_args()
    print(f'[ {Fore.RED}Your Email Id :{Fore.BLUE} {args.username}@1secmail.com {Fore.WHITE}]')
    time.sleep(10.0)
    get_msg(args.username)
except TypeError:
    print("Type -h To See all the options")
except KeyboardInterrupt:
    exit()
except:
    exit()
