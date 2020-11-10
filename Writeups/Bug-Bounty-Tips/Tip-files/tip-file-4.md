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
