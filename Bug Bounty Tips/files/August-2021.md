# Bug Bounty Tips - August 2021

## [Found a potential SSRF vuln but no luck? Don't give up just now!](https://twitter.com/intigriti/status/1421435484950208513?s=20)

![img](https://pbs.twimg.com/media/E7n0Cm3WQAEAqX8?format=jpg&name=small)

## Subdomain Enumeration using JLDC
```sh
curl -s "https://jldc.me/anubis/subdomains/att.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew 
```
![img](https://pbs.twimg.com/media/E8X1RmCXIAEd5wJ?format=jpg&name=small)
