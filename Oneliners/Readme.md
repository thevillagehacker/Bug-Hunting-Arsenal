# Bash Oneliners
## Open Redirect
```sh
cat urls| gf redirect | tee -a redirect.txt | cut -f 3- -d';' | qsreplace "https://evil.com" | httpx -status-code
```

## SSRF
```sh
cat urls| gf ssrf | tee -a ssrf.txt | cut -f 3- -d';' | qsreplace "https://public-server" | httpx -status-code
```
