## Keywords to search 
- [Keywords](git-keywords.txt)

# Google Dorks for Bug Bounty - Comprehensive Guide

## Table of Contents
1. [Quick Start Templates](#quick-start-templates)
2. [High-Value Target Discovery](#high-value-target-discovery)
3. [Vulnerability-Specific Searches](#vulnerability-specific-searches)
4. [Sensitive Information Exposure](#sensitive-information-exposure)
5. [Cloud & Infrastructure](#cloud--infrastructure)
6. [Development & Testing Environments](#development--testing-environments)
7. [Third-Party Integrations](#third-party-integrations)
8. [Advanced Techniques](#advanced-techniques)
9. [Automation Tips](#automation-tips)

---

## Quick Start Templates

Replace `example.com` with your target domain in these essential searches:

### Basic Domain Reconnaissance
```
site:example.com -www -shop -mail -ftp
```

### Find Subdomains with Sensitive Content
```
site:*.example.com inurl:admin OR inurl:login OR inurl:api
```

### Technology Stack Discovery
```
site:example.com ext:js OR ext:json OR ext:xml intitle:"API" OR intitle:"swagger"
```

---

## High-Value Target Discovery

### Bug Bounty Programs
```
inurl:bug-bounty-program OR inurl:vulnerability-disclosure-policy
```
```
inurl:security.txt "bounty" OR "reward"
```
```
inurl:responsible-disclosure "reward" OR "bounty"
```

### Admin Panels & Control Systems
```
inurl:/admin/login OR inurl:/admin/dashboard OR inurl:/cpanel
```
```
intitle:"Admin Panel" OR intitle:"Control Panel" OR intitle:"Dashboard"
```
```
inurl:/wp-admin OR inurl:/administrator OR inurl:/admin.php
```

### API Discovery
```
inurl:/api/v1 OR inurl:/api/v2 OR inurl:/api/v3 OR inurl:/rest
```
```
inurl:swagger OR inurl:api-docs OR inurl:graphql
```
```
inurl:/wp-json/wp/v2/users
```

---

## Vulnerability-Specific Searches

### XSS-Prone Parameters
```
site:example.com inurl:q= OR inurl:search= OR inurl:query= OR inurl:keyword=
```
```
site:example.com inurl:lang= OR inurl:locale= OR inurl:message=
```

### SQL Injection Targets
```
site:example.com inurl:id= OR inurl:pid= OR inurl:category= OR inurl:cat=
```
```
site:example.com inurl:page= OR inurl:action= OR inurl:sid=
```

### Open Redirect Vulnerabilities
```
site:example.com inurl:url= OR inurl:return= OR inurl:redirect= OR inurl:next=
```
```
site:example.com inurl:goto= OR inurl:redir= OR inurl:forward=
```

### SSRF-Prone Parameters
```
site:example.com inurl:url= OR inurl:uri= OR inurl:path= OR inurl:dest=
```
```
site:example.com inurl:domain= OR inurl:host= OR inurl:proxy=
```

### Local File Inclusion (LFI)
```
site:example.com inurl:file= OR inurl:include= OR inurl:dir= OR inurl:folder=
```
```
site:example.com inurl:path= OR inurl:doc= OR inurl:conf=
```

### Remote Code Execution (RCE)
```
site:example.com inurl:cmd= OR inurl:exec= OR inurl:command= OR inurl:shell=
```
```
site:example.com inurl:run= OR inurl:ping= OR inurl:system=
```

---

## Sensitive Information Exposure

### Configuration Files
```
site:example.com ext:env OR ext:ini OR ext:conf OR ext:config
```
```
inurl:/.env OR inurl:/config.json OR inurl:/config.yml
```
```
inurl:/wp-config.php OR inurl:/config.inc OR inurl:/.htaccess
```

### Database Exposures
```
inurl:phpmyadmin OR inurl:adminer OR inurl:mysql
```
```
inurl:/db.sql OR inurl:/backup.sql OR inurl:/dump.sql
```
```
ext:sql OR ext:sqlite OR ext:db filetype:sql
```

### Backup Files & Archives
```
site:example.com ext:bak OR ext:backup OR ext:old OR ext:orig
```
```
site:example.com ext:zip OR ext:tar OR ext:rar OR ext:7z
```
```
inurl:backup OR inurl:dump OR inurl:copy
```

### Git Repositories
```
inurl:/.git/config OR inurl:/.git/HEAD OR inurl:/.git/index
```
```
inurl:/.git/logs OR inurl:/.git/objects
```

### Log Files
```
inurl:error.log OR inurl:access.log OR inurl:debug.log
```
```
site:example.com ext:log "error" OR "exception" OR "fatal"
```

### Sensitive Documents
```
site:example.com ext:pdf OR ext:doc OR ext:xls intext:"confidential"
```
```
site:example.com ext:txt intext:"password" OR intext:"secret"
```

---

## Cloud & Infrastructure

### AWS S3 Buckets
```
site:s3.amazonaws.com "example.com"
```
```
site:s3-external-1.amazonaws.com "example.com"
```

### Microsoft Azure
```
site:blob.core.windows.net "example.com"
```
```
site:dev.azure.com "example.com"
```

### Google Cloud
```
site:googleapis.com "example.com"
```
```
site:storage.googleapis.com "example.com"
```

### File Sharing Services
```
site:drive.google.com "example.com"
```
```
site:dropbox.com/s "example.com"
```
```
site:onedrive.live.com "example.com"
```

### Container Registries
```
site:docker.io "example.com"
```
```
site:quay.io "example.com"
```

---

## Development & Testing Environments

### Staging & Development
```
site:example.com inurl:dev OR inurl:test OR inurl:staging
```
```
site:example.com inurl:sandbox OR inurl:demo OR inurl:beta
```

### Debug & Monitoring
```
inurl:/debug OR inurl:/trace OR inurl:/metrics
```
```
inurl:/actuator OR inurl:/health OR inurl:/info
```
```
inurl:/phpinfo OR inurl:phpinfo.php
```

### Application Frameworks
```
inurl:/jenkins OR inurl:/kibana OR inurl:/grafana
```
```
inurl:/prometheus OR inurl:/consul
```

---

## Third-Party Integrations

### Code Repositories
```
site:github.com "example.com" AND (password OR secret OR key)
```
```
site:gitlab.com "example.com" AND (api_key OR token)
```

### Paste Sites
```
site:pastebin.com "example.com"
```
```
site:justpaste.it "example.com"
```

### Code Sharing Platforms
```
site:jsfiddle.net "example.com"
```
```
site:codepen.io "example.com"
```

### Certificate Transparency
```
site:crt.sh "example.com"
```

---

## Advanced Techniques

### Error Pages & Exceptions
```
site:example.com intext:"SQL syntax" OR intext:"mysql error"
```
```
site:example.com intext:"Warning:" OR intext:"Fatal error:"
```
```
site:example.com intitle:"Index of" OR intitle:"Directory Listing"
```

### Technology Detection
```
site:example.com intext:"powered by" OR intext:"built with"
```
```
site:example.com intext:"Apache" OR intext:"nginx" OR intext:"IIS"
```

### Social Engineering Targets
```
site:example.com intext:"@example.com" filetype:pdf
```
```
site:linkedin.com "example.com" AND "CEO" OR "CTO"
```

### Mobile Applications
```
site:play.google.com "example.com"
```
```
site:apps.apple.com "example.com"
```

---

## Automation Tips

### Search Operators Combinations
- Use `OR` to combine multiple search terms
- Use `AND` to require multiple terms
- Use `-` to exclude terms
- Use `""` for exact phrases
- Use `*` as wildcard

### Efficient Workflow
1. Start with broad domain reconnaissance
2. Focus on high-value targets (admin panels, APIs)
3. Look for sensitive data exposure
4. Check development environments
5. Investigate third-party integrations

### Rate Limiting Considerations
- Space out your searches to avoid being blocked
- Use different search engines (Bing, DuckDuckGo)
- Consider using VPNs or proxies for large-scale searches

### Tools Integration
- Export results to spreadsheets for tracking
- Use tools like `gospider` or `hakrawler` for automated discovery
- Integrate with Burp Suite or OWASP ZAP for further testing

---

## Pro Tips

1. **Target Selection**: Focus on less obvious subdomains and services
2. **Timing**: Check for temporary files during business hours
3. **Seasonality**: Look for backup files at month/year end
4. **Documentation**: Always document your methodology for reports
5. **Validation**: Verify findings manually before reporting
6. **Scope**: Always confirm targets are within scope before testing


## Bash keywords
```text
language:bash password
language:bash pwd
language:bash ftp
language:bash dotfiles
language:bash JDBC
language:bash key-keys
language:bash send_key-keys
language:bash send,key-keys
language:bash token
language:bash user
language:bash login-singin
language:bash passkey-passkeys
language:bash pass
language:bash secret
language:bash credentials
language:bash config
language:bash security_credentials
language:bash connectionstring
language:bash ssh2_auth_password
```

## Python Keywords
```text
language:python password
language:python pwd
language:python ftp
language:python dotfiles
language:python JDBC
language:python key-keys
language:python send_key-keys
language:python send,key-keys
language:python token
language:python user
language:python login-singin
language:python passkey-passkeys
language:python pass
language:python secret
language:python credentials
language:python config
language:python security_credentials
language:python connectionstring
language:python ssh2_auth_password
```
**Example :** `“bugcrowd.com” password language:bash`
## More dorks
```text
FTP_PORT
FTP_PASSWORD
DB_DATABASE=
DB_HOST=
DB_PORT=
DB_PASSWORD=
DB_PW=
DB_USER=
api_key
“api keys”
authorization_bearer:
oauth
auth
authentication
client_secret
api_token:
“api token”
client_id
password
user_password
user_pass
passcode
client_secret
secret
password hash
OTP
user auth
```

***Source***
**https://orwaatyat.medium.com/your-full-map-to-github-recon-and-leaks-exposure-860c37ca2c82**

## AWS secert search

```
org:citrix "aws"
org:Target "bucket_name"
org:Target "aws_access_key"
org:Target "aws_secret_key"
org:Target "S3_BUCKET"
org:Target "S3_ACCESS_KEY_ID"
org:Target "S3_SECRET_ACCESS_KEY"
org:Target "S3_ENDPOINT"
org:Target "AWS_ACCESS_KEY_ID"
org:Target "list_aws_accounts"
```


---

*Remember: Only test on domains you own or have explicit permission to test. Always follow responsible disclosure practices.*
