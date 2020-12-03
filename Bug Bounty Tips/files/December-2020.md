# December Month Tips

📅 01-Dec-2020
## Misconfigured Jira Instance Discloses Sensitive Information
`site:http://atlassian.net "company"`

## Gitlab H1 Reports from [yvvdwf](https://hackerone.com/yvvdwf?type=user)
- https://hackerone.com/reports/950190
- https://hackerone.com/reports/806571
- https://hackerone.com/reports/824689
- https://hackerone.com/reports/831962

## Admin Auth Bypass
```http
GET /admin%2ejsp%3b.png
```
Was able to turn a number of post-auth SQL injections into pre-auth vulns.
