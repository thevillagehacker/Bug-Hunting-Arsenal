# BROKEN AUTHENTICATION

When the website allow weak passwords

- Bruteforce Wordlist (with common passwords)
- Credential stuffing (exposed databases)

- Exposed cookies / ids in the URL

- 🎫 [SESSION HIJACKING](BROKEN%20AUTHENTICATION%20410e8796ff124658bb58d85820b5be16/SESSION%20HIJACKING%205680569d402c459c82b312dd25038512.md)

- If the website permits bruteforce tentatives or weak passwords
- If the recovery methods is weak (knowledge-based aswers)
- If the website not encrypt the passwords (bcrypt)
- If the administrator panel has default passwords

### PREVENTION

- Not allow weak passwords ex: "password"
- Password Captcha
- Multi factor authentication
- Limit login tentatives
- Disable default administrative passwords
- Password validation  (NIST 800-63 Memorized Secrets)
