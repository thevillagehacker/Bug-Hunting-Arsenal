# 🐝 O W A S P

This is the TOP vulnerabilities topics listed in the OWASP

# 💉 SQL INJECTION
<!-- - 💉 [SQL INJECTION](OWASP%20a8681dc402a447439b5f02a5fefeff32/SQL%20INJECTION%20688d8e00caf7475fa4928dfa53061993.md)-->

select * from Usuarios where email='"+ email + "'and senha='"+ senha + " ' ";

**INJECTION**  
`'or 1=1#`
```sql
select * from Usuarios whre email=''or 1=1#'and senha='32425435453'
```
**PREVENTION**
- Sanitization API

# ⛓ BROKEN AUTHENTICATION
<!-- - ⛓ [BROKEN AUTHENTICATION](OWASP%20a8681dc402a447439b5f02a5fefeff32/BROKEN%20AUTHENTICATION%20410e8796ff124658bb58d85820b5be16.md)-->

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

# 🎲 DATA EXPOSURE
<!-- - 🎲 [DATA EXPOSURE](OWASP%20a8681dc402a447439b5f02a5fefeff32/DATA%20EXPOSURE%205dc2ec65cd434ea1a378b4d974e94314.md)-->

- NOT SEND PASSWORDS IN THE URL
- HTTPs in login / credential forms (main in the middle attacks)

### DIRECTORY LISTING

- If the website not block directory paths
