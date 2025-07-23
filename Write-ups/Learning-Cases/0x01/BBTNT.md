# [PROGRAM_NAME] Bug Bounty Testing Note

This template is designed to help bug bounty hunters efficiently track progress, findings, and critical details of their bug bounty engagement.

---

## 1. Target Information

| Target ID | Program/Asset Name | URL | Description | Known Issues | Scope (In/Out) | Status | Additional Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Program/Asset Name | URL | Brief description of asset/program | Known vulnerabilities (if any) | In-scope/Out-of-scope | Active/Inactive | Any extra details or concerns |

**Additional Notes:**

- Include details on target reputation, previous engagement, inscope, out of scope or anything noteworthy.
- Add program-specific quirks or rules that don’t fit into other categories.

---

## 2. Program Details

### **Program Rules:**

1. **Vulnerability Submission Guidelines:**
    
    Specify severity levels, payout structures, required information for submission, etc.
    
2. **Disclosure Policy:**
    
    Is the program public, private, or invite-only? Any special rules around responsible disclosure?
    
3. **Other Restrictions:**
    
    Specific limitations, like no automated tools, or non-aggressive testing.

---

## 3. Test Accounts

| Account Type | Email | Password | Roles | Notes |
| --- | --- | --- | --- | --- |
| Admin | [admin@example.com](mailto:admin@example.com) | P@ssw0rd | Administrator | Created via admin panel |
| Regular User | [user@example.com](mailto:user@example.com) | User123! | Basic User | Signed up via public signup page |

**Additional Test Accounts:**

- Include details on additional test accounts, cookies, session tokens, or multi-factor authentication (MFA) methods if applicable.

---

## 4. Objectives

### **Primary Objectives:**

- Find and exploit any **critical vulnerabilities** like SQLi, XSS, RCE, etc.
- Test for **authentication/authorization issues** (IDOR, privilege escalation).

### **Secondary Objectives:**

- Assess **business logic flaws** in how users interact with the application.
- Explore **post-authenticated vectors**.

---



## 5. Timeline

| Event | Date and Time (UTC) | Details |
| --- | --- | --- |
| Program Start | YYYY-MM-DD HH:MM | Invited to participate |
| Vulnerability Found | YYYY-MM-DD HH:MM | Found SQLi in login form |
| Report Submitted | YYYY-MM-DD HH:MM | SQLi report submitted to platform |
| Response from Program | YYYY-MM-DD HH:MM | SQLi confirmed, bounty awarded |

---

