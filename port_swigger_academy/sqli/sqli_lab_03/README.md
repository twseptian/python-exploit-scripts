# SQL injection UNION attacks

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the `UNION` keyword can be used to retrieve data from other tables within the database. This results in an SQL injection UNION attack.

The `UNION` keyword lets you execute one or more additional `SELECT` queries and append the results to the original query. For example:

`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`

This SQL query will return a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and `d` in `table2`.

For a `UNION` query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

To carry out an SQL injection UNION attack, you need to ensure that your attack meets these two requirements. This generally involves figuring out:

- How many columns are being returned from the original query?
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query?

## Determining the number of columns required in an SQL injection UNION attack

When performing an SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

The first method involves injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs. For example, assuming the injection point is a quoted string within the `WHERE` clause of the original query, you would submit:

`' ORDER BY 1-- ' ORDER BY 2-- ' ORDER BY 3-- etc.`

This series of payloads modifies the original query to order the results by different columns in the result set. The column in an `ORDER BY` clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as:

`The ORDER BY position number 3 is out of range of the number of items in the select list.`

The application might actually return the database error in its HTTP response, or it might return a generic error, or simply return no results. Provided you can detect some difference in the application's response, you can infer how many columns are being returned from the query.

The second method involves submitting a series of `UNION SELECT` payloads specifying a different number of null values:

`' UNION SELECT NULL-- ' UNION SELECT NULL,NULL-- ' UNION SELECT NULL,NULL,NULL-- etc.`

If the number of nulls does not match the number of columns, the database returns an error, such as:

`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`

Again, the application might actually return this error message, or might just return a generic error or no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column. The effect on the resulting HTTP response depends on the application's code. If you are lucky, you will see some additional content within the response, such as an extra row on an HTML table. Otherwise, the null values might trigger a different error, such as a `NullPointerException`. Worst case, the response might be indistinguishable from that which is caused by an incorrect number of nulls, making this method of determining the column count ineffective.

#### Note

- The reason for using  `NULL`  as the values returned from the injected  `SELECT`  query is that the data types in each column must be compatible between the original and the injected queries. Since  `NULL`  is convertible to every commonly used data type, using  `NULL`  maximizes the chance that the payload will succeed when the column count is correct.
- On Oracle, every  `SELECT`  query must use the  `FROM`  keyword and specify a valid table. There is a built-in table on Oracle called  `dual`  which can be used for this purpose. So the injected queries on Oracle would need to look like:
    
    `' UNION SELECT NULL FROM DUAL--`
- The payloads described use the double-dash comment sequence  `--`  to comment out the remainder of the original query following the injection point. On MySQL, the double-dash sequence must be followed by a space. Alternatively, the hash character  `#`  can be used to identify a comment.

For more details of database-specific syntax, see the  [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

# Lab: SQL injection UNION attack, determining the number of columns returned by the query

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

To solve the lab, determine the number of columns returned by the query by performing an  [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks)  attack that returns an additional row containing null values.

# PoC
```bash
$ python3 sqli_lab_03.py https://ac0f1f641f2e33ebc0bd0xxxxxxxx.web-security-academy.net/ 

    >> SQL injection UNION attack, determining the number of columns returned by the query
    >> by Port Swigger Academy

[*] Figuring out number of columns...
[✓] The number of columns is 3.
```