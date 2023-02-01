# Secure Admin

> This is an introduction to SQL injection. If you don't know what SQLi is, we recommend checking out a tutorial here ([https://ctf101.org/web-exploitation/sql-injection/what-is-sql-injection/](https://ctf101.org/web-exploitation/sql-injection/what-is-sql-injection/)).
This admin panel seems secure?

1. Go to the link they give you
2. The challenge says we should use sql injection.. lets do that
3. Type in the following into the username text box:

    ```sql
    ' OR 1=1--
    ```

4. The site notifies us that we need an entry for both text fields

    ![Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled.png](Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled.png)

    - So let's enter the same thing for the password.
5. The login works

    ![Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled%201.png](Secure%20Admin%20b0dee42673c6471fb8ce60696e3656b5/Untitled%201.png)

6. The flag is peaCTF{0f8544e4-b3c2-41ae-9486-d797da048af6}