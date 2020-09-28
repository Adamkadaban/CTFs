from flask import Flask, request, render_template, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
import os

def get_random():
    """Generate a random string."""
    return hashlib.sha512(os.urandom(32)).hexdigest()

# Create my flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = get_random()
DB_FILE = '/tmp/db.db'


@app.route('/')
def index():
    # Make sure a user is logged in!
    if 'username' not in session:
        # If they aren't we'll redirect them
        # to the login page.
        return redirect('/login')

    # If its me thats logged in, then
    # I'll want to see the flag.
    if session['username'] == 'admin':
        return render_template('flag.html')

    # For regular logged in users, we'll
    # just show them the index page.
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Load the username and password from the form
        username = request.form.get('username', default=None)
        password = request.form.get('password', default=None)

        # Make sure we actually got form data for both
        if username is None or password is None:
            return 'Missing username or password!', 400

        # Connect to the database
        db = sqlite3.connect(DB_FILE)
        c = db.cursor()

        # Get the user data
        c.execute('SELECT password FROM users WHERE username = ?;', (username,))
        user = c.fetchone()

        # Verify that the user exists
        if user is None:
            return 'User does not exists!', 400

        # Check the password to make sure they match
        if not check_password_hash(user[0], password):
            return 'Invalid credentials!', 400

        # Log them in if they match!
        session['username'] = username.strip()

        # Take them to the home page
        return redirect('/')

    # Give them the login form
    return render_template('login.html')


@app.route('/logout')
def logout():
    # Log them out
    session.pop('username', None)
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Load the username and password from the form
        username = request.form.get('username', default=None)
        password = request.form.get('password', default=None)

        # Make sure we actually got form data for both
        if username is None or password is None:
            return 'Missing username or password!', 400

        # Connect to the database
        db = sqlite3.connect(DB_FILE)
        c = db.cursor()

        # Make sure there isn't already a user with that username
        c.execute('SELECT username FROM users WHERE username = ?;', (username,))
        user = c.fetchone()
        if user is not None:
            return 'User already exists!', 400

        # If there isn't a user by that username, we'll create one!
        c.execute('INSERT INTO users VALUES (?, ?);', (username, generate_password_hash(password)))
        db.commit()
        c.close()

        # Log in the new user
        session['username'] = username

        # Take them to the home page
        return redirect('/')

    # Give them the register form
    return render_template('register.html')


if __name__ == "__main__":
    app.run('0.0.0.0', 5000, debug=True)
