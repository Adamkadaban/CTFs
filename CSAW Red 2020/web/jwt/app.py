from flask import Flask, jsonify, request, send_from_directory, url_for, redirect, make_response, current_app
import jwt
import os

app = Flask(__name__)

# get secret from file
def get_secret(filename):
    f = current_app.open_resource(filename)
    secret = f.readline().strip()
    f.close()
    return secret

# index page
@app.route('/', methods=['GET', 'POST'])
def index():
    # if GET request return html
    if request.method == 'GET':
        return """
        <h2>Request access</h2>
        <form method=POST>
            <input name=filename placeholder=filename>
            <input type=submit>
        </form>
        <a href="flag.txt">flag.txt</a>
        <a href="meme.jpg">meme.jpg</a>
        <a href="hints.txt">hints.txt</a>
        """

    # if post request set cookie
    filename = request.form['filename']

    # dont allow requesting access to flag
    if filename == 'flag.txt':
        return "sorry, can't give you access to that"

    # create response
    msg = f"<p>you now have access to view {request.form['filename']}<p>"
    msg += "<a href=/>home</a>"
    resp = make_response(msg)

    # create token
    secret = get_secret('static/secret.txt')
    json = {'filename': filename}
    token = jwt.encode(json, secret, algorithm='HS256')
    # set token as cookie
    resp.set_cookie('jwt', token)

    # return our response with our cookie set
    return resp

@app.route('/<filename>')
@app.route('/static/<filename>')
def get_file(filename):
    try:
        # try to decode token
        token = request.cookies.get('jwt').encode('utf-8')
        secret = get_secret('static/secret.txt')
        json = jwt.decode(token, secret, algorithms=['HS256'])
    except NameError:
        # unable to decode token, bad secret
        return "401 unauthorized: invalid token", 401
    except AttributeError:
        # no token set
        return "401 unauthorized: no token set", 401
    except jwt.exceptions.DecodeError:
        # unable to decode token, bad token
        return "401 unauthorized: invalid token", 401

    # check if we have access for file
    if json['filename'] == filename:
        return app.send_static_file(filename)
    else:
        # we're trying to access a file without correct token
        return "401 unauthorized", 401

if __name__ == "__main__":
    app.run('0.0.0.0', 5000)
