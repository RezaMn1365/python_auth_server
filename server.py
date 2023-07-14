import secrets
from flask import Flask, request, Response

app = Flask(__name__)

# Hardcoded username and password for authentication
USERNAME = 'admin'
PASSWORD = 'password'

# Store generated tokens
tokens = {}

def generate_access_token():
    access_token = secrets.token_hex(16)
    return access_token

def generate_refresh_token():
    refresh_token = secrets.token_hex(16)
    return refresh_token

@app.route('/')
def index():
    return 'Welcome to the authentication server!'

@app.route('/protected')
def protected():
    access_token = request.headers.get('Authorization')

    if access_token and access_token in tokens:
        return 'Access granted to protected resource!'
    else:
        return Response('Access denied. Please provide a valid access token.', 401)

@app.route('/signin', methods=['POST'])
def sign_in():
    auth = request.authorization

    if auth and auth.username == USERNAME and auth.password == PASSWORD:
        access_token = generate_access_token()
        refresh_token = generate_refresh_token()
        tokens[access_token] = refresh_token
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 900  # 15 minutes in seconds
        }
    else:
        return Response('Access denied. Please provide valid credentials.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.route('/refresh_token', methods=['POST'])
def refresh_token():
    refresh_token = request.headers.get('Authorization')

    if refresh_token and refresh_token in tokens.values():
        access_token = generate_access_token()
        tokens[access_token] = refresh_token
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 900  # 15 minutes in seconds
        }
    else:
        return Response('Invalid refresh token.', 401)

if __name__ == '__main__':
    app.run()
