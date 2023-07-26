import secrets
import time
import sqlite3
from flask import Flask, request, Response

app = Flask(__name__)

# Hardcoded username and password for authentication
USERNAME = 'admin'
PASSWORD = 'password'

# Store generated tokens and their expiration time
tokens = {}

# SQLite database file
DB_FILE = 'user_profiles.db'

def generate_access_token():
    access_token = secrets.token_hex(16)
    return access_token

def generate_refresh_token():
    refresh_token = secrets.token_hex(16)
    return refresh_token

def delete_expired_tokens():
    current_time = int(time.time())

    # Iterate over a copy of the tokens dictionary to avoid modifying it while iterating
    for access_token, expiration_time in tokens.copy().items():
        if expiration_time < current_time:
            del tokens[access_token]

def create_user_profile_table():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def verify_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user is not None

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
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if verify_user(username, password):
        access_token = generate_access_token()
        refresh_token = generate_refresh_token()
        tokens[access_token] = int(time.time()) + 900  # Set expiration time to 15 minutes from now
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 900  # 15 minutes in seconds
        }
    else:
        return Response('Access denied. Please provide valid credentials.', 401)

@app.route('/refresh_token', methods=['POST'])
def refresh_token():
    refresh_token = request.headers.get('Authorization')

    if refresh_token and refresh_token in tokens.values():
        delete_expired_tokens()  # Delete expired tokens before generating a new one

        access_token = generate_access_token()
        tokens[access_token] = int(time.time()) + 900  # Set expiration time to 15 minutes from now

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 900  # 15 minutes in seconds
        }
    else:
        return Response('Invalid refresh token.', 401)

if __name__ == '__main__':
    create_user_profile_table()  # Create the user profile table if it doesn't exist
    app.run()
