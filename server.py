import secrets
import time
import sqlite3
from flask import Flask, request, Response

app = Flask(__name__)

# Hardcoded username and password for authentication
USERNAME = 'admin'
PASSWORD = 'password'

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

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET access_token=NULL, refresh_token=NULL WHERE expiration_time < ?', (current_time,))
    conn.commit()
    conn.close()

def create_user_profile_table():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            access_token TEXT,
            refresh_token TEXT,
            expiration_time INTEGER
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

def add_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

def save_tokens(username, access_token, refresh_token, expiration_time):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET access_token=?, refresh_token=?, expiration_time=? WHERE username=?',
                   (access_token, refresh_token, expiration_time, username))
    conn.commit()
    conn.close()

def get_refresh_token(username, access_token):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT refresh_token FROM users WHERE username=? AND access_token=?', (username, access_token))
    refresh_token = cursor.fetchone()
    conn.close()
    return refresh_token[0] if refresh_token else None

@app.route('/')
def index():
    return 'Welcome to the authentication server!'

@app.route('/protected')
def protected():
    access_token = request.headers.get('Authorization')

    if access_token:
        username = request.authorization.username
        refresh_token = get_refresh_token(username, access_token)

        if refresh_token:
            return 'Access granted to protected resource!'
    
    return Response('Access denied. Please provide a valid access token.', 401)

@app.route('/signin', methods=['POST'])
def sign_in():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if verify_user(username, password):
        access_token = generate_access_token()
        refresh_token = generate_refresh_token()
        expiration_time = int(time.time()) + 900  # Set expiration time to 15 minutes from now
        save_tokens(username, access_token, refresh_token, expiration_time)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 900  # 15 minutes in seconds
        }
    else:
        return Response('Access denied. Please provide valid credentials.', 401)

@app.route('/refresh_token', methods=['POST'])
def refresh_token():
    data = request.get_json()
    username = data.get('username')
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')

    if not username or not access_token or not refresh_token:
        return Response('Username, access token, and refresh token are required.', 400)

    saved_refresh_token = get_refresh_token(username, access_token)

    if saved_refresh_token == refresh_token:
        delete_expired_tokens()  # Delete expired tokens before generating a new one

        new_access_token = generate_access_token()
        new_refresh_token = generate_refresh_token()
        expiration_time = int(time.time()) + 900  # Set expiration time to 15 minutes from now
        save_tokens(username, new_access_token, new_refresh_token, expiration_time)

        return {
            'access_token': new_access_token,
            'refresh_token': new_refresh_token,
            'expires_in': 900  # 15 minutes in seconds
        }
    else:
        return Response('Invalid refresh token.', 401)

@app.route('/signup', methods=['POST'])
def sign_up():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return Response('Username and password are required.', 400)

    # Check if the user already exists
    if verify_user(username, password):
        return Response('User already exists.', 400)

    # Add the user to the database
    add_user(username, password)

    return Response('User successfully signed up.', 201)

if __name__ == '__main__':
    create_user_profile_table()  # Create the user profile table if it doesn't exist
    app.run()
