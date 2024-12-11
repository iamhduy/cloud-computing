import base64
import hashlib
import hmac
import sqlite3
import os
import json
import requests
from flask import Flask, request

app = Flask(__name__)
db_name = "user.db"
sql_file = "user.sql"
db_flag = False


@app.route('/', methods=(['GET']))
def index():
    MICRO2URL = "http://micro-2:5001/test_micro"
    r = requests.get(url=MICRO2URL)
    data = r.json()

    return data


@app.route('/test_micro', methods=(['GET']))
def test_micro():
    return "This is Microservice 1"


def create_db():
    conn = sqlite3.connect(db_name)

    with open(sql_file, 'r') as sql_startup:
        init_db = sql_startup.read()
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    return conn


def get_db():
    if not db_flag:
        create_db()
    conn = sqlite3.connect(db_name)
    return conn


@app.route('/clear', methods=(['GET']))
def clear_db():
    result = request.form

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM user;")

    conn.commit()
    conn.close()
    return result


def check_valid_password(username, first_name, last_name, password):
    valid_pw_lower = False
    valid_pw_upper = False
    valid_pw_num = False

    for char in password:
        if 97 <= ord(char) <= 122:
            valid_pw_lower = True
        elif 65 <= ord(char) <= 90:
            valid_pw_upper = True
        elif 48 <= ord(char) <= 57:
            valid_pw_num = True

    valid_password = valid_pw_num and valid_pw_upper and valid_pw_lower

    pw = password.lower()

    if len(password) >= 8 and username.lower() not in pw and first_name.lower() not in pw \
            and last_name.lower() not in pw and valid_password:
        return True
    return False


def jwt_token_generator(username):
    header = {"alg": "HS256", "typ": "JWT"}
    byte_header = json.dumps(header).encode()
    base64_header = base64.b64encode(byte_header).decode()  # encoded header

    payload = {'username': username}

    print(payload)
    byte_payload = json.dumps(payload).encode()
    base64_payload = base64.b64encode(byte_payload).decode()  # encoded payload

    signature_input = f"{base64_header}.{base64_payload}"

    with open('key.txt', 'r') as file:
        signature_key = file.read()

    # encoded signature
    signature = hmac.new(signature_key.encode(), signature_input.encode(), hashlib.sha256).hexdigest()

    jwt_token = f"{signature_input}.{signature}"  # jwt token
    return jwt_token


@app.route('/get_user', methods=(['GET']))
def get_user():
    conn = get_db()
    cursor = conn.cursor()
    username = request.args.get('username')

    cursor.execute("SELECT username, group_name FROM user WHERE username = ?", (username,))
    user_record = cursor.fetchone()

    conn.commit()
    conn.close()

    if user_record:
        json_output = {"username": user_record[0], "group": user_record[1]}
        return json.dumps(json_output)

    return '', 200


@app.route('/create_user', methods=(['POST']))
def create_user():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    username = request.form.get('username')
    email = request.form.get('email_address')
    group_name = request.form.get('group')
    password = request.form.get('password')
    salt = request.form.get('salt')

    conn = get_db()
    cursor = conn.cursor()
    # print(first_name, last_name, username, email, password, salt) -- testing purpose

    if not username:
        status_code = 2
        pass_encrypted = 'NULL'
    elif not email:
        status_code = 3
        pass_encrypted = 'NULL'
    elif check_valid_password(username, first_name, last_name, password):
        passkey = (password + salt).encode()
        pass_encrypted = hashlib.sha256(passkey).hexdigest()

        user_record = (first_name, last_name, username, email, group_name, pass_encrypted, salt)
        try:
            cursor.execute("INSERT INTO user (first_name, last_name, username, email, group_name, password, salt)"
                           "VALUES (?,?,?,?,?,?,?);", user_record)

            conn.commit()
            status_code = 1

            write_log_url = "http://micro-4:5003/write_log"
            write_log_param = {'username': username, 'event': 'user_creation'}
            r = requests.post(url=write_log_url, data=write_log_param)
        except sqlite3.IntegrityError as e:
            error_msg = str(e)

            if 'username' in error_msg:
                status_code = 2
                pass_encrypted = 'NULL'
            else:
                status_code = 3
                pass_encrypted = 'NULL'

    else:
        status_code = 4
        pass_encrypted = 'NULL'

    conn.commit()
    conn.close()

    json_output = {"status": status_code, "pass_hash": pass_encrypted}
    return json.dumps(json_output)


@app.route('/login', methods=(['POST']))  # handle moderator log in HERE
def user_login():
    conn = get_db()
    cursor = conn.cursor()
    jwt_token = 'NULL'

    username = request.form.get('username')
    password = request.form.get('password')

    if username and password:
        cursor.execute("SELECT username, password, salt FROM user WHERE username = ?", (username,))

        user_info = cursor.fetchone()
        if user_info:
            salt = user_info[2]
            passphrase = hashlib.sha256((password + salt).encode()).hexdigest()
            if passphrase == user_info[1]:
                status_code = 1
                jwt_token = jwt_token_generator(username)  # jwt token

                write_log_url = "http://micro-4:5003/write_log"
                write_log_param = {'username': username, 'event': 'login'}
                r = requests.post(url=write_log_url, data=write_log_param)
            else:
                print("Invalid password")
                status_code = 2
        else:
            status_code = 2
            print("Username is not existed")
    else:
        status_code = 2
        print("Username and password must be filled!")

    conn.commit()
    conn.close()

    json_output = {"status": status_code, "jwt": jwt_token}
    return json.dumps(json_output)
