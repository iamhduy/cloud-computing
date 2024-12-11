import base64
import hashlib
import hmac
import sqlite3
import os
import json
import requests
from flask import Flask, request

app = Flask(__name__)

db_name = "logs.db"
sql_file = "logs.sql"
db_flag = False


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


def jwt_decoder(jwt):
    payload_encoded = jwt.split('.')[1]
    payload_json = base64.b64decode(payload_encoded).decode()
    return json.loads(payload_json)


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

    cursor.execute("DELETE FROM log;")

    conn.commit()
    conn.close()
    return result


@app.route('/write_log', methods=(['POST']))
def write_log():
    username = request.form.get('username')
    filename = request.form.get('filename')
    event_type = request.form.get('event')
    print(username, filename, event_type)
    conn = get_db()
    cursor = conn.cursor()

    if not filename:
        filename = 'NULL'

    log = (username, event_type, filename)
    cursor.execute("INSERT INTO log (username, event, filename) VALUES (?,?,?);", log)

    conn.commit()
    conn.close()

    return json.dumps({'status': 1})


@app.route('/view_log', methods=(['GET']))
def view_log():
    token = request.headers['Authorization']

    decoded_username = jwt_decoder(token)['username']
    token1 = jwt_token_generator(decoded_username)

    username = request.args.get('username')
    filename = request.args.get('filename')

    if token != token1:
        return json.dumps({'status': 2, 'data': 'NULL'})

    if username and username != decoded_username:
        print("Unauthorized to view this user")
        return json.dumps({'status': 3, 'data': 'NULL'})

    get_user_url = "http://micro-1:5000/get_user"
    get_user_param = {'username': decoded_username}
    r = requests.get(url=get_user_url, params=get_user_param)
    user_dict = r.json()
    user_group = user_dict['group']

    if filename:
        get_user_url = "http://micro-2:5001/get_doc"
        get_user_param = {'filename': filename}
        r = requests.get(url=get_user_url, params=get_user_param)
        doc_dict = r.json()
        groups = doc_dict['groups']

        if user_group not in groups:
            print("Unauthorized to view this doc")
            return json.dumps({"status": 3, 'data': 'NULL'})

    conn = get_db()
    cursor = conn.cursor()

    if username:
        cursor.execute("SELECT * FROM log WHERE username = ?;", (username, ))
    else:
        cursor.execute("SELECT * FROM log WHERE filename = ?;", (filename, ))

    logs = cursor.fetchall()
    log_dict = dict()
    for i in range(len(logs)):
        log_record = logs[i]
        event_dict = {"event": log_record[2], "user": log_record[1], "filename": log_record[3]}
        log_dict[int(i+1)] = event_dict

    conn.commit()
    conn.close()

    json_output = {'status': 1, 'data': log_dict}
    return json.dumps(json_output)


@app.route('/search_log', methods=(['GET']))
def search_log():
    filename = request.args.get('filename')
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM log WHERE filename = ? "
                   "AND event IN ('document_creation', 'document_edit') "
                   "ORDER BY id DESC;", (filename, ))

    modification_record = cursor.fetchone()
    last_mod_user = modification_record[0]

    cursor.execute("SELECT COUNT(*) FROM log WHERE event IN ('document_creation', 'document_edit') "
                   "AND filename = ?;", (filename, ))

    modification_count = cursor.fetchone()[0]

    json_output = {'last_mod': last_mod_user, 'total_mod': modification_count}
    print(json_output)
    return json.dumps(json_output)
