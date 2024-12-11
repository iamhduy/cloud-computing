import base64
import hashlib
import hmac
import sqlite3
import os
import json
import requests
from flask import Flask, request

app = Flask(__name__)

db_name = "documents.db"
sql_file = "documents.sql"
db_flag = False


@app.route('/', methods=(['GET']))
def index():
    return json.dumps({'1': 'test', '2': 'test2'})


@app.route('/test_micro', methods=(['GET']))
def test_micro():
    return json.dumps({"response": "This is a message from Microservice 2"})


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

    cursor.execute("DELETE FROM document;")
    cursor.execute("DELETE FROM group_doc;")

    conn.commit()
    conn.close()
    return result


@app.route('/create_document', methods=(['POST']))
def create_doc():
    token = request.headers['Authorization']

    # unpack jwt token here!!!!!
    username = jwt_decoder(token)['username']
    token_1 = jwt_token_generator(username)

    if token != token_1:
        return json.dumps({"status": 2})

    file_name = request.form.get('filename')
    body = request.form.get('body')
    groups = request.form.get('groups')
    group_dict = json.loads(groups)

    conn = get_db()
    cursor = conn.cursor()

    # Delete docs (if exist)
    cursor.execute("DELETE FROM document WHERE filename = ?", (file_name,))

    doc_record = (file_name, body, username)
    cursor.execute("INSERT INTO document (filename, body, owner) VALUES (?,?,?)", doc_record)

    for group_num, name in group_dict.items():
        group_record = (file_name, name)
        cursor.execute("INSERT INTO group_doc (doc_name, name) VALUES (?, ?)", group_record)

    conn.commit()
    conn.close()

    write_log_url = "http://micro-4:5003/write_log"
    write_log_param = {'username': username, 'event': 'document_creation', 'filename': file_name}
    r = requests.post(url=write_log_url, data=write_log_param)

    return json.dumps({"status": 1})


@app.route('/edit_document', methods=(['POST']))
def edit_doc():
    token = request.headers['Authorization']
    # unpack jwt token here!!!!!
    username = jwt_decoder(token)['username']
    token_1 = jwt_token_generator(username)

    if token != token_1:
        return json.dumps({"status": 2})

    get_user_url = "http://micro-1:5000/get_user"
    get_user_param = {'username': username}
    r = requests.get(url=get_user_url, params=get_user_param)
    if not r:
        return json.dumps({"status": 2})

    user_dict = r.json()
    user_group = user_dict['group']

    filename = request.form.get('filename')
    body = request.form.get('body')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, body FROM document WHERE filename = ?", (filename,))
    file_record = cursor.fetchone()

    cursor.execute("SELECT name FROM group_doc WHERE doc_name = ? AND name = ?",
                   (filename, user_group, ))
    group_record = cursor.fetchone()

    if not group_record:
        print("Unauthorized")
        return json.dumps({"status": 3})

    new_body = file_record[1] + body
    cursor.execute("UPDATE document SET body = ? WHERE filename = ?", (new_body, file_record[0],))

    conn.commit()
    conn.close()

    write_log_url = "http://micro-4:5003/write_log"
    write_log_param = {'username': username, 'event': 'document_edit', 'filename': filename}
    r = requests.post(url=write_log_url, data=write_log_param)

    return json.dumps({"status": 1})


@app.route('/get_doc', methods=(['GET']))
def get_document():
    filename = request.args.get('filename')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, body, owner FROM document WHERE filename = ?",
                   (filename,))
    file_record = cursor.fetchone()

    if not file_record:
        return '', 200

    cursor.execute("SELECT name FROM group_doc WHERE doc_name = ?", (filename,))
    group_record = cursor.fetchall()

    groups = list()
    for group in group_record:
        groups.append(group[0])

    json_output = {'filename': file_record[0], 'body': file_record[1], 'owner': file_record[2], 'groups': groups}

    conn.commit()
    conn.close()
    return json.dumps(json_output)
