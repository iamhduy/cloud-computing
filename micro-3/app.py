import base64
import hashlib
import hmac
import sqlite3
import os
import json
import requests
from flask import Flask, request

app = Flask(__name__)


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


@app.route('/clear', methods=(['GET']))
def clear_db():
    return 'Nothing to clear', 200


@app.route('/search', methods=(['GET']))
def search():
    filename = request.args.get('filename')

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

    get_user_url = "http://micro-2:5001/get_doc"
    get_user_param = {'filename': filename}
    r = requests.get(url=get_user_url, params=get_user_param)
    doc_dict = r.json()
    groups = doc_dict['groups']

    if user_group not in groups:
        print("Unauthorized")
        return json.dumps({"status": 3, 'data': 'NULL'})

    filename = doc_dict['filename']
    body = doc_dict['body']
    owner = doc_dict['owner']

    get_user_url = "http://micro-4:5003/search_log"
    get_user_param = {'filename': filename}
    r = requests.get(url=get_user_url, params=get_user_param)
    log_dict = r.json()
    print(log_dict)
    last_mod = log_dict['last_mod']
    total_mod = log_dict['total_mod']

    file_name1 = "temp.txt"
    with open(file_name1, "w", newline='\n') as file:
        file.write(body)

    with open(file_name1, 'rb', buffering=0) as file:
        hash_file = hashlib.file_digest(file, 'sha256').hexdigest()

    os.remove(file_name1)

    data = {
        "filename": filename,
        "owner": owner,
        "last_mod": last_mod,
        "total_mod": total_mod,
        "hash": hash_file
    }

    write_log_url = "http://micro-4:5003/write_log"
    write_log_param = {'username': username, 'event': 'document_search', 'filename': filename}
    r = requests.post(url=write_log_url, data=write_log_param)

    json_output = {'status': 1, 'data': data}
    return json.dumps(json_output)
