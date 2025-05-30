import requests
import hashlib
from passlib.hash import md5_crypt
import xml.etree.ElementTree as ET

def get_salt(username):
    url = "https://webshare.cz/api/salt/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    data = {
        "username_or_email": username
    }
    response = requests.post(url, headers=headers, data=data, timeout=10)
    print(f"[DEBUG] SALT response: {response.text}")
    root = ET.fromstring(response.content)
    salt = root.findtext("salt")
    if not salt:
        err = root.findtext("message")
        print(f"[DEBUG] ERROR GETTING SALT: {err}")
        return None
    print(f"[DEBUG] SALT: {salt}")
    return salt

def hash_password(user_name, password, salt):
    # Passlib hash
    md5_pass = md5_crypt.using(salt=salt).hash(password)
    print(f"[DEBUG] passlib md5_crypt: {md5_pass}")
    password_sha1 = hashlib.sha1(md5_pass.encode('utf-8')).hexdigest()
    print(f"[DEBUG] password (SHA1(md5_crypt)): {password_sha1}")
    digest_str = f"{user_name}:Webshare:{password_sha1}"
    print(f"[DEBUG] Digest str: {digest_str}")
    digest = hashlib.md5(digest_str.encode('utf-8')).hexdigest()
    print(f"[DEBUG] digest: {digest}")
    return password_sha1, digest

def webshare_login(user_name, password):
    salt = get_salt(user_name)
    if not salt:
        print("Could not get salt, aborting login.")
        return
    password_hash, digest = hash_password(user_name, password, salt)
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
    url = "https://webshare.cz/api/login/"
    data = {
        'username_or_email': user_name,
        'password': password_hash,
        'digest': digest,
        'keep_logged_in': 1
    }
    print(f"[DEBUG] LOGIN POST data: {data}")
    response = requests.post(url, data=data, headers=headers, timeout=10)
    print(f"[DEBUG] LOGIN response: {response.text}")
    root = ET.fromstring(response.content)
    status = root.findtext('status')
    if status != "OK":
        message = root.findtext('message')
        code = root.findtext('code')
        print(f"[LOGIN ERROR] status={status}, code={code}, message={message}")
        return
    token = root.findtext('token')
    print(f"[LOGIN OK] token: {token}")

if __name__ == "__main__":
    username = input("Webshare meno/email: ").strip()
    password = input("Webshare heslo: ").strip()
    webshare_login(username, password)
