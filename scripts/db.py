# server/db.py
import pymysql
import os

# read DB connection from env (do not commit creds)
DB_HOST = os.getenv("DB_HOST","127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT","3306"))
DB_USER = os.getenv("DB_USER","root")
DB_PASS = os.getenv("DB_PASS","")
DB_NAME = os.getenv("DB_NAME","securechat")

def get_conn():
    return pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                           password=DB_PASS, database=DB_NAME, autocommit=True,
                           cursorclass=pymysql.cursors.DictCursor)

def create_user(email, username, salt_bytes, pwd_hash_hex, cert_cn=None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            sql = "INSERT INTO users (email, username, salt, pwd_hash, cert_cn) VALUES (%s,%s,%s,%s,%s)"
            cur.execute(sql, (email, username, salt_bytes, pwd_hash_hex, cert_cn))
    return True

def get_user_by_email(email):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            return cur.fetchone()

def get_user_by_username(username):
    with get_conn() as conn():
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cur.fetchone()
