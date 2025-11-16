# check_hash_matches_db.py
import pymysql, binascii, hashlib, sys, os

DB = dict(host="127.0.0.1", port=3306, user="chatuser", password="chatpass", database="securechat")
email = "m@gmail.com"
local_salt_file = f"salts/{email}.bin"   # if client saved it
password_guess = "123"                   # the password you used on client

conn = pymysql.connect(**DB, autocommit=True, cursorclass=pymysql.cursors.DictCursor)
with conn.cursor() as cur:
    cur.execute("SELECT HEX(salt) AS salt_hex, pwd_hash FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    if not row:
        print("No such user in DB"); sys.exit(1)
    db_salt_hex = row["salt_hex"]
    db_hash = row["pwd_hash"]
print("DB salt (hex):", db_salt_hex)
print("DB pwd_hash :", db_hash)

# If local salt file exists, compare
if os.path.exists(local_salt_file):
    with open(local_salt_file,"rb") as f:
        local_salt = f.read()
    print("Local salt (hex):", binascii.hexlify(local_salt).decode())
    recomputed = hashlib.sha256(local_salt + password_guess.encode()).hexdigest()
    print("Recomputed hash:", recomputed)
    print("Matches DB hash? ->", recomputed == db_hash)
else:
    print("Local salt file not found at", local_salt_file)
    print("If you don't have local salt, run the next step to export DB salt to a file for testing.")
