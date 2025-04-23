import bcrypt
password = b'WhereMainShell'
hashed = bcrypt.hashpw(password, bcrypt.gensalt(12))
print(hashed.decode('utf-8'))
