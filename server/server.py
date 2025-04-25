import asyncio
import websockets
import json
import sqlite3
import hashlib
import base64
import os
import datetime
import shutil
import redis
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

print("Starting server...")

# Получаем мастер-ключ из файла или переменной окружения
MASTER_KEY_DIR = "/app/master_key"
MASTER_KEY_PATH = os.path.join(MASTER_KEY_DIR, "master_key.txt")
MASTER_KEY = os.getenv("MASTER_KEY")

# Создаём директорию для мастер-ключа, если она не существует
if not os.path.exists(MASTER_KEY_DIR):
    os.makedirs(MASTER_KEY_DIR)
    print(f"Created directory {MASTER_KEY_DIR}")

if not MASTER_KEY:
    print("MASTER_KEY not set in environment, checking file...")
    # Если путь существует и это директория, удаляем её
    if os.path.exists(MASTER_KEY_PATH) and os.path.isdir(MASTER_KEY_PATH):
        print(f"{MASTER_KEY_PATH} is a directory, removing it...")
        shutil.rmtree(MASTER_KEY_PATH)
    
    # Проверяем файл
    try:
        with open(MASTER_KEY_PATH, "r") as f:
            MASTER_KEY = f.read().strip()
        print("MASTER_KEY loaded from file")
        # Если файл пустой, генерируем новый ключ
        if not MASTER_KEY:
            print("MASTER_KEY file is empty, generating a new one...")
            MASTER_KEY = Fernet.generate_key().decode()
            with open(MASTER_KEY_PATH, "w") as f:
                f.write(MASTER_KEY)
            print(f"New MASTER_KEY generated and saved to {MASTER_KEY_PATH}")
    except FileNotFoundError:
        print("MASTER_KEY file not found, generating a new one...")
        MASTER_KEY = Fernet.generate_key().decode()
        with open(MASTER_KEY_PATH, "w") as f:
            f.write(MASTER_KEY)
        print(f"New MASTER_KEY generated and saved to {MASTER_KEY_PATH}")

MASTER_FERNET = Fernet(MASTER_KEY.encode())
print("Master key initialized")

# Подключение к Redis
redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)

# Функция для генерации RSA-ключей
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Сериализуем публичный ключ в формат JWK
    public_numbers = public_key.public_numbers()
    public_jwk = {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, byteorder='big'
        )).decode('utf-8').rstrip('='),
        "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, byteorder='big'
        )).decode('utf-8').rstrip('='),
        "alg": "RSA-OAEP-256",
        "use": "enc"
    }
    
    # Сериализуем приватный ключ для хранения
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return json.dumps(public_jwk), private_pem

# Инициализация базы данных
def init_db():
    print("Initializing database...")
    db_path = "/app/chat.db"
    print(f"Opening database at {db_path}")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Таблица пользователей
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT,
                    is_admin INTEGER,
                    pubkey TEXT
                 )''')
    # Таблица конференций
    c.execute('''CREATE TABLE IF NOT EXISTS conferences (
                    conf_id TEXT,
                    username TEXT,
                    PRIMARY KEY (conf_id, username)
                 )''')
    # Таблица ключей конференций
    c.execute('''CREATE TABLE IF NOT EXISTS conference_keys (
                    conf_id TEXT PRIMARY KEY,
                    encryption_key TEXT
                 )''')
    # Таблица сообщений конференций
    c.execute('''CREATE TABLE IF NOT EXISTS conference_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conf_id TEXT,
                    sender TEXT,
                    encrypted_message TEXT,
                    timestamp TEXT
                 )''')
    # Добавление администратора
    admin_pubkey, admin_privkey = generate_rsa_keys()
    c.execute("INSERT OR IGNORE INTO users (username, password_hash, is_admin, pubkey) VALUES (?, ?, ?, ?)",
              ("admin", hashlib.sha256("WhereMainShell".encode()).hexdigest(), 1, admin_pubkey))
    redis_client.set(f"private_key:admin", admin_privkey)
    conn.commit()
    conn.close()
    print("Database initialized")

init_db()

# Хранилище подключений
connections = {}  # username -> websocket
public_keys = {}  # username -> pubkey

# Функции шифрования
def generate_conference_key():
    key = Fernet.generate_key().decode()
    encrypted_key = MASTER_FERNET.encrypt(key.encode()).decode()
    return key, encrypted_key

def encrypt_message(message, key):
    fernet = Fernet(key.encode())
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key.encode())
    return fernet.decrypt(encrypted_message.encode()).decode()

def decrypt_conference_key(encrypted_key):
    return MASTER_FERNET.decrypt(encrypted_key.encode()).decode()

async def handle_connection(websocket, path):
    print("New connection")
    username = None
    try:
        async for message in websocket:
            data = json.loads(message)
            print(f"Received message: {data}")

            if data["type"] == "login":
                username = data["username"]
                password_hash = hashlib.sha256(data["password"].encode()).hexdigest()
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))
                user = c.fetchone()

                if user:
                    session_token = base64.b64encode(os.urandom(16)).decode('utf-8')
                    connections[username] = websocket
                    public_keys[username] = user[3]  # pubkey
                    # Отправляем приватный ключ, если он есть в Redis
                    private_key = redis_client.get(f"private_key:{username}")
                    # Получаем публичные ключи всех пользователей
                    c.execute("SELECT username, pubkey FROM users")
                    all_public_keys = {row[0]: row[1] for row in c.fetchall() if row[1] and row[1] != "{}"}
                    for u, pk in all_public_keys.items():
                        public_keys[u] = pk
                    conn.close()
                    await websocket.send(json.dumps({
                        "type": "login_success",
                        "session_token": session_token,
                        "is_admin": bool(user[2]),
                        "private_key": private_key if private_key else None,
                        "public_keys": all_public_keys  # Отправляем все публичные ключи
                    }))
                    # Удаляем приватный ключ из Redis после отправки
                    if private_key:
                        redis_client.delete(f"private_key:{username}")
                    await broadcast_user_list()
                    # Отправляем полный список пользователей
                    conn = sqlite3.connect("/app/chat.db")
                    c = conn.cursor()
                    c.execute("SELECT username FROM users")
                    all_users = [row[0] for row in c.fetchall()]
                    conn.close()
                    print(f"Sending all users to {username} after login: {all_users}")
                    await websocket.send(json.dumps({
                        "type": "all_users",
                        "users": all_users
                    }))
                else:
                    conn.close()
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Invalid username or password"
                    }))

            elif data["type"] == "get_public_key":
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("SELECT pubkey FROM users WHERE username = ?", (data["username"],))
                result = c.fetchone()
                if result and result[0] and result[0] != "{}":
                    public_keys[data["username"]] = result[0]
                    await websocket.send(json.dumps({
                        "type": "public_key",
                        "username": data["username"],
                        "pubkey": result[0]
                    }))
                else:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"Public key for {data['username']} not found"
                    }))
                
                if "pubkey" in data:
                    public_keys[data["username"]] = data["pubkey"]
                    c.execute("UPDATE users SET pubkey = ? WHERE username = ?", (data["pubkey"], data["username"]))
                    conn.commit()
                    for ws in connections.values():
                        await ws.send(json.dumps({
                            "type": "public_key",
                            "username": data["username"],
                            "pubkey": data["pubkey"]
                        }))
                conn.close()

            elif data["type"] == "get_all_users":
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("SELECT username FROM users")
                all_users = [row[0] for row in c.fetchall()]
                conn.close()
                print(f"Sending all users to {username}: {all_users}")
                await websocket.send(json.dumps({
                    "type": "all_users",
                    "users": all_users
                }))

            elif data["type"] == "create_conference":
                conf_id = data["conf_id"]
                members = data["members"]
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("DELETE FROM conferences WHERE conf_id = ?", (conf_id,))
                for member in members:
                    c.execute("INSERT INTO conferences (conf_id, username) VALUES (?, ?)", (conf_id, member))
                c.execute("SELECT encryption_key FROM conference_keys WHERE conf_id = ?", (conf_id,))
                key = c.fetchone()
                if not key:
                    key, encrypted_key = generate_conference_key()
                    c.execute("INSERT INTO conference_keys (conf_id, encryption_key) VALUES (?, ?)",
                              (conf_id, encrypted_key))
                else:
                    key = decrypt_conference_key(key[0])
                conn.commit()
                conn.close()
                print(f"Creating conference {conf_id} with members: {members}")
                for member in members:
                    if member in connections:
                        print(f"Sending conference update: {json.dumps({'type': 'conference_update', 'conf_id': conf_id, 'members': members})}")
                        await connections[member].send(json.dumps({
                            "type": "conference_update",
                            "conf_id": conf_id,
                            "members": members
                        }))

            elif data["type"] == "conference_message":
                conf_id = data["conf_id"]
                encrypted_messages = data["encrypted_messages"]
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("SELECT encryption_key FROM conference_keys WHERE conf_id = ?", (conf_id,))
                key = c.fetchone()
                if not key:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Conference key not found"
                    }))
                    conn.close()
                    continue
                encryption_key = decrypt_conference_key(key[0])
                encrypted_message = encrypt_message(f"{username}: [Encrypted]", encryption_key)
                c.execute("INSERT INTO conference_messages (conf_id, sender, encrypted_message, timestamp) VALUES (?, ?, ?, ?)",
                          (conf_id, username, encrypted_message, datetime.datetime.now().isoformat()))
                c.execute("SELECT username FROM conferences WHERE conf_id = ?", (conf_id,))
                members = [row[0] for row in c.fetchall()]
                conn.commit()
                conn.close()
                for member in members:
                    if member == username:
                        continue
                    if member in connections:
                        await connections[member].send(json.dumps({
                            "type": "conference_message",
                            "conf_id": conf_id,
                            "from": username,
                            "text": encrypted_messages.get(member, "[Encrypted]")
                        }))

            elif data["type"] == "register_user":
                if username not in connections or not is_admin(username):
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Only admins can register users"
                    }))
                    continue
                new_user = data["username"]
                password_hash = hashlib.sha256(data["password"].encode()).hexdigest()
                is_admin_user = data["is_admin"]
                # Генерируем ключи для нового пользователя
                pubkey, privkey = generate_rsa_keys()
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                try:
                    c.execute("INSERT INTO users (username, password_hash, is_admin, pubkey) VALUES (?, ?, ?, ?)",
                              (new_user, password_hash, is_admin_user, pubkey))
                    # Сохраняем приватный ключ в Redis
                    redis_client.set(f"private_key:{new_user}", privkey)
                    conn.commit()
                    # Обновляем публичные ключи
                    public_keys[new_user] = pubkey
                    await websocket.send(json.dumps({
                        "type": "register_success",
                        "message": f"{new_user} registered successfully"
                    }))
                    # Обновляем список пользователей
                    c.execute("SELECT username FROM users")
                    all_users = [row[0] for row in c.fetchall()]
                    print(f"Sending all users to all clients after registration: {all_users}")
                    for ws in connections.values():
                        await ws.send(json.dumps({
                            "type": "all_users",
                            "users": all_users
                        }))
                    # Отправляем публичный ключ нового пользователя всем клиентам
                    for ws in connections.values():
                        await ws.send(json.dumps({
                            "type": "public_key",
                            "username": new_user,
                            "pubkey": pubkey
                        }))
                except sqlite3.IntegrityError:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"User {new_user} already exists"
                    }))
                conn.close()
                await broadcast_user_list()

            elif data["type"] == "change_password":
                if username not in connections or not is_admin(username):
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Only admins can change passwords"
                    }))
                    continue
                target_user = data["username"]
                new_password_hash = hashlib.sha256(data["password"].encode()).hexdigest()
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, target_user))
                if c.rowcount == 0:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"User {target_user} not found"
                    }))
                else:
                    await websocket.send(json.dumps({
                        "type": "change_password_success",
                        "message": f"Password changed for {target_user}"
                    }))
                conn.commit()
                conn.close()

            elif data["type"] == "delete_users":
                if username not in connections or not is_admin(username):
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Only admins can delete users"
                    }))
                    continue
                usernames = data["usernames"]
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                for user in usernames:
                    c.execute("DELETE FROM users WHERE username = ?", (user,))
                    c.execute("DELETE FROM conferences WHERE username = ?", (user,))
                    redis_client.delete(f"private_key:{user}")
                    if user in connections:
                        del connections[user]
                    if user in public_keys:
                        del public_keys[user]
                conn.commit()
                conn.close()
                await websocket.send(json.dumps({
                    "type": "delete_user_success",
                    "message": f"Deleted users: {', '.join(usernames)}"
                }))
                await broadcast_user_list()
                # Обновляем список пользователей
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("SELECT username FROM users")
                all_users = [row[0] for row in c.fetchall()]
                conn.close()
                print(f"Sending all users to all clients after deletion: {all_users}")
                for ws in connections.values():
                    await ws.send(json.dumps({
                        "type": "all_users",
                        "users": all_users
                    }))

            elif data["type"] == "get_conferences":
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("SELECT DISTINCT conf_id FROM conferences WHERE username = ?", (username,))
                conf_ids = [row[0] for row in c.fetchall()]
                conferences = {}
                for conf_id in conf_ids:
                    c.execute("SELECT username FROM conferences WHERE conf_id = ?", (conf_id,))
                    members = [row[0] for row in c.fetchall()]
                    conferences[conf_id] = members
                conn.close()
                await websocket.send(json.dumps({
                    "type": "conference_list",
                    "conferences": conferences
                }))

            elif data["type"] == "get_conference_messages":
                conf_id = data["conf_id"]
                conn = sqlite3.connect("/app/chat.db")
                c = conn.cursor()
                c.execute("SELECT encryption_key FROM conference_keys WHERE conf_id = ?", (conf_id,))
                key = c.fetchone()
                if not key:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Conference key not found"
                    }))
                    conn.close()
                    continue
                encryption_key = decrypt_conference_key(key[0])
                c.execute("SELECT sender, encrypted_message, timestamp FROM conference_messages WHERE conf_id = ? ORDER BY timestamp",
                          (conf_id,))
                messages = c.fetchall()
                decrypted_messages = []
                for sender, encrypted_message, timestamp in messages:
                    try:
                        decrypted_message = decrypt_message(encrypted_message, encryption_key)
                        decrypted_messages.append({
                            "from": sender,
                            "text": decrypted_message,
                            "timestamp": timestamp
                        })
                    except Exception as e:
                        print(f"Error decrypting message: {e}")
                        decrypted_messages.append({
                            "from": sender,
                            "text": "[Decryption Failed]",
                            "timestamp": timestamp
                        })
                conn.close()
                await websocket.send(json.dumps({
                    "type": "conference_messages",
                    "conf_id": conf_id,
                    "messages": decrypted_messages
                }))

    except websockets.exceptions.ConnectionClosed:
        print("Connection closed")
    finally:
        if username in connections:
            del connections[username]
            await broadcast_user_list()

async def broadcast_user_list():
    online_users = list(connections.keys())
    print(f"Broadcasting online users: {online_users}")
    for ws in connections.values():
        await ws.send(json.dumps({
            "type": "user_list",
            "users": online_users
        }))

def is_admin(username):
    conn = sqlite3.connect("/app/chat.db")
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result and result[0]

print("Starting WebSocket server on ws://0.0.0.0:8765")
start_server = websockets.serve(handle_connection, "0.0.0.0", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()