import asyncio
import websockets
import json
import sqlite3
import hashlib
import base64
import os
import datetime
from cryptography.fernet import Fernet

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect("chat.db")
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
    c.execute("INSERT OR IGNORE INTO users (username, password_hash, is_admin, pubkey) VALUES (?, ?, ?, ?)",
              ("admin", hashlib.sha256("WhereMainShell".encode()).hexdigest(), 1, "{}"))
    conn.commit()
    conn.close()

init_db()

# Хранилище подключений
connections = {}  # username -> websocket
public_keys = {}  # username -> pubkey

# Функции шифрования
def generate_conference_key():
    return Fernet.generate_key().decode()

def encrypt_message(message, key):
    fernet = Fernet(key.encode())
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    fernet = Fernet(key.encode())
    return fernet.decrypt(encrypted_message.encode()).decode()

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
                conn = sqlite3.connect("chat.db")
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))
                user = c.fetchone()
                conn.close()

                if user:
                    session_token = base64.b64encode(os.urandom(16)).decode('utf-8')
                    connections[username] = websocket
                    public_keys[username] = user[3]  # pubkey
                    await websocket.send(json.dumps({
                        "type": "login_success",
                        "session_token": session_token,
                        "is_admin": bool(user[2])
                    }))
                    await broadcast_user_list()
                else:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Invalid username or password"
                    }))

            elif data["type"] == "get_public_key":
                if data["username"] in public_keys:
                    await websocket.send(json.dumps({
                        "type": "public_key",
                        "username": data["username"],
                        "pubkey": public_keys[data["username"]]
                    }))
                if "pubkey" in data:
                    public_keys[data["username"]] = data["pubkey"]
                    conn = sqlite3.connect("chat.db")
                    c = conn.cursor()
                    c.execute("UPDATE users SET pubkey = ? WHERE username = ?", (data["pubkey"], data["username"]))
                    conn.commit()
                    conn.close()

            elif data["type"] == "message":
                for recipient in data["recipients"]:
                    if recipient in connections:
                        await connections[recipient].send(json.dumps({
                            "type": "message",
                            "from": username,
                            "text": data["encrypted_messages"][recipient]
                        }))

            elif data["type"] == "create_conference":
                conf_id = data["conf_id"]
                members = data["members"]
                conn = sqlite3.connect("chat.db")
                c = conn.cursor()
                # Удаляем старую конференцию
                c.execute("DELETE FROM conferences WHERE conf_id = ?", (conf_id,))
                # Добавляем участников
                for member in members:
                    c.execute("INSERT INTO conferences (conf_id, username) VALUES (?, ?)", (conf_id, member))
                # Генерируем ключ шифрования, если его нет
                c.execute("SELECT encryption_key FROM conference_keys WHERE conf_id = ?", (conf_id,))
                key = c.fetchone()
                if not key:
                    encryption_key = generate_conference_key()
                    c.execute("INSERT INTO conference_keys (conf_id, encryption_key) VALUES (?, ?)",
                              (conf_id, encryption_key))
                conn.commit()
                conn.close()
                print(f"Creating conference {conf_id} with members: {members}")
                # Отправка обновления всем участникам
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
                conn = sqlite3.connect("chat.db")
                c = conn.cursor()
                # Получаем ключ шифрования конференции
                c.execute("SELECT encryption_key FROM conference_keys WHERE conf_id = ?", (conf_id,))
                key = c.fetchone()
                if not key:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Conference key not found"
                    }))
                    conn.close()
                    continue
                encryption_key = key[0]
                # Сохраняем сообщение в зашифрованном виде
                # Для примера зашифруем исходное сообщение от отправителя
                encrypted_message = encrypt_message(f"{username}: [Encrypted]", encryption_key)
                c.execute("INSERT INTO conference_messages (conf_id, sender, encrypted_message, timestamp) VALUES (?, ?, ?, ?)",
                          (conf_id, username, encrypted_message, datetime.datetime.now().isoformat()))
                # Получаем участников конференции
                c.execute("SELECT username FROM conferences WHERE conf_id = ?", (conf_id,))
                members = [row[0] for row in c.fetchall()]
                conn.commit()
                conn.close()
                # Отправляем сообщение участникам
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
                pubkey = data["pubkey"]
                conn = sqlite3.connect("chat.db")
                c = conn.cursor()
                try:
                    c.execute("INSERT INTO users (username, password_hash, is_admin, pubkey) VALUES (?, ?, ?, ?)",
                              (new_user, password_hash, is_admin_user, pubkey))
                    conn.commit()
                    await websocket.send(json.dumps({
                        "type": "register_success",
                        "message": f"{new_user} registered successfully"
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
                conn = sqlite3.connect("chat.db")
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
                conn = sqlite3.connect("chat.db")
                c = conn.cursor()
                for user in usernames:
                    c.execute("DELETE FROM users WHERE username = ?", (user,))
                    c.execute("DELETE FROM conferences WHERE username = ?", (user,))
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

            elif data["type"] == "get_conferences":
                conn = sqlite3.connect("chat.db")
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
                conn = sqlite3.connect("chat.db")
                c = conn.cursor()
                # Получаем ключ шифрования
                c.execute("SELECT encryption_key FROM conference_keys WHERE conf_id = ?", (conf_id,))
                key = c.fetchone()
                if not key:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Conference key not found"
                    }))
                    conn.close()
                    continue
                encryption_key = key[0]
                # Получаем сообщения
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
    for ws in connections.values():
        await ws.send(json.dumps({
            "type": "user_list",
            "users": online_users
        }))

def is_admin(username):
    conn = sqlite3.connect("chat.db")
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result and result[0]

start_server = websockets.serve(handle_connection, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()