from redis.asyncio import Redis
from aiohttp import web
import json
import aiohttp_cors
import bcrypt
import secrets

class ChatServer:
    def __init__(self):
        self.clients = {}  # {ws: username}
        self.sessions = {}  # {session_token: username}
        self.redis = None
        self.conferences = {}  # {conf_id: {admin: username, members: set(usernames)}}

    async def init_redis(self):
        self.redis = Redis.from_url("redis://redis", decode_responses=True)

    async def websocket_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    print(f"Received message: {data}")
                    if data["type"] == "login":
                        await self.login_user(ws, data)
                    elif data["type"] == "register_user" and await self.is_admin(ws):
                        await self.register_user(ws, data)
                    elif data["type"] == "change_password" and await self.is_admin(ws):
                        await self.change_password(ws, data)
                    elif data["type"] == "delete_users" and await self.is_admin(ws):
                        await self.delete_users(ws, data)
                    elif data["type"] == "message":
                        await self.send_message(ws, data)
                    elif data["type"] == "create_conference" and await self.is_admin(ws):
                        await self.create_conference(ws, data)
                    elif data["type"] == "conference_message":
                        await self.send_conference_message(ws, data)
                    elif data["type"] == "get_public_key":
                        await self.get_public_key(ws, data)
                    elif data["type"] == "get_all_users":
                        await self.get_all_users(ws)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            await self.remove_client(ws)
        return ws

    async def is_admin(self, ws):
        username = self.clients.get(ws)
        if not username:
            return False
        is_admin = await self.redis.get(f"user:{username}:is_admin")
        return is_admin == "true"

    async def register_user(self, ws, data):
        username = data["username"]
        password = data["password"]
        pubkey = data["pubkey"]
        is_admin = data.get("is_admin", False)
        
        if await self.redis.exists(f"user:{username}:password"):
            await ws.send_json({
                "type": "error",
                "message": "Username already exists"
            })
            return
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        await self.redis.set(f"user:{username}:password", hashed.decode('utf-8'))
        await self.redis.set(f"user:{username}:pubkey", pubkey)
        if is_admin:
            await self.redis.set(f"user:{username}:is_admin", "true")
        
        await ws.send_json({
            "type": "register_success",
            "message": f"User {username} registered"
        })

    async def change_password(self, ws, data):
        target_username = data["username"]
        new_password = data["password"]
        
        if not await self.redis.exists(f"user:{target_username}:password"):
            await ws.send_json({
                "type": "error",
                "message": f"User {target_username} not found"
            })
            return
        
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        await self.redis.set(f"user:{target_username}:password", hashed.decode('utf-8'))
        
        await ws.send_json({
            "type": "change_password_success",
            "message": f"Password changed for {target_username}"
        })

    async def delete_users(self, ws, data):
        usernames = data["usernames"]
        deleted = []
        
        for username in usernames:
            if await self.redis.exists(f"user:{username}:password"):
                await self.redis.delete(f"user:{username}:password")
                await self.redis.delete(f"user:{username}:pubkey")
                await self.redis.delete(f"user:{username}:is_admin")
                deleted.append(username)
        
        await ws.send_json({
            "type": "delete_user_success",
            "message": ", ".join(deleted) if deleted else "None"
        })

    async def login_user(self, ws, data):
        username = data["username"]
        password = data["password"]
        print(f"Login attempt: {username}")
        
        stored_hash = await self.redis.get(f"user:{username}:password")
        if stored_hash and bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            print(f"Login successful: {username}")
            session_token = secrets.token_hex(32)
            self.sessions[session_token] = username
            self.clients[ws] = username
            is_admin = await self.redis.get(f"user:{username}:is_admin") == "true"
            await ws.send_json({
                "type": "login_success",
                "session_token": session_token,
                "is_admin": is_admin
            })
            await self.broadcast_user_list()
        else:
            print(f"Login failed: {username}")
            await ws.send_json({
                "type": "error",
                "message": "Invalid username or password"
            })

    async def send_message(self, sender_ws, data):
        sender = self.clients.get(sender_ws)
        recipients = data["recipients"]
        encrypted_messages = data["encrypted_messages"]
        print(f"Sending message from {sender} to {recipients}")
        
        for recipient in recipients:
            recipient_ws = None
            for ws, username in self.clients.items():
                if username == recipient:
                    recipient_ws = ws
                    break
            
            if recipient_ws:
                can_send = True
                for conf_id, conf in self.conferences.items():
                    if sender in conf["members"] and recipient in conf["members"]:
                        can_send = False
                        break
                
                if can_send:
                    await recipient_ws.send_json({
                        "type": "message",
                        "from": sender,
                        "text": encrypted_messages[recipient]
                    })
                else:
                    await sender_ws.send_json({
                        "type": "error",
                        "message": "Private messaging restricted in conference"
                    })
            else:
                await sender_ws.send_json({
                    "type": "error",
                    "message": f"User {recipient} not found"
                })

    async def send_conference_message(self, sender_ws, data):
        sender = self.clients.get(sender_ws)
        conf_id = data["conf_id"]
        encrypted_messages = data["encrypted_messages"]
        print(f"Sending conference message in {conf_id} from {sender}")
        
        if conf_id not in self.conferences:
            await sender_ws.send_json({
                "type": "error",
                "message": "Conference not found"
            })
            return
        
        for ws, username in self.clients.items():
            if username in self.conferences[conf_id]["members"] and username != sender:
                encrypted_message = encrypted_messages.get(username)
                if encrypted_message:
                    await ws.send_json({
                        "type": "conference_message",
                        "conf_id": conf_id,
                        "from": sender,
                        "text": encrypted_message
                    })

    async def create_conference(self, sender_ws, data):
        conf_id = data["conf_id"]
        members = data["members"]
        admin = self.clients.get(sender_ws)
        print(f"Creating conference {conf_id} with members: {members}")
        
        valid_members = set()
        for username in members:
            if await self.redis.exists(f"user:{username}:pubkey"):
                valid_members.add(username)
        
        valid_members.add(admin)
        self.conferences[conf_id] = {
            "admin": admin,
            "members": valid_members
        }
        
        for ws, username in self.clients.items():
            if username in self.conferences[conf_id]["members"]:
                await ws.send_json({
                    "type": "conference_update",
                    "conf_id": conf_id,
                    "members": list(self.conferences[conf_id]["members"])
                })

    async def get_public_key(self, ws, data):
        username = data["username"]
        pubkey = await self.redis.get(f"user:{username}:pubkey")
        await ws.send_json({
            "type": "public_key",
            "username": username,
            "pubkey": pubkey if pubkey else ""
        })

    async def get_all_users(self, ws):
        keys = await self.redis.keys("user:*:password")
        users = [key.split(":")[1] for key in keys]
        await ws.send_json({
            "type": "all_users",
            "users": users
        })

    async def remove_client(self, ws):
        if ws in self.clients:
            username = self.clients[ws]
            del self.clients[ws]
            await self.broadcast_user_list()

    async def broadcast_user_list(self):
        users = list(self.clients.values())
        print(f"Broadcasting user list: {users}")
        for ws in self.clients:
            await ws.send_json({
                "type": "user_list",
                "users": users
            })

async def init_app():
    server = ChatServer()
    await server.init_redis()
    
    app = web.Application()
    route = app.router.add_get("/ws", server.websocket_handler, name="ws")
    
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        )
    })
    cors.add(route)
    
    return app

if __name__ == "__main__":
    web.run_app(init_app(), port=8765)