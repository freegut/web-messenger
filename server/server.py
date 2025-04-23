import asyncio
from aiohttp import web
import aioredis
import json

class ChatServer:
    def __init__(self):
        self.clients = {}
        self.redis = None

    async def init_redis(self):
        self.redis = await aioredis.from_url("redis://redis")

    async def websocket_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data["type"] == "register":
                    await self.register(ws, data)
                elif data["type"] == "message":
                    await self.broadcast(ws, data)

        return ws

    async def register(self, ws, data):
        username = data["username"]
        await self.redis.set(f"user:{username}:pubkey", data["pubkey"])
        self.clients[ws] = username

    async def broadcast(self, sender_ws, data):
        for ws, username in self.clients.items():
            if ws != sender_ws:
                await ws.send_json(data)

async def init_app():
    server = ChatServer()
    await server.init_redis()
    
    app = web.Application()
    app.router.add_get("/ws", server.websocket_handler)
    return app

if __name__ == "__main__":
    web.run_app(init_app(), port=8765)