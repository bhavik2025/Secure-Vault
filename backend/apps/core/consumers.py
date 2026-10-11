from channels.generic.websocket import AsyncJsonWebsocketConsumer


class PingConsumer(AsyncJsonWebsocketConsumer):
    """Foundation-only smoke test for the ASGI/Channels stack.

    Carries no user data. It is replaced by an authenticated event consumer in the
    lockdown/real-time phase, where the session is verified in `connect`.
    """

    async def connect(self):
        await self.accept()
        await self.send_json({"type": "pong", "status": "ok"})

    async def receive_json(self, content, **kwargs):
        await self.send_json({"type": "pong", "status": "ok"})
