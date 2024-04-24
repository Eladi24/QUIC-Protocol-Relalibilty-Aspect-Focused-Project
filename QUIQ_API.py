import asyncio
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.stream import open_connection

class QUICClient:
    _active_stream = None  # Singleton because we want only one stream

    def __new__(cls, new_stream):  # singleton
        if cls._active_stream is None:  # If an instance does not exist -> create a new one
            cls._active_stream = super().__new__(cls)  # super -> from Object class
        return cls._active_stream

    def __init__(self, new_stream):
        if not hasattr(self, 'stream'):
            self.host = host
            self.port = port
            self.protocol = None


    async def connect(self):
        self.protocol = await connect(
            self.host,
            self.port,
            configuration=QuicConnectionProtocol,
        )

    async def send_data(self, data):
        if self.protocol is None:
            raise Exception("Not connected to server")

        stream = await open_connection(
            (self.host, self.port),
            configuration=self.protocol.configuration,
        )
        await stream.sendall(data.encode())
        await stream.aclose()

    async def receive_data(self):
        if self.protocol is None:
            raise Exception("Not connected to server")

        stream = await open_connection(
            (self.host, self.port),
            configuration=self.protocol.configuration,
        )
        data = await stream.read()
        await stream.aclose()
        return data