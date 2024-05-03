import os
import uuid
from QUIC_API import QUIC_API, IDGenerator


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.stream = None
        # 16-bit client ID
        self.client_id = IDGenerator().generate_id()



