import os
import uuid
from QUIC_API import QUIC_Protocol, IDGenerator


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.stream = None




