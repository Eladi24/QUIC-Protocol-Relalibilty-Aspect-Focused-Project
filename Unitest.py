import unittest
from QUIC_Client import QUIC_Client
from QUIC_Server import QUIC_Server
import threading
import os
import time
from QUIC_API import *


class TestQUICProtocol(unittest.TestCase):
    server_thread = None
    SERVER_PORT = 12000
    SERVER_ADDRESS = ('localhost', SERVER_PORT)
    ORIGINAL_FILE = '10MB_file.bin'
    lock = threading.Lock()

    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=cls.start_server)
        cls.server_thread.start()
        # Start the test file transfer

        # Give the server a moment to start up
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        # Make sure the server thread is finished
        cls.server_thread.join()
        # Clean up the original file
        os.remove(cls.ORIGINAL_FILE)

    @classmethod
    def start_server(cls):
        server = QUIC_Server(cls.SERVER_PORT)
        server.start_server()
        server.accept_connection()
        server.file_handshake_server()
        server.file_transfer()

    def test_file_transfer(self):
        client = QUIC_Client('localhost', self.SERVER_PORT)

        client.start_client()
        client.connect_to_server()
        client.request_file_handshake()
        client.file_transfer()

        # Check if the file was received
        self.assertTrue(os.path.exists('received_file.bin'))

        # Check if the size of the received file matches the original file
        original_file_size = os.path.getsize(self.ORIGINAL_FILE)
        received_file_size = os.path.getsize('received_file.bin')
        self.assertEqual(original_file_size, received_file_size)

        # Clean up received file
        os.remove('received_file.bin')


class TestQUICHandshake(unittest.TestCase):
    server_thread = None
    SERVER_PORT = 12000
    SERVER_ADDRESS = ('localhost', SERVER_PORT)
    lock = threading.Lock()

    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=cls.start_server)
        cls.server_thread.start()

        # Give the server a moment to start up
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        # Make sure the server thread is finished
        cls.server_thread.join()

    @classmethod
    def start_server(cls):
        server = QUIC_Server(cls.SERVER_PORT)
        server.start_server()
        server.accept_connection()
        server.serverSocket.close()

    def test_handshake(self):
        client = QUIC_Client('localhost', self.SERVER_PORT)
        client.start_client()
        result = client.connect_to_server()
        # Check if the file handshake was successful
        self.assertTrue(result)
        client.clientSocket.close()


class TestQUIC0RTTHandshake(unittest.TestCase):
    server_thread = None
    SERVER_PORT = 12000
    SERVER_ADDRESS = ('localhost', SERVER_PORT)
    lock = threading.Lock()

    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=cls.start_server)
        cls.server_thread.start()

        # Give the server a moment to start up
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        # Make sure the server thread is finished
        cls.server_thread.join()

    @classmethod
    def start_server(cls):
        server = QUIC_Server(cls.SERVER_PORT)
        server.start_server()
        server.accept_connection()
        server.file_handshake_server()
        server.serverSocket.close()

    def test_handshake(self):
        client = QUIC_Client('localhost', self.SERVER_PORT)
        client.start_client()
        result = client.connect_to_server()
        # Check if the file handshake was successful
        self.assertTrue(result)
        result = client.request_file_handshake()
        self.assertTrue(result)
        client.clientSocket.close()


class TestQUICConnectionClose(unittest.TestCase):
    server_thread = None
    SERVER_PORT = 12000
    SERVER_ADDRESS = ('localhost', SERVER_PORT)
    lock = threading.Lock()

    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=cls.start_server)
        cls.server_thread.start()

        # Give the server a moment to start up
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        # Make sure the server thread is finished
        cls.server_thread.join()

    @classmethod
    def start_server(cls):
        server = QUIC_Server(cls.SERVER_PORT)
        server.start_server()
        server.accept_connection()
        server.file_handshake_server()
        server.close_connection()

    def test_connection_close(self):
        client = QUIC_Client('localhost', self.SERVER_PORT)
        client.start_client()
        result = client.connect_to_server()
        # Check if the file handshake was successful
        self.assertTrue(result)
        result = client.request_file_handshake()
        self.assertTrue(result)
        result = client.close_connection()
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
