import unittest
from QUIC_Client import QUIC_Client
from QUIC_Server import QUIC_Server
import threading
import os
import time

class TestQUICProtocol(unittest.TestCase):
    SERVER_PORT = 12000
    SERVER_ADDRESS = ('localhost', SERVER_PORT)
    ORIGINAL_FILE = 'original_file.bin'

    @classmethod
    def setUpClass(cls):
        # Create a large file for testing
        with open(cls.ORIGINAL_FILE, 'wb') as f:
            f.write(b'\0' * (10 * 1024 * 1024))  # 10MB of null bytes

        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=cls.start_server)
        cls.server_thread.start()
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

    def test_file_transfer(self):
        client = QUIC_Client('localhost', self.SERVER_PORT)
        client.start_client()

        # Check if the file was received
        self.assertTrue(os.path.exists('received_file.bin'))

        # Check if the size of the received file matches the original file
        original_file_size = os.path.getsize(self.ORIGINAL_FILE)
        received_file_size = os.path.getsize('received_file.bin')
        self.assertEqual(original_file_size, received_file_size)

        # Clean up received file
        os.remove('received_file.bin')


if __name__ == '__main__':
    unittest.main()

