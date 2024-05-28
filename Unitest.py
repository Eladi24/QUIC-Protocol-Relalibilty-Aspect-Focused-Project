import unittest
from QUIC_Client import QUIC_Client  # Assuming QUIC_Client.py contains the ClientQUIC class
from QUIC_Server import QUIC_Server  # Assuming QUIC_Server.py contains the ServerQUIC class
# from QUIC_API import *
import threading
import time

class TestQUICFileTransfer(unittest.TestCase):
    def test_file_transfer(self):
        # Instantiate actual ServerQUIC and ClientQUIC objects
        server_quic = QUIC_Server()
        client_quic = QUIC_Client()

        # Run the server in a separate thread
        # Run the server
        server_quic = QUIC_Server()  # Instantiate the ser

        server_thread = threading.Thread(target=server_quic.start_server())# Start the server operation
        server_thread.start()

        # Give the server a moment to start
        time.sleep(1)

        # Run the client
        client_quic = QUIC_Client()  # Instantiate the client object
        client_quic.start_client()  # Start the client operation

        # Give some time for client-server interaction
        time.sleep(1)

        # Verify server sent the correct amount of data
        total_data_sent = server_quic.total_data_sent()  # Implement this method in your ServerQUIC class
        self.assertEqual(total_data_sent, 10 * 1024 * 1024)

        # Verify client received the correct amount of data
        total_data_received = client_quic.total_data_received()  # Implement this method in your ClientQUIC class
        self.assertEqual(total_data_received, 10 * 1024 * 1024)

        # Join the server thread
        server_thread.join()

if __name__ == '__main__':
    unittest.main()
