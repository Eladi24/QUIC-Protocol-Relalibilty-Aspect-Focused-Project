import struct
from socket import *
import time
import Utils
from QUIC_API import *
# from QUIC_API_Based_number_packet import *
# from QUIC_API_Based_time import *


# Description: This file contains the QUIC server class.
# This class is representing the QUIC server.
# Gap 40960 bytes of 10MB file. Gap 8192 bytes of 2MB file.
# A gap of 25/64% loss rate.
# A buffer to store the file content (50,000 kilobytes)

class QUIC_Server:
    # The QUIC server class
    def __init__(self, server_port):
        # The constructor
        self.server_port = server_port
        self.server_address = ('', self.server_port)
        self.total_bytes_sent = 0
        self.quic_connection = None
        self.serverSocket = None

    def start_server(self):

        # Size of the file is 10MB
        FILE_SIZE = 10 * 1024 * 1024
        MAX_TIME_WAIT = 1
        timeout_microseconds = 0
        # Convert the timeout to the required structure
        timeout = MAX_TIME_WAIT + timeout_microseconds / 1_000_000
        # Create the random file
        Utils.generate_random_file('10MB_file.bin', FILE_SIZE)
        # Create a UDP socket
        self.serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        # Bind the socket to the server address
        self.serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.serverSocket.bind(self.server_address)
        # Set the socket option to set the maximum wait time for the recvfrom(2) call.
        self.serverSocket.setsockopt(SOL_SOCKET, SO_RCVTIMEO,
                                     struct.pack('ll', int(MAX_TIME_WAIT), int(timeout_microseconds)))
        
        print("Waiting for QUIC connection request from the client...")
        self.quic_connection = QUIC_Protocol(self.serverSocket, self.server_address)
        print("Created the QUIC connection object")

    def file_transfer(self):
        FILE_SIZE = 10 * 1024 * 1024
        BUFFER_SIZE = 60 * 1024
        while True:
            bytes_sent = 0
            bytes_received = 0
            self.total_bytes_sent = 0
            message_buffer = []

            # Read the file to buffer
            # Start counting the time
            start_time = time.time()
            with open('10MB_file.bin', 'rb') as f:
                while True:
                    data = f.read(BUFFER_SIZE)
                    if not data:
                        break
                    bytes_sent = self.quic_connection.QUIC_send_data(data, self.quic_connection.client_address)
                    self.total_bytes_sent += bytes_sent
            # print(f"Total bytes sent: {total_bytes_sent}")
            if self.total_bytes_sent >= FILE_SIZE:
                print("File sent successfully")
            end_time = time.time()
            break
        self.close_connection()
        # Calculate the time
        time_taken = end_time - start_time
        total_mb = self.total_bytes_sent / (1024 * 1024)
        total_bands = total_mb / time_taken
        print(f"Time taken to send the file: {time_taken} seconds")
        print(f"Total bandwidth: {total_bands} MB/s")

    def accept_connection(self):
        self.quic_connection.QUIC_accept_connection()

    def file_handshake_server(self):
        self.quic_connection.file_handshake_server()

    def close_connection(self):
        self.quic_connection.QUIC_close_connection(False)
        self.serverSocket.close()


if __name__ == '__main__':
    # The server port
    serverPort = 12000
    # Instantiate the server object
    server = QUIC_Server(serverPort)
    # Start the server
    server.start_server()
    # Accept the connection
    server.accept_connection()
    # Start the file transfer
    server.file_handshake_server()
    server.file_transfer()
