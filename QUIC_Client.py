import os
import uuid
from socket import *
from QUIC_API import *
# from QUIC_API_Based_number_packet import *
# from QUIC_API_Based_time import *
import struct


class QUIC_Client:

    def __init__(self, server_name, server_port):
        self.server_name = server_name
        self.server_port = server_port
        self.server_address = (self.server_name, self.server_port)
        self.total_bytes_received = 0
        self.quic_connection = None
        self.clientSocket = None

    def start_client(self):
        MAX_TIME_WAIT = 1
        timeout_microseconds = 0
        timeout = MAX_TIME_WAIT + timeout_microseconds / 1_000_000
        self.clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        self.clientSocket.setsockopt(SOL_SOCKET, SO_RCVTIMEO,
                                     struct.pack('ll', int(MAX_TIME_WAIT), int(timeout_microseconds)))
        print("Start the QUIC client...")

        self.quic_connection = QUIC_Protocol(self.clientSocket, self.server_address)
        print("Created the QUIC connection object")

    def connect_to_server(self):
        print("Connected to the server")
        return self.quic_connection.QUIC_connect(self.server_address)

    def request_file_handshake(self):
        return self.quic_connection.request_file_handshake()

    def file_transfer(self):
        # Size of the file is 10MB
        FILE_SIZE = 10 * 1024 * 1024
        # A buffer to store the file content (50,000 kilobytes)
        BUFFER_SIZE = 60 * 1024
        # Receive the file
        while True:
            bytes_received = 0
            self.total_bytes_received = 0
            # A binary buffer to store the file content
            file_buffer = []

            # Receive the file
            with open('received_file.bin', 'wb') as f:
                while self.total_bytes_received < FILE_SIZE:
                    bytes_received = self.quic_connection.QUIC_receive_data(file_buffer, BUFFER_SIZE,
                                                                            self.server_address)
                    self.total_bytes_received += bytes_received
                    # Write the received data to a file
                    for data in file_buffer:
                        f.write(data)
                    # print(f"Received {bytes_received} bytes")
                    # Clear the buffer
                    file_buffer.clear()
            print(f"Total bytes received: {self.total_bytes_received}")
            if self.total_bytes_received >= FILE_SIZE:
                print("File received successfully")

                break
        self.close_connection()

    def close_connection(self):
        self.quic_connection.QUIC_close_connection(True)
        self.clientSocket.close()
        print("Connection closed")
        return True


if __name__ == '__main__':
    serverName = 'localhost'
    serverPort = 12000
    SERVER_ADDRESS = (serverName, serverPort)
    client_quic = QUIC_Client(serverName, serverPort)
    client_quic.start_client()
    client_quic.connect_to_server()
    client_quic.request_file_handshake()
    client_quic.file_transfer()
