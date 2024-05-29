import os
import uuid
from socket import *
from QUIC_API import *
import struct


class QUIC_Client:

    def __init__(self, server_name, server_port):
        self.server_name = server_name
        self.server_port = server_port
        self.server_address = (self.server_name, self.server_port)

    def start_client(self):
        # A buffer to store the file content (50,000 kilobytes)
        BUFFER_SIZE = 60 * 1024
        # Size of the file is 10MB
        FILE_SIZE = 10 * 1024 * 1024
        MAX_TIME_WAIT = 1
        timeout_microseconds = 0
        timeout = MAX_TIME_WAIT + timeout_microseconds / 1_000_000
        clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        clientSocket.setsockopt(SOL_SOCKET, SO_RCVTIMEO,
                                struct.pack('ll', int(MAX_TIME_WAIT), int(timeout_microseconds)))
        print("Start the QUIC client...")
        quic_connection = QUIC_Protocol(clientSocket, self.server_address)
        quic_connection.QUIC_connect(self.server_address)
        quic_connection.request_file_handshake()

        # Receive the file
        while True:
            bytes_received = 0
            total_bytes_received = 0
            # A binary buffer to store the file content
            file_buffer = []

            # Receive the file
            with open('received_file.bin', 'wb') as f:
                while total_bytes_received < FILE_SIZE:
                    bytes_received = quic_connection.QUIC_receive_data(file_buffer, BUFFER_SIZE, SERVER_ADDRESS)
                    total_bytes_received += bytes_received
                    # Write the received data to a file
                    for data in file_buffer:
                        f.write(data)
                    # print(f"Received {bytes_received} bytes")
                    # Clear the buffer
                    file_buffer.clear()
            print(f"Total bytes received: {total_bytes_received}")
            if total_bytes_received >= FILE_SIZE:
                print("File received successfully")

            break
        quic_connection.QUIC_close_connection(True)
        clientSocket.close()


if __name__ == '__main__':
    serverName = 'localhost'
    serverPort = 12000
    SERVER_ADDRESS = (serverName, serverPort)
    client_quic = QUIC_Client(serverName, serverPort)
    client_quic.start_client()
