from socket import *

import Utils
from QUIC_API import *

# Description: This file contains the QUIC server class.
# This class is representing the QUIC server.

# A buffer to store the file content (50,000 kilobytes)
BUFFER_SIZE = 50*1024
# Size of the file is 10MB
FILE_SIZE = 10*1024*1024
# Create the random file
Utils.generate_random_file('10MB_file.bin', FILE_SIZE)
# The server address
serverPort = 12000
SERVER_ADDRESS = ('', serverPort)
# Create a UDP socket
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(SERVER_ADDRESS)
print("Waiting for QUIC connection request from the client...")
quic_connection = QUIC_Protocol(serverSocket, SERVER_ADDRESS)
quic_connection.QUIC_accept_connection()
quic_connection.file_handshake_server()

while True:
    bytes_sent = 0
    bytes_received = 0
    total_bytes_sent = 0
    message_buffer = []
    # Read the file to buffer
    while total_bytes_sent < FILE_SIZE:
        with open('10MB_file.bin', 'rb') as f:
            f.seek(bytes_sent)
            data = f.read(BUFFER_SIZE)
            bytes_sent = quic_connection.QUIC_send_data(data, quic_connection.client_address, BUFFER_SIZE)
            total_bytes_sent += len(data)
            print(f"Sent {len(data)} bytes")
    print(f"Total bytes sent: {total_bytes_sent}")
    # Receive the message from the client and store it
    bytes_received += quic_connection.QUIC_receive_data(message_buffer, BUFFER_SIZE, quic_connection.client_address)
    # If the message is goodbye, then break the loop
    for message in message_buffer:
        if message == "Goodbye":
            break
quiconnection.QUIC_close_connection(False)










