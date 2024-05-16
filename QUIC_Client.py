import os
import uuid
from socket import *
from QUIC_API import *
# A buffer to store the file content (50,000 kilobytes)
BUFFER_SIZE = 50*1024
# Size of the file is 10MB
FILE_SIZE = 10*1024*1024
serverName = 'localhost'
serverPort = 12000
SERVER_ADDRESS = (serverName, serverPort)
clientSocket = socket(AF_INET, SOCK_DGRAM)
print("Start the QUIC client...")
quic_connection = QUIC_Protocol(clientSocket, True, SERVER_ADDRESS)
quic_connection.QUIC_connect(SERVER_ADDRESS)
quic_connection.request_file_handshake()
# Receive the file
while True:
    bytes_received = 0
    total_bytes_received = 0
    # A binary buffer to store the file content
    file_buffer = []
    # Receive the file
    while total_bytes_received < FILE_SIZE:
        bytes_received = quic_connection.QUIC_receive_data(file_buffer, BUFFER_SIZE, SERVER_ADDRESS)
        total_bytes_received += bytes_received
        # Write the received data to a file
        with open('received_file.bin', 'wb') as f:
            for data in file_buffer:
                f.write(data)
        print(f"Received {bytes_received} bytes")
    print(f"Total bytes received: {total_bytes_received}")
    # Send the goodbye message
    message = "Goodbye"
    # Read the message to buffer
    quic_connection.QUIC_send_data(message, SERVER_ADDRESS, len(message))
    break
quic_connection.QUIC_close_connection(True)









