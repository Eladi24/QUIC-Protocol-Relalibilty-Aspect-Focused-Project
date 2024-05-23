import struct
from socket import *
import time
import Utils
from QUIC_API import *

# Description: This file contains the QUIC server class.
# This class is representing the QUIC server.
# Gap 40960 bytes of 10MB file. Gap 8192 bytes of 2MB file.
# A gap of 25/64% loss rate.
# A buffer to store the file content (50,000 kilobytes)
BUFFER_SIZE = 60 * 1024
# Size of the file is 10MB
FILE_SIZE = 10 * 1024 * 1024
MAX_TIME_WAIT = 1
timeout_microseconds = 0

# Convert the timeout to the required structure
timeout = MAX_TIME_WAIT + timeout_microseconds / 1_000_000
# Create the random file
Utils.generate_random_file('10MB_file.bin', FILE_SIZE)
# The server address
serverPort = 12000
SERVER_ADDRESS = ('', serverPort)
# Create a UDP socket
serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
serverSocket.bind(SERVER_ADDRESS)
# Set the socket option to set the maximum wait time for the recvfrom(2) call.
serverSocket.setsockopt(SOL_SOCKET, SO_RCVTIMEO, struct.pack('ll', int(MAX_TIME_WAIT), int(timeout_microseconds)))
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
    # Start counting the time
    start_time = time.time()
    with open('10MB_file.bin', 'rb') as f:
        while True:
            data = f.read(BUFFER_SIZE)
            if not data:
                break
            bytes_sent = quic_connection.QUIC_send_data(data, quic_connection.client_address)
            total_bytes_sent += bytes_sent
    print(f"Total bytes sent: {total_bytes_sent}")
    if total_bytes_sent >= FILE_SIZE:
        print("File sent successfully")
    end_time = time.time()
    break
quic_connection.QUIC_close_connection(False)
serverSocket.close()
# Calculate the time
time_taken = end_time - start_time
total_mb = total_bytes_sent / (1024 * 1024)
total_bands = total_mb / time_taken
print(f"Time taken to send the file: {time_taken} seconds")
print(f"Total bandwidth: {total_bands} MB/s")
