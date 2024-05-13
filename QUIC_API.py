from socket import *
import ssl
import os
import uuid
import hashlib
from QUIC_Packet import *

"""
This project represents the QUIC protocol.
This project focuses on the reliability aspect of the protocol.
Meaning that the aspects of security, encryption, flow control and multiple streams are not implemented.
It includes the functions to establish the connection, send and receive data, and close the connection.
The class also includes the functions to handle packet loss and recovery mechanism.
"""

"""
This class generates unique IDs for the clients and the servers.
It generates a 16-bit ID for each client and server.
Each ID is unique and is not used by any other client or server.
"""


class IDGenerator:
    def __init__(self):
        self.used_ids = set()

    def generate_id(self):
        while True:
            new_id = uuid.uuid4().int & (1 << 16) - 1
            if new_id not in self.used_ids:
                self.used_ids.add(new_id)
                return new_id


class QUIC_Protocol:

    def __init__(self, socket_fd, server_address: None, client_address: None, is_client: False):
        self.socket_fd = socket_fd
        self.server_address = server_address
        self.client_address = client_address
        self.is_client = is_client
        self.connection_id = 0
        if is_client:
            self.QUIC_connect(server_address, client_address)
        else:
            self.QUIC_accept_connection()

    """
    This function establishes the connection with the server.
    It establishes the connection according to the QUIC protocol handshake focusing on the reliability aspect.
    It supports the basic handshake mechanism without the advanced features and security aspects.
    Meaning that CID, tls 1.3 handshake, retry packet and token generation are not implemented. 
    It sends the connection request to the server and waits for the response.
    The handshake supports 0-RTT and 1-RTT.
    The steps are as follows:
    1. Send the initial client hello packet to the server.
    2. Receive the initial response from the server.
    
    
    
    Parameters:
    ip(String): The IP address of the server.
    port(int): The port number of the server.
    
    Returns:
    int: 1 if the connection is established successfully, -1 otherwise.
    """

    def QUIC_connect(self, ip, port):
        # Create the long header for the initial packet
        long_header = QUICLongHeader("Initial", "Client Hello", "1.0")
        # Create the message for the initial packet
        message = "Client Hello"
        # Create the frame for the initial packet
        message.encode()
        stream_frame = QUICStreamFrame("Stream", message, len(message))
        total_frames = [stream_frame]
        # Create the packet for the initial packet
        initial_packet = QUICPacket(long_header, total_frames)
        # Send the initial packet to the server
        if self.socket_fd.sendto(initial_packet, (ip, port)) == -1:
            return -1
        # Receive the initial response from the server
        initial_response, server_address = self.socket_fd.recvfrom(2048)
        # If the server address is not set, set it to the server address
        if self.server_address is None:
            self.server_address = server_address
        # Receive the handshake complete packet from the server
        handshake_complete_packet, server_address = self.socket_fd.recvfrom(2048)
        # Send ack frame for the response packet
        ack_frame = QUICAckFrame("Ack", 0, 0, 0, 0, 0, 0)
        long_header = QUICLongHeader("Long", "Initial", "1.0")
        total_frames = [ack_frame]
        ack_packet = QUICPacket(long_header, total_frames)
        if self.socket_fd.sendto(ack_packet, server_address) == -1:
            return -1
        # Send ack frame for the handshake complete packet
        ack_frame = QUICAckFrame("Ack", 0, 0, 0, 0, 0, 0)
        long_header = QUICLongHeader("Long", "Handshake", "1.0")
        total_frames = [ack_frame]
        ack_packet = QUICPacket(long_header, total_frames)
        if self.socket_fd.sendto(ack_packet, server_address) == -1:
            return -1
        # If the handshake complete packet is received, the connection is established
        return 1

    """
    This function accepts the connection from the client.
    It accepts the connection request from the client according to the QUIC protocol handshake.
    It supports the basic handshake mechanism without the advanced features and security aspects.
    Meaning that CID, tls 1.3 handshake, retry packet and token generation are not implemented. 
    It sends the connection response to the client
    The handshake supports 0-RTT and 1-RTT.
    The steps are as follows:
    1. Receive the initial packet from the client.
    2. Send the initial response to the client.
    3. Send the handshake complete packet to the client with finish message.
    Returns:
    int: 1 if the connection is accepted successfully, -1 otherwise.
    """

    def QUIC_accept_connection(self):
        # Receive the initial packet from the client
        initial_packet, client_address = self.socket_fd.recvfrom(2048)
        # If the client address is not set, set it to the client address
        if self.client_address is None:
            self.client_address = client_address
        # Create the long header for the response packet
        long_header = QUICLongHeader("Long", "Initial", "1.0")
        # Create the message for the response packet
        message = "Server Hello"
        # Create the frames for the response packet. Stream frame and ack frame
        stream_frame = QUICStreamFrame("Stream", message, len(message))
        ack_frame = QUICAckFrame("Ack", 0, 0, 0, 0, 0, 0)
        total_frames = [stream_frame, ack_frame]
        response_packet = QUICPacket(long_header, total_frames)
        # Send the response packet to the client
        if self.socket_fd.sendto(response_packet, client_address) == -1:
            return -1
        # Create the long header for the handshake complete packet
        long_header = QUICLongHeader("Long", "Handshake", "1.0")
        # Create the message for the handshake complete packet
        message = "Finished"
        # Create the frame for the handshake complete packet
        stream_frame = QUICStreamFrame("Stream", message, len(message))
        total_frames = [stream_frame]
        # Create the packet for the handshake complete packet
        handshake_complete_packet = QUICPacket(long_header, total_frames)
        # Send the handshake complete packet to the client
        if self.socket_fd.sendto(handshake_complete_packet, client_address) == -1:
            return -1
        # Receive the ack frame for the response packet
        ack_packet, client_address = self.socket_fd.recvfrom(2048)
        # Receive the ack frame for the handshake complete packet
        ack_packet, client_address = self.socket_fd.recvfrom(2048)
        # If the handshake complete packet is received, the connection is established
        return 1

    """
    This function sends data from one peer to another.
    It takes the data and copy it to the frames.
    It sends the data and makes sure that the data is received by the receiver.
    Handles the packet loss and recovery mechanism.
    
    Parameters:
    data(String): The data to be sent.
    receiver_address(Tuple): The address of the receiver.
    size(double): The size of the data to be sent.
    
    Returns:
    int: The number of bytes sent if the data is sent successfully, 0 if the receiver disconnects, -1 otherwise. 
    """

    def QUIC_send_data(self, data, receiver_address, size):
        # Create short header for the data packet
        header = QUICHeader("Short")


    """
    This function receives data from the sender. It receives the data and sends the acknowledgement to the sender.
    
    Returns:
    int: The number of bytes received if the data is received successfully, 0 if the sender disconnects, -1 otherwise.
    """

    def QUIC_receive_data(self):
        # Receive a packet from the sender
        packet, sender_address = self.socket_fd.recvfrom(2048)
        # If the address has changed but the CID is the same, this is a potential connection migration
        if sender_address != self.client_address and packet.cid == self.connection_id:
            # Send a PATH_CHALLENGE packet to the new address
            self.send_path_challenge(sender_address)
            # Receive a PATH_RESPONSE packet from the new address

    def send_path_challenge(self, new_address):
        # Generate a random payload
        payload = os.urandom(8)
        # Create a PATH_CHALLENGE frame with the payload
        frame = QUICFrame("PATH_CHALLENGE", payload)
        # Send the frame to the new address
        self.socket_fd.sendto(frame, new_address)
        # Store the payload for later verification
        self.path_challenge_payload = payload

    def handle_path_response(self, frame):
        # If the PATH_RESPONSE payload matches the PATH_CHALLENGE payload, this confirms the new address
        if frame.data == self.path_challenge_payload:
            # Update the client address to the new address
            self.client_address = frame.address

    """
    This function closes the connection between the two peers.
    
    Returns:
    int: 0 if the connection is closed successfully, -1 otherwise and  errno is set appropriately.
    """

    def QUIC_close_connection(self):
        pass

    """
    This function handles the packet loss in the network.
    
    """

    def QUIC_handle_packet_loss(self):
        pass

    """
    This function implements the recovery mechanism in case of packet loss and reordering in the network.
    It includes both loss detection and recovery mechanisms.
    The recovery mechanism includes the following steps:
    1. Detect the lost packets.
    2. Detect the reordered packets.
    3. Implement the recovery mechanism.
    Parameters:
    
    Returns:
    
    """

    def QUIC_recovery(self):
        pass

    """
    This function generates a connection ID (CID).
    The connection ID is used to identify the connection between the two peers.
    Each peer provides a number and the function combines them to create a unique connection ID.
    
    Parameters:
    client_id(int): The client ID.
    server_id(int): The server ID.
    
    Returns:
    int: The connection ID.
    """

    def generate_connection_id(self, client_id, server_id):
        # Concatenate the client ID and the server ID
        combined_id = str(client_id) + str(server_id)
        # Hash the combined ID to create a unique connection ID
        connection_id = hashlib.sha256(combined_id.encode()).hexdigest()
        return connection_id

    def generate_random_file(filename, size):
        """
        Generate a file with random content.

        :param filename: Name of the file to be created.
        :param size: Size of the file in bytes.
        """
        with open(filename, 'wb') as f:
            f.write(os.urandom(size))

    # Usage:
    # generate_random_file('random_file.txt', 1024)  # Creates a file with 1024 random bytes
