from socket import *
import ssl
import os
import uuid

"""
This class represents the QUIC API.
It includes the functions to establish the connection, send and receive data, and close the connection.
The class also includes the functions to handle packet loss and recovery mechanism.
"""


class QUICPacket:
    def __init__(self, packet_number, frames, long_header=None, short_header=None):
        self.packet_number = packet_number
        self.frames = frames
        self.long_header = long_header
        self.short_header = short_header


class QUICLongHeader:
    def __init__(self, version, packet_type, length, sequence_number, ack_number, data):
        self.version = version
        self.packet_type = packet_type
        self.length = length
        self.sequence_number = sequence_number
        self.ack_number = ack_number
        self.data = data


class QUICShortHeader:
    def __init__(self, packet_type, length, sequence_number):
        self.packet_type = packet_type
        self.length = length
        self.sequence_number = sequence_number


class QUICFrame:
    def __init__(self, frame_type, data):
        self.frame_type = frame_type
        self.data = data

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


class QUIC_API:
    # Singleton class to have only one active stream at a time.
    _instance = None

    def __new__(cls, socket_fd, server_address, client_address):
        if cls._instance is None:
            cls._instance = super(QUIC_API, cls).__new__(cls)
            cls._instance.protocol = None
            cls._instance.stream_id = 0
        return cls._instance

    def __init__(self, socket_fd, server_address: None, client_address: None):
        self.socket_fd = socket_fd
        self.server_address = server_address
        self.client_address = client_address
        self.connection_id = 0

    """
    This function establishes the connection with the server.
    It establishes the connection according to the QUIC protocol handshake.
    It sends the connection request to the server and waits for the response.
    
    Parameters:
    ip(String): The IP address of the server.
    port(int): The port number of the server.
    client_id(int): The client ID.
    
    Returns:
    int: 1 if the connection is established successfully, -1 otherwise.
    """

    def QUIC_connect(self, ip, port, client_id):
        # Send an initial packet to the server with the client ID
        initial_packet = QUICPacket(0, [QUICFrame("client_id", client_id)])
        self.socket_fd.sendto(initial_packet, (ip, port))

        # If a Retry token is provided, include it in the packet
        if self.server_address is not None:
            initial_packet.frames.append(QUICFrame("token", self.server_address))

        # Receive a Retry packet from the server
        retry_packet, server_address = self.socket_fd.recvfrom(2048)

        # Verify the server's address and the token in the Retry packet
        if server_address == self.server_address and retry_packet.long_header.packet_type == "retry":
            # Send a new Initial packet to the server with the token
            new_initial_packet = QUICPacket(1, [QUICFrame("token", retry_packet.data)])
            self.socket_fd.sendto(new_initial_packet, (ip, port))

            # Perform a TLS 1.3 handshake to establish the shared secret
            self.tls_handshake_client()

    """
    This function accepts the connection from the client.
    It accepts the connection request from the client according to the QUIC protocol handshake.
    
    Returns:
    int: A new QUIC socket that is connected to the client if the connection is accepted successfully, -1 otherwise.
    """

    def QUIC_accept_connection(self, server_id):
        # Receive the initial packet from the client
        initial_packet, client_address = self.socket_fd.recvfrom(2048)

        # Verify the client's address and the client ID in the Initial packet
        if client_address == self.client_address and initial_packet.frames[0].data == server_id:
            # Generate a token and include it in the Retry packet
            token = self.generate_token()
            retry_packet = QUICPacket(0, [QUICFrame("token", token)])
            self.socket_fd.sendto(retry_packet, client_address)

            # Receive the new Initial packet from the client
            new_initial_packet, client_address = self.socket_fd.recvfrom(2048)

            # Perform a TLS 1.3 handshake to establish the shared secret
            self.tls_handshake_server()
            # Return a new QUIC socket that is connected to the client
            return QUIC_API(self.socket_fd, self.server_address, client_address)



    """
    This function sends data from one peer to another.
    It sends the data and makes sure that the data is received by the receiver.
    Handles the packet loss and recovery mechanism.
    
    Parameters:
    data(String): The data to be sent.
    
    Returns:
    int: The number of bytes sent if the data is sent successfully, 0 if the receiver disconnects, -1 otherwise. 
    """

    def QUIC_send_data(self, data):
        pass

    """
    This function receives data from the sender. It receives the data and sends the acknowledgement to the sender.
    
    Returns:
    int: The number of bytes received if the data is received successfully, 0 if the sender disconnects, -1 otherwise.
    """

    def QUIC_receive_data(self):
        pass

    """
    This function closes the connection between the two peers.
    
    Returns:
    int: 0 if the connection is closed successfully, -1 otherwise and  errno is set appropriately.
    """

    def QUIC_close_connection(self):
        pass

    """
    
    """

    def QUIC_handle_packet_loss(self):
        pass

    """
    This function implements the recovery mechanism in case of packet loss and reordering in the network.
    It includes both loss detection and congestion control.
    
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
        pass

    def tls_handshake_client(self):
        try:
            # Create a new SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # Use the context to establish a TLS session
            with context.wrap_socket(self.socket_fd, server_hostname=self.server_address) as secured_sock:
                # Display the TLS version used
                print(secured_sock.version())
        except ssl.SSLError as e:
            print(f"SSL error occurred: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    def tls_handshake_server(self):
        try:
            # Create a new SSL context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            # Use the context to establish a TLS session
            with context.wrap_socket(self.socket_fd, server_side=True) as secured_sock:
                # Display the TLS version used
                print(secured_sock.version())
        except ssl.SSLError as e:
            print(f"SSL error occurred: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

        # If the server is not able to establish the connection, return -1
        if self.server_address is None:
            return -1
        else:
            return 0

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
