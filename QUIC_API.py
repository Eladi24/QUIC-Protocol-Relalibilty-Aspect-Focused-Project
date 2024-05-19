from socket import *
import ssl
import os
import uuid
import hashlib
import Utils
from QUIC_Packet import *
import pickle
import time
from Utils import *
import threading

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


class QUIC_Protocol:
    FRAME_SIZE = 65447  # Maximum frame size after subtracting protocol overhead
    PACKET_THRESHOLD = 3
    # Time Threshold >= 1 packet AND time > 9/8 * max(SRTT, latest_RTT)

    MAX_UDP_SIZE = 65507

    def __init__(self, socket_fd, server_address, client_address=None):
        self.socket_fd = socket_fd
        self.server_address = server_address
        self.client_address = client_address
        self.packet_number_generator = QUICHeader.packet_number_generator()
        self.largest_acknowledged = 0
        self.acked_packets = {}
        # Create a map set of packet numbers as keys and the frames as values
        self.in_flight_packets = {}
        self.ack_ranges = []
        # Stores the send times of each packet
        self.packet_send_times = {}
        # The estimated network RTT
        self.smoothed_rtt = 0
        # The variation in the RTT samples
        self.latest_rtt = 0
        # Timer for the Probe Timeout (PTO) period
        self.pto_timer = None
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

    def QUIC_connect(self, server_address):
        self.server_address = server_address
        # Create the long header for the initial packet
        long_header = QUICLongHeader("Initial", "Client Hello", next(self.packet_number_generator))
        # Create the message for the initial packet
        message = "Client Hello"
        # Create the frame for the initial packet
        stream_frame = QUICStreamFrame("Stream", message, len(message))
        total_frames = [stream_frame]
        # Create the packet for the initial packet
        initial_packet = QUICPacket(long_header, total_frames)
        print(f"Initial Packet number: {initial_packet.get_packet_number()}")
        # Serialize the initial packet with pickle
        initial_packet = pickle.dumps(initial_packet)
        # Send the initial packet to the server
        if self.socket_fd.sendto(initial_packet, server_address) < 0:
            raise Exception("Error: The initial packet is not sent.")
        print("Connection request sent to the server, waiting for the response.")
        # Set timeout for the socket if the response is not received
        #self.socket_fd.settimeout(5.0)

        # Receive the initial response from the server
        initial_response, _ = self.socket_fd.recvfrom(2048)
        # If the server address is not set, set it to the server address

        # Deserialize the initial response with pickle
        initial_response = pickle.loads(initial_response)
        # Check if the frames contain the ack frame
        print(f"Initial response received from the server: {initial_response}")

        # Receive the handshake complete packet from the server
        handshake_complete_packet, server_address = self.socket_fd.recvfrom(2048)
        # Deserialize the handshake complete packet with pickle
        handshake_complete_packet = pickle.loads(handshake_complete_packet)

        print(f"Handshake complete packet received from the server: {handshake_complete_packet}")
        # Send ack frame for the response packet
        ack_frame = QUICAckFrame("Ack", self.largest_acknowledged, 0, self.ack_ranges)
        long_header = QUICLongHeader("Long", "Initial", next(self.packet_number_generator))
        total_frames = [ack_frame]
        ack_packet = QUICPacket(long_header, total_frames)
        print(f"Ack packet number: {ack_packet.get_packet_number()}")
        ack_packet = pickle.dumps(ack_packet)
        if self.socket_fd.sendto(ack_packet, server_address) == -1:
            raise Exception("Error: The ack frame is not sent.")
        print("Ack frame sent for the response packet.")
        # Send ack frame for the handshake complete packet
        ack_frame = QUICAckFrame("Ack", self.largest_acknowledged, 0, self.ack_ranges)
        long_header = QUICLongHeader("Long", "Handshake", next(self.packet_number_generator))
        total_frames = [ack_frame]
        ack_packet = QUICPacket(long_header, total_frames)
        ack_packet = pickle.dumps(ack_packet)
        if self.socket_fd.sendto(ack_packet, server_address) == -1:
            raise Exception("Error: The ack frame is not sent.")
        # If the handshake complete packet is received, the connection is established
        print(f"Connection established with the server: {server_address}")
        # Reset the largest acknowledged
        self.largest_acknowledged = 0

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
        # Deserialize the initial packet with pickle
        initial_packet = pickle.loads(initial_packet)
        self.largest_ack_update(initial_packet)
        print(f"Initial packet received from the client: {initial_packet}")
        # Create the long header for the response packet
        long_header = QUICLongHeader("Long", "Initial", next(self.packet_number_generator))
        # Create the message for the response packet
        message = "Server Hello"
        # Create the frames for the response packet. Stream frame and ack frame
        stream_frame = QUICStreamFrame("Stream", message, len(message))
        ack_frame = QUICAckFrame("Ack", self.largest_acknowledged, 0, self.ack_ranges)
        total_frames = [stream_frame, ack_frame]
        response_packet = QUICPacket(long_header, total_frames)
        print(f"Response packet number: {response_packet.get_packet_number()}")
        # Serialize the response packet with pickle
        response_packet = pickle.dumps(response_packet)
        # Send the response packet to the client
        if self.socket_fd.sendto(response_packet, client_address) == -1:
            raise Exception("Error: The response packet is not sent.")
        print("Response packet sent to the client.")
        # Create the long header for the handshake complete packet
        long_header = QUICLongHeader("Long", "Handshake", next(self.packet_number_generator))
        # Create the message for the handshake complete packet
        message = "Finished"
        # Create the frame for the handshake complete packet
        stream_frame = QUICStreamFrame("Stream", message, len(message))
        total_frames = [stream_frame]
        # Create the packet for the handshake complete packet
        handshake_complete_packet = QUICPacket(long_header, total_frames)
        print(f"Handshake complete packet number: {handshake_complete_packet.get_packet_number()}")
        # Serialize the handshake complete packet with pickle
        handshake_complete_packet = pickle.dumps(handshake_complete_packet)
        # Send the handshake complete packet to the client
        if self.socket_fd.sendto(handshake_complete_packet, client_address) == -1:
            raise Exception("Error: The handshake complete packet is not sent.")
        print("Handshake complete packet sent to the client.")
        # Receive the ack frame for the response packet
        ack_packet, client_address = self.socket_fd.recvfrom(2048)
        # Deserialize the ack packet with pickle
        ack_packet = pickle.loads(ack_packet)
        self.largest_ack_update(ack_packet)
        print(f"Ack frame received for the response packet: {ack_packet}")
        # Receive the ack frame for the handshake complete packet
        ack_packet, client_address = self.socket_fd.recvfrom(2048)
        # Deserialize the ack packet with pickle
        ack_packet = pickle.loads(ack_packet)
        self.largest_ack_update(ack_packet)
        print(f"Ack frame received for the handshake complete packet: {ack_packet}")
        # If the handshake complete packet is received, the connection is established
        print(f"Connection established with the client: {client_address}")
        # Reset the largest acknowledged
        self.largest_acknowledged = 0
        return client_address

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

    def QUIC_send_data(self, data, receiver_address):
        bytes_sent = 0
        # Create short header for the data packet
        header = QUICHeader("Short", next(self.packet_number_generator))
        # Create the frame for the data packet
        frames = self.divide_into_frames(data, self.FRAME_SIZE)
        # Create ACK frame for the data packet
        ack_frame = QUICAckFrame("Ack", self.largest_acknowledged, 0, self.ack_ranges)
        total_frames = frames + [ack_frame]
        # Create the data packet
        data_packet = QUICPacket(header, total_frames)
        # Serialize the data packet with pickle
        ser_paket = pickle.dumps(data_packet)
        # Check the size of the data packet
        bytes_size_packet = Utils.calculate_bytes(ser_paket)
        bytes_size_data = Utils.calculate_bytes(data)
        print(f"Data size: {bytes_size_data}")
        if bytes_size_packet > self.MAX_UDP_SIZE:
            raise ValueError("Error: The data packet size is too large.")

        # Send the data packet to the receiver and start the timer
        send_time = time.time()
        self.packet_send_times[data_packet.get_packet_number()] = send_time
        # self.start_pto_timer(data_packet.get_packet_number(), receiver_address)
        bytes_sent = self.socket_fd.sendto(ser_paket, receiver_address)
        if bytes_sent < 0:
            raise Exception("Error: The data packet is not sent.")
        self.in_flight_packets[data_packet.get_packet_number()] = data_packet.frames
        print(f"Data packet sent to the receiver: {data_packet.get_packet_number()}")
        # Receive the ack packet from the receiver
        ack_packet, _ = self.socket_fd.recvfrom(self.MAX_UDP_SIZE)
        # Deserialize the ack packet with pickle
        ack_packet = pickle.loads(ack_packet)
        # If the method returns true, the packet is lost and the recovery mechanism is initiated
        if not self.QUIC_detect_and_handle_loss(receiver_address, ack_packet, data_packet.get_packet_number()):
            ack_time = time.time()
            self.latest_rtt = ack_time - send_time
            print(f"Round-trip time:{self.latest_rtt} seconds")
            if self.smoothed_rtt == 0:
                self.smoothed_rtt = self.latest_rtt
            else:
                self.smoothed_rtt = 7 / 8 * self.smoothed_rtt + 1 / 8 * self.latest_rtt
        print(f"Bytes sent: {bytes_sent}")
        return bytes_size_data

    """
    This function receives data from the sender. It receives the data and sends the acknowledgement to the sender.
    
    Returns:
    int: The number of bytes received if the data is received successfully, 0 if the sender disconnects, -1 otherwise.
    """

    def QUIC_receive_data(self, data_buffer, buffer_size, sender_address):
        # Receive the packet from the sender
        packet, _ = self.socket_fd.recvfrom(self.MAX_UDP_SIZE)
        # Deserialize the packet with pickle
        bytes_received = 0

        packet = pickle.loads(packet)
        recv_number = packet.get_packet_number()
        print(f"Packet received from the sender: {recv_number}")

        # Check if the packet is received
        if packet:
            bytes_received = self.process_packet(packet, data_buffer, buffer_size, sender_address)
            print(f"Bytes received: {bytes_received}")
        return bytes_received

    def process_packet(self, packet, data_buffer, buffer_size, sender_address):
        # Add the packet to the acked packets in the packet number index
        data_bytes_received = 0
        self.acked_packets[packet.get_packet_number()] = packet.frames
        print("Process packet")

        # Send the ack packet to the sender
        self.largest_ack_update(packet)
        ack_frame = QUICAckFrame("Ack", self.largest_acknowledged, 0, self.ack_ranges)
        short_header = QUICHeader("Short", next(self.packet_number_generator))
        total_frames = [ack_frame]
        ack_packet = QUICPacket(short_header, total_frames)
        ack_packet = pickle.dumps(ack_packet)
        if self.socket_fd.sendto(ack_packet, sender_address) == -1:
            raise Exception("Error: The ack packet is not sent.")
        print("Ack packet sent to the sender.")

        # Receive the data from the packet
        frames_size = Utils.calculate_bytes(packet.frames)
        print(f"Frames size {frames_size}")

        # Add the data to the buffer according to the buffer size
        for frame in packet.frames:
            if frame.get_frame_type() == "Stream":
                data_buffer.append(frame.data)
                data_bytes_received += frame.data_length
        print("Data added to the buffer.")
        return data_bytes_received

    def update_ack_ranges(self, packet_number):
        # If ack_ranges is empty, add the first range
        if not self.ack_ranges:
            self.ack_ranges.append(AckRange(0, (packet_number, packet_number)))
        else:
            # Check if the packet number fits into an existing range
            for i, ack_range in enumerate(self.ack_ranges):
                start, end = ack_range.ack_range
                if start <= packet_number <= end:
                    # The packet number is already in a range, no need to update
                    return
                elif packet_number == end + 1:
                    # The packet number extends the range by 1
                    ack_range.ack_range = (start, packet_number)
                    return
                elif packet_number == start - 1:
                    # The packet number extends the range by 1 at the start
                    ack_range.ack_range = (packet_number, end)
                    return
                elif packet_number > end + 1:
                    # Calculate the gap between the end of the range and the packet number
                    gap = packet_number - 1 - end - 1
                    # Create a new range with the gap
                    self.ack_ranges.insert(i + 1, AckRange(gap, (packet_number, packet_number)))
                    return
                elif packet_number < start - 1:
                    # Calculate the gap between the start of the range and the packet number
                    gap = start - 1 - packet_number - 1
                    # Create a new range with the gap
                    self.ack_ranges.insert(i, AckRange(gap, (packet_number, packet_number)))
                    return

            # If the packet number doesn't fit into any existing range, create a new range
            self.ack_ranges.append(AckRange(0, (packet_number, packet_number)))

    """
    This function closes the connection between the two peers.
    
    Returns:
    int: 0 if the connection is closed successfully, -1 otherwise and  errno is set appropriately.
    """

    def QUIC_close_connection(self, is_client):
        if is_client:
            # Create the long header for the close packet
            long_header = QUICLongHeader("Long", "Close", next(self.packet_number_generator))
            # Create the message for the close packet
            message = "Client Close"
            # Create the frame for the close packet
            stream_frame = QUICStreamFrame("Stream", message, len(message))
            total_frames = [stream_frame]
            # Create the packet for the close packet
            close_packet = QUICPacket(long_header, total_frames)
            # Serialize the close packet with pickle
            close_packet = pickle.dumps(close_packet)
            # Send the close packet to the server
            if self.socket_fd.sendto(close_packet, self.server_address) == -1:
                raise Exception("Error: The close packet is not sent.")
            print("Close packet sent to the server.")
            # Receive the response from the server
            response_packet, server_address = self.socket_fd.recvfrom(self.MAX_UDP_SIZE)
            # Deserialize the response with pickle
            response_packet = pickle.loads(response_packet)
            # Check if the ack packet is received
            for frame in response_packet.frames:
                if frame.get_frame_type() == "Ack":
                    print(f"Response received from the server")


        # Server case
        else:
            client_close_packet, _ = self.socket_fd.recvfrom(self.MAX_UDP_SIZE)
            client_close_packet = pickle.loads(client_close_packet)
            print("Client close packet received.")
            # Send the response packet to the client
            long_header = QUICLongHeader("Long", "Close", next(self.packet_number_generator))
            ack_frame = QUICAckFrame("Ack", self.largest_acknowledged, 0, 0)
            stream_frame = QUICStreamFrame("Stream", "Server Close", len("Server Close"))
            total_frames = [ack_frame, stream_frame]
            response_packet = QUICPacket(long_header, total_frames)
            response_packet = pickle.dumps(response_packet)
            if self.socket_fd.sendto(response_packet, self.client_address) == -1:
                raise Exception("Error: The response packet is not sent.")
            print("Response packet sent to the client.")

    """
    This function handles the packet loss in the network.
    
    """

    def QUIC_detect_and_handle_loss(self, receiver_address, ack_packet, date_packet_number):
        for frame in ack_packet.frames:
            if frame.get_frame_type() == "Ack":
                if frame.largest_acknowledged == date_packet_number:
                    print("Ack received for the data packet.")
                    # Remove the packet from the in-flight packets
                    self.in_flight_packets.pop(date_packet_number)
                    return False
                elif frame.largest_acknowledged > date_packet_number:
                    print("Packet loss detected.")
                    # Find the previous range of the largest acknowledged and compare the gap with the threshold
                    for ack_range in self.ack_ranges:
                        start, end = ack_range.ack_range
                        if start <= frame.largest_acknowledged <= end:
                            if ack_range.gap >= self.PACKET_THRESHOLD:
                                print("Packet loss recovery mechanism initiated.")
                                packet_sent = self.QUIC_recovery(frame.largest_acknowledged, receiver_address)
                                return True
                            else:
                                print("Packet loss recovery mechanism not initiated.")

        time_threshold = 9 / 8 * max(self.smoothed_rtt, self.latest_rtt)
        for packet_number, send_time in self.packet_send_times.items():
            if time.time() - send_time > time_threshold:
                print("Packet loss recovery mechanism initiated.")
                packet_sent = self.QUIC_recovery(packet_number, receiver_address)
                return True
        return False

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

    def QUIC_recovery(self, largest_acknowledged, receiver_address):
        total_bytes = 0
        packet_count = 0
        for packet_number, frames in self.in_flight_packets.items():
            if largest_acknowledged - self.PACKET_THRESHOLD > packet_number:
                packet_count += 1
                print(f"Packet number {packet_number} is lost.")
                # Get the frames of the lost packet and create a packet with a new packet number
                header = QUICHeader("Short", next(self.packet_number_generator))
                lost_packet = QUICPacket(header, frames)
                # Serialize the lost packet with pickle
                lost_packet = pickle.dumps(lost_packet)
                # Get the size of the lost packet in bytes
                lost_packet_size = Utils.calculate_bytes(lost_packet)
                # Send the lost packet to the receiver
                if self.socket_fd.sendto(lost_packet, receiver_address) < 0:
                    raise Exception("Error: The lost packet is not sent.")
                print(f"Lost packet {packet_number} sent to the receiver.")
                total_bytes += lost_packet_size
                # Remove the old packet from the in-flight packets and add the new packet
                self.in_flight_packets.pop(packet_number)
                self.in_flight_packets[header.packet_number] = frames
        print(f"Total bytes sent for the lost packets: {total_bytes}")
        return packet_count

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

    def largest_ack_update(self, packet):
        if packet.get_packet_number() == self.largest_acknowledged + 1:
            self.largest_acknowledged = packet.get_packet_number()

            return True
        elif packet.get_packet_number() > self.largest_acknowledged + 1:
            self.largest_acknowledged = packet.get_packet_number()
            print("Packet out of order.")
            return False
        else:
            return False

    def request_file_handshake(self):
        message = "Request a file"
        # Create the long header for the request packet
        long_header = QUICLongHeader("Long", "Handshake", next(self.packet_number_generator))
        # Create the frame for the request packet
        stream_frame = QUICStreamFrame("Stream", message, len(message))
        total_frames = [stream_frame]
        # Create the packet for the request packet
        request_packet = QUICPacket(long_header, total_frames)
        # Serialize the request packet with pickle
        request_packet = pickle.dumps(request_packet)
        # Send the request packet to the server
        if self.socket_fd.sendto(request_packet, self.server_address) == -1:
            raise Exception("Error: The request packet is not sent.")
        print("Request packet sent to the server.")
        # Receive the response from the server
        response_packet, server_address = self.socket_fd.recvfrom(2048)
        # Deserialize the response with pickle
        response_packet = pickle.loads(response_packet)
        # Check if the ack packet is received
        for frame in response_packet.frames:
            if frame.get_frame_type() == "Ack" and response_packet.get_packet_number():
                print(f"Response received from the server: {response_packet}")
                return True
            else:
                raise Exception("Error: The response packet is not received.")

    def file_handshake_server(self):
        # Receive the request from the client
        request_packet, client_address = self.socket_fd.recvfrom(2048)
        # Deserialize the request with pickle
        request_packet = pickle.loads(request_packet)
        self.largest_ack_update(request_packet)
        print(f"Request received from the client: {request_packet}")
        # Create the long header for the response packet
        long_header = QUICLongHeader("Long", "Handshake", next(self.packet_number_generator))
        # Create the ACK packet for the response packet
        ack_frame = QUICAckFrame("Ack", self.largest_acknowledged, 0, 0)
        total_frames = [ack_frame]
        response_packet = QUICPacket(long_header, total_frames)
        # Serialize the response packet with pickle
        response_packet = pickle.dumps(response_packet)
        # Send the response packet to the client
        if self.socket_fd.sendto(response_packet, client_address) == -1:
            raise Exception("Error: The response packet is not sent.")
        print("Response packet sent to the client, beginning the file transfer.")

    def divide_into_frames(self, data, frame_size):
        try:
            # Calculate the number of frames
            data_bytes_size = Utils.calculate_bytes(data)
            num_frames = data_bytes_size // frame_size
            if data_bytes_size % frame_size != 0:
                num_frames += 1  # Add one more frame if there's leftover data

            # Create the frames
            frames = []
            for i in range(num_frames):
                start = i * frame_size
                end = start + frame_size
                frame = QUICStreamFrame("Stream", data[start:end], Utils.calculate_bytes(data[start:end]))
                frames.append(frame)
            return frames
        except Exception as e:
            print(f"Error: {e}")

    def start_pto_timer(self, packet_number, receiver_address):
        # Calculate the PTO period
        pto_period = self.smoothed_rtt + 4 * self.latest_rtt
        # Start the PTO timer
        self.pto_timer = threading.Timer(pto_period, self.handle_pto_expiry, args=[packet_number, receiver_address])
        self.pto_timer.start()

    def handle_pto_expiry(self, packet_number, receiver_address):
        print(f"PTO timer expired for packet number {packet_number}.")
        # Resend the packet
        self.QUIC_send_data(self.in_flight_packets[packet_number], receiver_address)
