"""
This file contains the QUIC Packet class.
The QUIC Packet is composed of a header long/short and frames.
"""
import uuid
from abc import ABC
from ctypes import *


# Since there are two types of headers, long and short, we will create an abstract class for the header.
class QUICHeader:
    def __init__(self, header_form):
        self.packet_number_generator = self.packet_number_generator()
        # Header Form: identifies the type of the header (1 bit)
        self.header_form = header_form
        # Packet Number: The packet number
        self.packet_number = next(self.packet_number_generator)

    @staticmethod
    def packet_number_generator():
        packet_number = 0
        while True:
            yield packet_number
            packet_number += 1


class QUICLongHeader(QUICHeader):
    def __init__(self, header_form, long_packet_type, version_id):
        super().__init__(header_form)
        # Header Form: identifies the type of the header (1 bit)
        self.header_form = header_form
        # Long Packet Type (T): Indicates the type of long header packet (2 bits).
        self.long_packet_type = long_packet_type
        # Version ID: The version of the QUIC protocol (32 bits).
        self.version_id = version_id


class QUICFrame(ABC):
    def __init__(self):
        pass


class QUICStreamFrame(QUICFrame):
    def __init__(self, frame_type, data, data_length=None):
        super().__init__()
        self.frame_type = frame_type
        self.data = data
        self.data_length = data_length


class QUICAckFrame(QUICFrame):
    def __init__(self, frame_type, largest_acknowledged, ack_delay, ack_range_count, first_ack_range, ack_ranges,
                 ECN_counts):
        super().__init__()
        self.frame_type = frame_type
        self.largest_acknowledged = largest_acknowledged
        self.ack_delay = ack_delay
        self.ack_range_count = ack_range_count
        self.first_ack_range = first_ack_range
        self.ack_ranges = ack_ranges
        self.ECN_counts = ECN_counts


class QUICPacket:
    def __init__(self, header, frames):
        self.header = header
        self.frames = frames

    def __str__(self):
        return f"Header: {self.header}, Frames: {self.frames}"

    def get_packet_number(self):
        return self.header.packet_number
