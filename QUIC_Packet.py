"""
This file contains the QUIC Packet class.
The QUIC Packet is composed of a header long/short and frames.
"""
import uuid
from abc import ABC, abstractmethod
from ctypes import *
import pickle


# Since there are two types of headers, long and short, we will create an abstract class for the header.
class QUICHeader:

    def __init__(self, header_form, packet_number):
        # Header Form: identifies the type of the header (1 bit)
        self.header_form = header_form
        # Packet Number: The packet number
        self.packet_number = packet_number

    def __getstate__(self):
        # Convert the object to a dictionary
        state = self.__dict__.copy()
        return state

    def __setstate__(self, state):
        # Restore the object's state from the dictionary
        self.__dict__.update(state)

    def __str__(self):
        return f"Header Form: {self.header_form}, Packet Number: {self.packet_number}"

    @staticmethod
    def packet_number_generator():
        packet_number = 0
        while True:
            yield packet_number
            packet_number += 1


class QUICLongHeader(QUICHeader):
    def __init__(self, header_form, long_packet_type, packet_number):
        super().__init__(header_form, packet_number)
        # Header Form: identifies the type of the header (1 bit)
        self.header_form = header_form
        # Long Packet Type (T): Indicates the type of long header packet (2 bits).
        self.long_packet_type = long_packet_type

    # Override the __str__ method of the QUICHeader class
    def __str__(self):
        return (f"Header Form: {self.header_form}, Long Packet Type: {self.long_packet_type}, "
                f"Packet Number: {self.packet_number}")


class QUICFrame(ABC):
    def __init__(self, frame_type):
        self.frame_type = frame_type

    def __getstate__(self):
        # Convert the object to a dictionary
        state = self.__dict__.copy()
        return state

    def __setstate__(self, state):
        # Restore the object's state from the dictionary
        self.__dict__.update(state)

    def get_frame_type(self):
        return self.frame_type

    @abstractmethod
    def __str__(self):
        pass


class QUICStreamFrame(QUICFrame):
    def __init__(self, frame_type, data, data_length=None):
        super().__init__(frame_type)
        self.data = data
        self.data_length = data_length

    def __str__(self):
        return f"Frame Type: {self.frame_type}, Data: {self.data}, Data Length: {self.data_length}"

    __repr__ = __str__


class QUICAckFrame(QUICFrame):
    def __init__(self, frame_type, largest_acknowledged, ack_delay, ack_ranges):
        super().__init__(frame_type)
        self.largest_acknowledged = largest_acknowledged
        self.ack_delay = ack_delay
        self.ack_ranges = ack_ranges

    def __str__(self):
        return (f"Frame Type: {self.frame_type}, Largest Acknowledged: {self.largest_acknowledged}, "
                f"Ack Delay: {self.ack_delay}, Ack Ranges: {self.ack_ranges}")

    __repr__ = __str__


class AckRange:
    def __init__(self, gap, ack_range):
        self.gap = gap
        self.ack_range = ack_range


class QUICPacket:
    def __init__(self, header, frames):
        self.header = header
        self.frames = frames

    def __getstate__(self):
        # Convert the object to a dictionary
        state = self.__dict__.copy()
        # Convert the header object to a dictionary
        state['header'] = pickle.dumps(state['header'])
        # Convert the frames objects to a list of dictionaries
        state['frames'] = [pickle.dumps(frame) for frame in state['frames']]
        return state

    def __setstate__(self, state):
        # Restore the object's state from the dictionary
        self.__dict__.update(state)
        # Restore the header object from the dictionary
        self.header = pickle.loads(state['header'])
        # Restore the frames objects from the list of dictionaries
        self.frames = [pickle.loads(frame) for frame in state['frames']]

    def __str__(self):
        return f"Header: {self.header}, Frames: {self.frames} Number: {self.header.packet_number}"

    __repr__ = __str__

    def get_packet_number(self):
        return self.header.packet_number
