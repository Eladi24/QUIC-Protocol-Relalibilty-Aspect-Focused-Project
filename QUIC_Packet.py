"""
This file contains the QUIC Packet class.
The QUIC Packet is composed of a header long/short and frames.
"""
import uuid
from abc import ABC


# Since there are two types of headers, long and short, we will create an abstract class for the header.
class QUICHeader(ABC):
    def __init__(self):
        pass


class QUICLongHeader(QUICHeader):
    def __init__(self, header_form, fixed_bit, long_packet_type, type_specific_bits, version_id, DCID_length, DCID,
                 SCID_length, SCID):
        super().__init__()
        # Header Form: identifies the type of the header (1 bit)
        self.header_form = header_form
        # Fixed Bit: indicates if the packet is valid. If valid set to 0 (1 bit)
        self.fixed_bit = fixed_bit
        # Long Packet Type (T): Indicates the type of long header packet (2 bits).
        self.long_packet_type = long_packet_type
        # Type-Specific Bits (S): Bits specific for the long header packet type (4 bits).
        self.type_specific_bits = type_specific_bits
        # Version ID: The version of the QUIC protocol (32 bits).
        self.version_id = version_id
        # Destination Connection ID Length (DCIL): The length of the destination connection ID (8 bits).
        self.DCID_length = DCID_length
        # Destination Connection ID (DCID): The connection ID of the destination (0 - 160 bits).
        self.DCID = DCID
        # Source Connection ID Length (SCIL): The length of the source connection ID (8 bits).
        self.SCID_length = SCID_length
        # Source Connection ID (SCID): The connection ID of the source (0 - 160 bits).
        self.SCID = SCID


class QUICShortHeader(QUICHeader):
    def __init__(self, header_form, fixed_bit, spin_bit, reserved, key_phase, p, DCID, packet_number,
                 protected_payload):
        super().__init__()
        # Header Form: identifies the type of the header (1 bit)
        self.header_form = header_form
        # Fixed Bit: indicates if the packet is valid. If valid set to 0 (1 bit)
        self.fixed_bit = fixed_bit
        # Spin Bit: latency spin bit (1 bit)
        self.spin_bit = spin_bit
        # Reserved: reserved for future use (2 bits)
        self.reserved = reserved
        # Key Phase: identifies the packet protection key (1 bit)
        self.key_phase = key_phase
        # P: indicates the packet number length (2 bits)
        self.p = p
        # Destination Connection ID (DCID): The connection ID of the destination (0 - 160 bits)
        self.DCID = DCID

        # Protected Payload: The encrypted payload (0 - 1500 bytes)
        self.protected_payload = protected_payload


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
    def __init__(self, header, frames, packet_number):
        self.header = header
        self.frames = frames
        self.packet_number = packet_number
