import os
import sys
from QUIC_Packet import *
import pickle

# Usage:
# generate_random_file('random_file.bin', 1024)  # Creates a file with 1024 random bytes
"""
    Generate a file with random content.

    :param filename: Name of the file to be created.
    :param size: Size of the file in bytes.
"""


def generate_random_file(filename, size):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size))


def calculate_bytes(obj):
    return sys.getsizeof(pickle.dumps(obj))
