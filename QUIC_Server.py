# Description: This file contains the QUIC server class.

# This class is representing the QUIC server.
# The stages of starting the server, accepting the connection from the client and sending a large file to the client are as follows:
# 1. Create a QUIC configuration object.
# 2. Create a QUIC server object.
# 3. Start the QUIC server to listen for incoming connections (set socket address and port).
# 4. Accept the connection from the client.
# 5. Send the file a using buffer (the file is sent once).
# 6. Close the connection with the client.

class Server:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.stream = None
