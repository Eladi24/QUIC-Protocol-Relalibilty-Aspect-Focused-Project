
# QUIC Protocol Implementation

## Overview

This project implements a simplified version of the QUIC protocol, focusing on the reliability aspect. QUIC is a UDP-based transport protocol that addresses some of the disadvantages of TCP, offering faster connections and more efficient data transmission.

## Features

- **Dynamic Packet Structure**: The packet structure can be modified at runtime, allowing for smaller headers when certain fields are unnecessary. This optimization speeds up the initial connection between peers.
- **Reliability Mechanism**: Ensures data delivery and integrity through:
  - **Unique Packet Numbering**: Each packet is assigned a unique number and is considered "in flight" until acknowledged by the receiving side.
  - **Enhanced Acknowledgment**: Unlike TCP, which acknowledges packets individually, this implementation sends back a sequence of all received packets, providing more information to the sender.
  - **Time-Based Reliability**: The sender tracks the time each packet is sent and received, comparing the delta time against an allowed threshold. If a packet isn't acknowledged within a certain time (based on RTT samples), it is retransmitted.

## Libraries Used

- `pickle`
- `os`
- `sys`
- `abc`
- `unittest`
- `time`
- `threading`

## Reliability Mechanism Details

1. **Packet Numbering**:
   - Each packet has a unique serial number.
   - A packet remains "in flight" until it is acknowledged by the receiver.

2. **Acknowledgment**:
   - The receiver sends back a sequence of all previously received packets in each acknowledgment packet, providing comprehensive feedback to the sender.

3. **Time Monitoring**:
   - The sender monitors the time taken for packets to be acknowledged.
   - If a packet exceeds the allowed time threshold, it is retransmitted as a new packet using a recovery mechanism.

## Multithreading

The project utilizes multithreading to manage timeouts and retransmissions efficiently. A timer is started for each packet based on RTT samples, and if a packet is not acknowledged within the expected time, it is resent.

## Getting Started

### Running the Project

1. **Server**: First execute the server with the following command:
   ```bash
   python3 QUIC_Server.py
2. **Client**: After the server is up and listening execute the client with the following command:
   ```bash
   python3 QUIC_Client.py

### Testing

Unit tests are included and can be run using the `unittest` framework. To execute the tests, use the following command:

```bash
python3 Unitest.py
```

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. Ensure that your code adheres to the coding standards and passes all tests.

## Acknowledgments

This project is inspired by the QUIC protocol and aims to provide a simplified implementation focusing on its reliability aspects.

---

Feel free to customize and expand upon this README as needed, especially in sections like "Getting Started" and "Running the Project," where specific instructions for running your code should be provided.
