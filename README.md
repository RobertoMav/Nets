# Token Ring Simulator

This Python application simulates a token ring network using UDP for message transmission between nodes. It implements token passing, message queuing, CRC32 error checking, fault injection, and basic unicast/broadcast functionality as per the Computer Networks final project assignment requirements.

## Features

-   **Token Passing:** A token circulates the ring, allowing only the holder to transmit data.
-   **Message Queue:** Each node has a message queue (max 10 messages).
-   **UDP Communication:** All packets (token and data) are sent via UDP.
-   **Packet Formats:** Adheres to assignment specification - token (`9000`) and data (`7777:<status>;<source>;<dest>;<CRC>;<message>`).
-   **CRC32 Error Control:** Data packets include a CRC32 checksum for message integrity.
-   **ACK/NACK/NAOEXISTE:** Handles different states for message delivery as specified.
-   **Retransmission:** Retransmits NACKed packets once only.
-   **Fault Injection:** Both automatic (10% probability) and manual fault injection. For broadcast, status remains `naoexiste`.
-   **Broadcast:** Supports sending messages to all nodes using nickname `TODOS`.
-   **Token Control:** The designated generator node manages token loss (timeout) and duplicate detection.
-   **Configuration File:** Node parameters loaded from config file following exact assignment format.
-   **Command-Line Interface:** Comprehensive CLI with debugging and monitoring features.

## File Structure

-   `ring_node.py`: The main Python script that runs each node in the simulation.
-   `config_A.txt`, `config_B.txt`, `config_C.txt`: Example configuration files for 3-node ring (Alice → Bob → Charlie → Alice).
-   `test_ring.sh`: Test script with instructions for running the 3-node demonstration.

## How to Run

1.  **Prerequisites:**
    *   Python 3.12+ (or use `uv run` with virtual environment)

2.  **Configuration Files:**
    Each node requires a configuration file following the **exact assignment specification** (4 lines):

    ```
    <token_destination_ip>:port
    <current_machine_nickname>
    <token_time>
    <token_generator_true_or_false>
    ```

    **Example `config_A.txt` (Alice - Token Generator):**
    ```
    127.0.0.1:6002
    Alice
    1
    true
    ```
    **Example `config_B.txt` (Bob):**
    ```
    127.0.0.1:6003
    Bob
    1
    false
    ```
    **Example `config_C.txt` (Charlie):**
    ```
    127.0.0.1:6001
    Charlie
    1
    false
    ```

    **Ring topology:** Alice (6001) → Bob (6002) → Charlie (6003) → Alice

3.  **Running the Script:**
    **IMPORTANT:** The `--port` argument is **required** for each node to specify its listening port.

    **Command syntax:**
    ```bash
    uv run python ring_node.py --config <config_file> --port <listen_port>
    ```
    or
    ```bash
    python ring_node.py --config <config_file> --port <listen_port>
    ```

    **For Local Testing (3 terminals):**
    ```bash
    # Terminal 1 (Alice - Token Generator)
    uv run python ring_node.py --config config_A.txt --port 6001

    # Terminal 2 (Bob)
    uv run python ring_node.py --config config_B.txt --port 6002

    # Terminal 3 (Charlie)
    uv run python ring_node.py --config config_C.txt --port 6003
    ```

    **For Multi-Machine Setup:**
    Each machine runs with its own listen port and config file pointing to the next machine in the ring.

    The token generator node will automatically create and send the first token after a short delay.

4.  **User Commands:**
    Once a node is running, you can use these commands:

    **Basic Commands:**
    - `send <nickname> <message>` - Send message to specific node
    - `send TODOS <message>` - Broadcast message to all nodes
    - `queue` - Show current message queue
    - `token` - Show token status
    - `status` - Show detailed node information
    - `quit` - Exit the program

    **Debugging Commands:**
    - `faultmode on|off` - Enable/disable fault injection for next message
    - `verbose on|off` - Control verbose logging (shows packet forwarding)
    - `gentoken` - Manually generate a new token
    - `stoptoken` - (Generator only) Stop token for debugging

5.  **Network Setup (for multi-machine):**
    *   Ensure all machines are on the same local network.
    *   Configure OS firewalls to allow incoming UDP traffic on the specified ports.
    *   Verify each node's config points to the correct next neighbor IP and port.

## Example Testing Session

```bash
# Start the test helper
./test_ring.sh

# Run in 3 terminals as shown, then try these commands:

[Alice]> send Bob Hello from Alice
[Alice]> send TODOS Broadcast to everyone  
[Alice]> faultmode on
[Alice]> send Charlie This message will be corrupted
[Alice]> status
[Alice]> queue
```

## Implementation Details

-   **Assignment Compliance:** Follows the exact packet formats and configuration specified in the assignment.
-   **Concurrency:** Uses `threading` module for UDP listener and token timeout detection.
-   **CRC32:** Uses `zlib.crc32` for error control calculation and verification.
-   **Packet Parsing:** String-based parsing with semicolon (`;`) delimiters.
-   **Token Control:** Timer-based token loss detection and duplicate prevention.
-   **Error Handling:** Comprehensive error handling for network issues and malformed packets.

## Key Features for Assignment Demonstration

1.  **Token Passing Visualization:** Shows token movement through the ring
2.  **Message Forwarding:** Displays when nodes forward packets (verbose mode)
3.  **Error Detection & Recovery:** CRC validation and retransmission
4.  **Fault Injection:** Both automatic and manual for testing
5.  **Broadcast Support:** `TODOS` nickname for network-wide messages
6.  **Network Monitoring:** Status commands show ring health and token location

## Notes

-   **Message Content:** Avoid semicolons (`;`) in messages as they're used as packet delimiters.
-   **CRC Calculation:** CRC32 is calculated on the message content only.
-   **Port Requirements:** Each node must use a unique listening port.
-   **Assignment Format:** Configuration files strictly follow the 4-line format specified in the assignment. 