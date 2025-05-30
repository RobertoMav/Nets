# Token Ring Simulator

This Python application simulates a token ring network using UDP for message transmission between nodes. It implements token passing, message queuing, CRC32 error checking, fault injection, and basic unicast/broadcast functionality as per the assignment requirements.

## Features

-   **Token Passing:** A token circulates the ring, allowing only the holder to transmit data.
-   **Message Queue:** Each node has a message queue (max 10 messages).
-   **UDP Communication:** All packets (token and data) are sent via UDP.
-   **Packet Formats:** Adheres to specified formats for token (`9000`) and data (`7777:...`).
-   **CRC32 Error Control:** Data packets include a CRC32 checksum for message integrity.
-   **ACK/NACK/NAOEXISTE:** Handles different states for message delivery.
-   **Retransmission:** Retransmits NACKed packets once.
-   **Fault Injection:** Randomly introduces errors into messages with a configurable probability.
-   **Broadcast:** Supports sending messages to all nodes (`TODOS`).
-   **Token Control:** The designated generator node manages token loss (timeout) and potential duplicates (simplified detection).
-   **Configuration File:** Node parameters are loaded from `config.txt`.
-   **Command-Line Interface:** Basic CLI to send messages and view status.

## File Structure

-   `ring_node.py`: The main Python script that runs each node in the simulation.
-   `config.txt`: Configuration file for a node. Each node needs its own version of this file.

## How to Run

1.  **Prerequisites:**
    *   Python 3.12+

2.  **Configuration (`config.txt`):
    Each machine participating in the ring needs its own `config.txt` file with the following format:

    ```
    <token_destination_ip>:<port>
    <current_machine_nickname>
    <token_time_seconds>
    <is_token_generator_true_or_false>
    ```

    *   **Line 1: `<token_destination_ip>:<port>`**: The IP address and UDP port of the machine to the right in the ring. All machines in the ring should use the **same port number** for communication.
        *   Example: `192.168.1.102:6000`
        *   For local testing on one machine, use `127.0.0.1` with different ports for each node if you bind specifically to that port, or the same port if your listener binds to `0.0.0.0` and you manage distinct config files for each instance.
    *   **Line 2: `<current_machine_nickname>`**: A unique nickname for this machine.
        *   Example: `Alice`
    *   **Line 3: `<token_time_seconds>`**: The time (in seconds, can be a float) this machine will hold a token or data packet for simulation/debugging purposes before forwarding it.
        *   Example: `1` or `0.5`
    *   **Line 4: `<is_token_generator_true_or_false>`**: Set to `true` if this machine should generate the initial token and control it. Only **one** machine in the ring should have this set to `true`. Others should be `false`.
        *   Example: `true`

    **Example `config.txt` for Node A (Generator):**
    ```
    192.168.1.101:7000  // IP/Port of Node B
    NodeA
    1
    true
    ```
    **Example `config.txt` for Node B:**
    ```
    192.168.1.102:7000  // IP/Port of Node C
    NodeB
    1
    false
    ```
    **Example `config.txt` for Node C (points back to Node A):**
    ```
    192.168.1.100:7000  // IP/Port of Node A (assuming NodeA is 192.168.1.100)
    NodeC
    1
    false
    ```

3.  **Network Setup:**
    *   Ensure all machines are on the same local network (e.g., connected to the same switch).
    *   Verify IP addresses. Each machine needs to know the IP of its right neighbor.
    *   **Firewall:** Configure your OS firewall to allow incoming UDP traffic on the port specified in your `config.txt` (e.g., port `7000` in the example) for the `python` or `python3` executable.

4.  **Running the Script:**
    Open a terminal on each machine, navigate to the directory containing `ring_node.py` and that machine's `config.txt`, and run:
    ```bash
    python ring_node.py
    ```
    (Or `python3 ring_node.py` depending on your Python installation).

    The node designated as the token generator will automatically create and send the first token after a short delay.

5.  **User Interaction:**
    Once running, you can type commands into the terminal for each node:
    *   `send <destination_nickname> <message_content>`: Adds a message to this node's send queue.
        *   Example: `send Bob Hello Bob from Alice!`
        *   Example (Broadcast): `send TODOS This is a broadcast message!`
    *   `queue`: Displays the current messages in this node's send queue.
    *   `token`: (Debug) Shows if this node currently thinks it has the token.
    *   `quit`: Shuts down the node.
    *   If `is_token_generator` is `true`:
        *   `gentoken`: Manually (re)generates and injects a token.
        *   `stoptoken`: (Debug) Clears the local token flag and stops the token timer (for testing recovery).

## Implementation Details

-   **Concurrency:** Uses the `threading` module. A separate thread listens for incoming UDP packets, while the main thread handles user input and primary logic execution when a token is received.
-   **Global State:** Some global variables (`config`, `has_token`, `message_queue`, `udp_socket`, `last_sent_message_details`) are used to manage node state and shared resources. `has_token` is a `threading.Event` for safe cross-thread signaling.
-   **CRC32:** `zlib.crc32` is used for error checking.
-   **Packet Parsing:** Simple string splitting based on delimiters.
-   **Token Control (Generator):** Uses a `threading.Timer` to detect lost tokens (timeout). Duplicate token detection is basic: if the generator receives a token while it believes one is already out (timer active) or it already holds one, it discards the incoming one.

## Testing Strategy

1.  **Local Loopback:** Test with multiple instances on a single machine using `127.0.0.1` and different port numbers in separate `config.txt` files (e.g., NodeA sends to `127.0.0.1:6001`, NodeB listens on `6001` and sends to `127.0.0.1:6002`, etc.). The `ring_node.py` script binds to `0.0.0.0:<port_from_config>`, so each instance will correctly listen on its configured port.
2.  **Two Machines:** Test communication between two physical machines.
3.  **Full Group:** Test with all participating machines.

## Potential Improvements / Future Work

-   More robust duplicate token detection (e.g., using sequence numbers on tokens).
-   Dynamic discovery of neighbors (more complex, beyond typical scope of this assignment).
-   More sophisticated UI than basic CLI.
-   Allowing messages to contain the delimiter character (e.g., by escaping).
-   More detailed logging options (e.g., to a file, different log levels).
-   Using `asyncio` for potentially better performance in I/O-bound operations if scaling further. 