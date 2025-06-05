# Token Ring Simulator

This Python application simulates a token ring network using UDP for message transmission between nodes. It implements token passing, message queuing, CRC32 error checking, fault injection, and basic unicast/broadcast functionality as per the assignment requirements.

## Features

-   **Token Passing:** A token circulates the ring, allowing only the holder to transmit data.
-   **Message Queue:** Each node has a message queue (max 10 messages).
-   **UDP Communication:** All packets (token and data) are sent via UDP.
-   **Packet Formats:** Adheres to specified formats for token (`9000`) and data (`7777:...`).
-   **CRC32 Error Control:** Data packets include a CRC32 checksum for message integrity (calculated on the message payload only).
-   **ACK/NACK/NAOEXISTE:** Handles different states for message delivery.
-   **Retransmission:** Retransmits NACKed packets once.
-   **Fault Injection:** Randomly introduces errors into messages. For broadcast, status remains `naoexiste`.
-   **Broadcast:** Supports sending messages to all nodes (`TODOS`).
-   **Token Control:** The designated generator node manages token loss (timeout) and potential duplicates.
-   **Configuration File:** Node parameters are loaded from a specified config file (e.g., `config.txt`, `config_A.txt`).
-   **Command-Line Interface:** Basic CLI to send messages and view status. Accepts `--config` argument for config file path.

## File Structure

-   `ring_node.py`: The main Python script that runs each node in the simulation.
-   `config_A.txt`, `config_B.txt`, `config_C.txt`: Example configuration files for local testing of a 3-node ring. (And generally, `config.txt` or similar for single node/multi-machine setups).

## How to Run

1.  **Prerequisites:**
    *   Python 3.12+

2.  **Configuration Files (e.g., `config_A.txt`):
    Each node instance requires a configuration file. The format is 5 lines:

    ```
    <my_listen_port>
    <token_destination_ip>:<token_destination_port>
    <current_machine_nickname>
    <token_time_seconds>
    <is_token_generator_true_or_false>
    ```
    (See detailed explanation of lines in previous sections or by running `python ring_node.py --help`)

    **Example `config_A.txt` (NodeA for local testing):**
    ```
    7000
    127.0.0.1:7001
    NodeA
    1
    true
    ```
    **Example `config_B.txt` (NodeB for local testing):**
    ```
    7001
    127.0.0.1:7002
    NodeB
    1
    false
    ```
    **Example `config_C.txt` (NodeC for local testing - corrected):**
    ```
    7002
    127.0.0.1:7000
    NodeC
    1
    false
    ```

3.  **Network Setup (for multi-machine):**
    *   Ensure all machines are on the same local network.
    *   Verify IP addresses and that each node's config points to the correct neighbor IP and listening port.
    *   **Firewall:** Configure OS firewalls to allow incoming UDP traffic on `<my_listen_port>` for Python.

4.  **Running the Script:**
    Open a terminal and navigate to the directory containing `ring_node.py` and your config files.

    *   **For Local Testing (3 terminals):**
        *   Terminal 1 (NodeA): `python ring_node.py --config config_A.txt`
        *   Terminal 2 (NodeB): `python ring_node.py --config config_B.txt`
        *   Terminal 3 (NodeC): `python ring_node.py --config config_C.txt`

    *   **For Multi-Machine Setup:**
        On each machine, ensure its specific `config.txt` (or other named config file) is present.
        *   Machine A: `python ring_node.py --config machine_a_config.txt` (or simply `config.txt` if named that way)
        *   Machine B: `python ring_node.py --config machine_b_config.txt`
        *   ...and so on.
        If you name the config file `config.txt` on each machine, you can just run `python ring_node.py` and it will use the default.

    The node designated as the token generator will automatically create and send the first token after a short delay.

5.  **User Interaction:**
    (Commands remain the same: `send`, `queue`, `token`, `quit`, `gentoken`, `stoptoken`)

## Implementation Details

-   **Argparse:** Uses `argparse` for command-line configuration file input.
-   **Concurrency:** Uses the `threading` module.
-   **CRC32:** `zlib.crc32` is used.
-   **Packet Parsing:** Simple string splitting.
-   **Token Control (Generator):** Uses `threading.Timer` for lost token detection.

## Testing Strategy Reminder

1.  **Local Loopback (as described above):** Crucial for initial debugging.
2.  **Two Machines:** Test communication between two physical machines.
3.  **Full Group:** Test with all participating machines.

## Notes on Message Content

-   The CRC32 is calculated *only* on the `<message>` part of the data packet.
-   Messages should *not* contain semicolons (`;`) as this character is used as a delimiter in the packet structure. 