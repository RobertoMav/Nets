import random
import socket
import threading
import time
import zlib  # For CRC32
from collections import deque

# --- Constants ---
TOKEN_PACKET_ID = "9000"
DATA_PACKET_ID = "7777"
BROADCAST_NICKNAME = "TODOS"
STATUS_NAOEXISTE = "naoexiste"
STATUS_ACK = "ACK"
STATUS_NACK = "NACK"
MESSAGE_QUEUE_MAX_SIZE = 10
CRC_PLACEHOLDER = "00000000"  # Placeholder for CRC during initial packet construction


# --- Configuration ---
class Config:
    def __init__(
        self,
        right_neighbor_ip: str,
        right_neighbor_port: int,
        nickname: str,
        token_hold_time: float,
        is_generator: bool,
        listen_port: int,
    ):
        self.right_neighbor_ip = right_neighbor_ip
        self.right_neighbor_port = right_neighbor_port
        self.nickname = nickname
        self.token_hold_time = token_hold_time  # Time to hold token/data for simulation
        self.is_generator = is_generator
        self.listen_port = listen_port  # Port this node listens on

        # For token control by the generator
        self.token_timer = None
        self.TOKEN_TIMEOUT_SECONDS = (
            30  # Example: Max time for token to circle, adjust based on ring size and hold times
        )
        self.MIN_TOKEN_INTERVAL_SECONDS = (
            1  # Example: Min time for token to pass, to detect duplicates
        )


config: Config = None  # Global config object

# --- State Variables ---
has_token = threading.Event()  # Use an Event to signal token presence
message_queue = deque(
    maxlen=MESSAGE_QUEUE_MAX_SIZE
)  # (destination_nickname, message_content, retransmission_attempted)
# retransmission_attempted is a boolean, True if it's a NACKed message being resent

# For source machine to wait for its data packet to return
# Stores: {unique_packet_id: threading.Event()} - event is set when packet returns
# unique_packet_id could be f"{source_nickname}_{destination_nickname}_{timestamp_or_seq_num}"
# For simplicity, let's manage one outstanding data packet at a time by the source.
# If a machine sends data, it holds the token and waits.
# We'll need a way to correlate sent data with returned data.
# For now, assume only one data packet from self is "in flight" at a time when holding token.
# The logic for releasing token is tied to data packet's return.


# --- Utility Functions ---
def calculate_crc32(data: str) -> str:
    """Calculates CRC32 for the given string data and returns as a string."""
    # Ensure bytes for CRC calculation
    crc_val = zlib.crc32(data.encode("utf-8"))
    return str(crc_val)


def verify_crc32(data: str, expected_crc: str) -> bool:
    """Verifies if the calculated CRC32 matches the expected CRC."""
    if not expected_crc.isdigit():
        print_log(f"Invalid CRC format: {expected_crc}. Assuming CRC check failed.")
        return False
    return calculate_crc32(data) == expected_crc


def print_log(message: str):
    """Prints a log message with the machine's nickname."""
    if config:
        print(f"[{config.nickname}] {message}")
    else:
        print(message)


def parse_data_packet(packet_str: str) -> dict | None:
    """
    Parses a raw data packet string.
    Format: 7777:<status>;<source_nickname>;<destination_nickname>;<crc>;<message>
    Returns a dictionary with parsed fields or None if format is incorrect.
    """
    if not packet_str.startswith(DATA_PACKET_ID + ":"):
        return None
    try:
        parts = packet_str[len(DATA_PACKET_ID + ":") :].split(";", 4)
        if len(parts) == 5:
            return {
                "type": "data",
                "status": parts[0],
                "source_nickname": parts[1],
                "destination_nickname": parts[2],
                "crc": parts[3],
                "message": parts[4],
            }
        print_log(f"Error parsing data packet: {packet_str}. Expected 5 parts, got {len(parts)}")
        return None
    except Exception as e:
        print_log(f"Exception parsing data packet '{packet_str}': {e}")
        return None


def create_data_packet(
    status: str,
    source_nickname: str,
    destination_nickname: str,
    message: str,
    crc_val: str | None = None,
) -> str:
    """
    Creates a data packet string.
    If crc_val is None, it calculates CRC on the message.
    """
    if crc_val is None:
        crc_val = calculate_crc32(message)
    return (
        f"{DATA_PACKET_ID}:{status};{source_nickname};{destination_nickname};{crc_val};{message}"
    )


# --- Network Communication ---
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_packet(packet_data: str, dest_ip: str, dest_port: int):
    """Sends a packet via UDP."""
    try:
        udp_socket.sendto(packet_data.encode("utf-8"), (dest_ip, dest_port))
        # print_log(f"Sent: '{packet_data[:50]}...' to {dest_ip}:{dest_port}") # Log trimmed packet
    except socket.gaierror:
        print_log(f"Error: Hostname {dest_ip} could not be resolved. Message not sent.")
    except Exception as e:
        print_log(f"Error sending packet to {dest_ip}:{dest_port}: {e}")


def forward_token():
    """Forwards the token to the right neighbor."""
    global has_token
    if has_token.is_set():
        print_log(f"Forwarding token to {config.right_neighbor_ip}:{config.right_neighbor_port}")
        send_packet(TOKEN_PACKET_ID, config.right_neighbor_ip, config.right_neighbor_port)
        has_token.clear()
        if config.is_generator:
            start_token_timer()  # Generator restarts its timer when it sends the token


def start_token_timer():
    """For token generator: starts/restarts the timer to detect lost token."""
    if config.token_timer:
        config.token_timer.cancel()
    config.token_timer = threading.Timer(config.TOKEN_TIMEOUT_SECONDS, handle_token_timeout)
    config.token_timer.daemon = True  # Allow main program to exit even if timer is active
    config.token_timer.start()
    # print_log(f"Token timer started ({config.TOKEN_TIMEOUT_SECONDS}s).")


def handle_token_timeout():
    """For token generator: called when token hasn't returned in time."""
    print_log("Token timeout! Token might be lost. Regenerating token.")
    # Potentially clear has_token if it was somehow set or stuck
    has_token.clear()
    receive_token(is_regenerated=True)  # Simulate receiving a new token to kickstart


def receive_token(is_regenerated=False):
    """Handles this machine receiving the token."""
    global has_token

    if config.is_generator and not is_regenerated:
        if config.token_timer:  # If timer is active, it means the token returned
            # print_log("Token returned to generator.")
            config.token_timer.cancel()
            # Add logic here to check for "too early" arrival if needed
        else:
            # This case could happen if a token appears while generator thought it was lost
            # or at startup if it wasn't the one generating it.
            # For now, accept it and start the timer when it's passed on.
            pass

    if (
        has_token.is_set() and not is_regenerated
    ):  # Already have a token, and this isn't a regeneration
        if config.is_generator:
            print_log("Duplicate token detected by generator. Discarding incoming token.")
            # Generator simply doesn't forward it, effectively removing it.
            return
        else:
            # Non-generators shouldn't ideally see this if generator is working,
            # but as a safeguard, they could just ignore or log.
            print_log(
                "Warning: Received token while already holding one (non-generator). Ignoring."
            )
            return

    has_token.set()
    print_log("Received token.")

    # Simulate holding time
    time.sleep(config.token_hold_time)

    # Check message queue
    if message_queue:
        dest_nick, msg_content, retransmission_attempted = (
            message_queue.popleft()
        )  # Get first message

        print_log(f"Have message for {dest_nick}: '{msg_content[:30]}...'. Preparing to send.")

        current_status = STATUS_NAOEXISTE
        # For retransmissions, the problem states:
        # "changing NACK to naoexiste, placing the original error-free message"
        # Our queue stores original error-free message. retransmission_attempted flag handles this.

        # Fault Injection (before CRC calculation for data integrity)
        # This implementation of fault injection for broadcast ensures naoexiste status
        # For unicast, it corrupts data.
        message_to_send_after_fault_injection = msg_content
        if random.random() < 0.1:  # 10% chance of fault
            if dest_nick == BROADCAST_NICKNAME:
                print_log(
                    "Fault Injection: Ensuring 'naoexiste' for broadcast "
                    "(no data corruption needed as per rule)."
                )
                # The status is already naoexiste for new messages.
            else:  # Unicast fault
                faulty_char_index = random.randint(0, len(msg_content) - 1)
                faulty_char = chr(ord(msg_content[faulty_char_index]) ^ 0xFF)  # Flip some bits
                message_to_send_after_fault_injection = (
                    msg_content[:faulty_char_index]
                    + faulty_char
                    + msg_content[faulty_char_index + 1 :]
                )
                print_log(
                    f"Fault Injection: Corrupted message for {dest_nick}. "
                    f"Original: '{msg_content[:30]}...', "
                    f"Faulty: '{message_to_send_after_fault_injection[:30]}...'"
                )

        # CRC is calculated on the potentially (un)corrupted message
        crc = calculate_crc32(message_to_send_after_fault_injection)

        # For broadcast, source *always* sets naoexiste (as per clarification)
        if dest_nick == BROADCAST_NICKNAME:
            current_status = STATUS_NAOEXISTE

        # Construct and send data packet
        data_packet = create_data_packet(
            status=current_status,
            source_nickname=config.nickname,
            destination_nickname=dest_nick,
            message=message_to_send_after_fault_injection,  # Send the (possibly corrupted) message
            crc_val=crc,
        )
        print_log(f"Sending data packet: '{data_packet[:100]}...'")
        send_packet(data_packet, config.right_neighbor_ip, config.right_neighbor_port)

        # This machine now WAITS for this data packet to return.
        # The token is NOT forwarded yet.
        # The packet_handler will deal with the returned packet and then call forward_token().
        # We need to store that this message was sent to handle its return:
        global last_sent_message_details
        last_sent_message_details = {
            "original_dest_nick": dest_nick,
            "original_msg_content": msg_content,  # Store original for potential NACK re-queuing
            "retransmission_attempted": retransmission_attempted,
            "is_broadcast": dest_nick == BROADCAST_NICKNAME,
        }

    else:  # No messages to send
        print_log("Message queue empty.")
        forward_token()


last_sent_message_details = None  # Holds info about the data packet this node sent


# --- Packet Processing Logic ---
def process_incoming_packet(packet_str: str, sender_address: tuple):
    """Processes any incoming packet (token or data)."""
    global has_token, message_queue, last_sent_message_details
    sender_ip, sender_port = sender_address
    # print_log(f"Processing packet from {sender_ip}:{sender_port}: '{packet_str[:50]}...'")

    if packet_str == TOKEN_PACKET_ID:
        receive_token()
        return

    data_info = parse_data_packet(packet_str)
    if data_info:
        # Simulate holding time for data packets too
        time.sleep(config.token_hold_time)

        # Is this packet for me?
        if data_info["destination_nickname"] == config.nickname:
            print_log(
                f"Data packet for me from {data_info['source_nickname']}: "
                f"'{data_info['message'][:30]}...'"
            )

            # Recalculate CRC on received message
            crc_ok = verify_crc32(data_info["message"], data_info["crc"])
            new_status = STATUS_ACK if crc_ok else STATUS_NACK

            print_log(
                f"CRC check: {'OK' if crc_ok else 'FAIL'}. "
                f"Original CRC: {data_info['crc']}, "
                f"Calculated on: '{data_info['message']}'. "
                f"Sending {new_status}."
            )

            # Send back to ring, changing status (and possibly other fields if needed)
            # The packet is sent back to the source via the ring.
            # Source and Destination remain the same in the packet header.
            response_packet = create_data_packet(
                status=new_status,
                source_nickname=data_info["source_nickname"],
                destination_nickname=data_info[
                    "destination_nickname"
                ],  # Still original destination
                message=data_info["message"],  # Send back the received message
                crc_val=data_info["crc"],  # Send back the original CRC it came with
            )
            print_log(f"Sending data packet response: '{response_packet[:100]}...'")
            send_packet(response_packet, config.right_neighbor_ip, config.right_neighbor_port)

        # Is this a broadcast packet?
        elif data_info["destination_nickname"] == BROADCAST_NICKNAME:
            print_log(
                f"Broadcast packet from {data_info['source_nickname']} "
                f"for {data_info['destination_nickname']}: "
                f"'{data_info['message'][:30]}...'"
            )
            # Process broadcast (e.g., display it)
            # Then forward it unchanged
            print_log(f"Forwarding broadcast packet: '{packet_str[:100]}...'")
            send_packet(packet_str, config.right_neighbor_ip, config.right_neighbor_port)

        # Is this packet originated by me and returning?
        elif data_info["source_nickname"] == config.nickname:
            print_log(
                f"My data packet returned. Status: {data_info['status']}, "
                f"Msg: '{data_info['message'][:30]}...'"
            )

            if not last_sent_message_details:
                print_log(
                    "Warning: Received a self-originated packet, but no details of "
                    "last sent message. Ignoring."
                )
                # This implies the token should probably be passed if we have it, as this packet
                # isn't one we're "waiting" on. However, if has_token is set, it implies we *are*
                # waiting. This state shouldn't occur.For now, if it's our packet and we have
                # the token, assume it's the one we sent.
                if has_token.is_set():
                    forward_token()
                return

            # Retrieve details of the message this node actually sent
            original_dest = last_sent_message_details["original_dest_nick"]
            original_msg = last_sent_message_details["original_msg_content"]
            was_retransmission_attempt = last_sent_message_details["retransmission_attempted"]
            is_broadcast_msg = last_sent_message_details["is_broadcast"]
            last_sent_message_details = None  # Clear it, we've handled the return.

            if is_broadcast_msg:
                # As per clarification: source logs and discards its own returned broadcast.
                # The status would be 'naoexiste'.
                print_log(
                    f"My broadcast message to {BROADCAST_NICKNAME} completed its round. "
                    f"Original content: '{original_msg[:30]}...'"
                )
                # Message is implicitly removed from queue as it was popped when sent.
                # Now pass the token.
                if has_token.is_set():
                    forward_token()
                else:
                    print_log(
                        "Warning: My broadcast packet returned, but I don't have the "
                        "token to pass."
                    )
                return

            # --- Unicast Packet Return Handling ---
            if data_info["status"] == STATUS_ACK:
                print_log(
                    f"Message to {original_dest} successfully ACKed: '{original_msg[:30]}...'"
                )
                # Message is removed from queue (already popped when sent)

            elif data_info["status"] == STATUS_NAOEXISTE:
                print_log(
                    f"Message to {original_dest} returned 'naoexiste' (destination not "
                    f"found/off): '{original_msg[:30]}...'"
                )
                # Message is removed from queue (already popped when sent)

            elif data_info["status"] == STATUS_NACK:
                print_log(f"Message to {original_dest} NACKed: '{original_msg[:30]}...'.")
                if not was_retransmission_attempt:
                    print_log("Will retransmit once.")
                    # Add back to the FRONT of the queue for retransmission
                    message_queue.appendleft(
                        (original_dest, original_msg, True)
                    )  # Mark as retransmission_attempted=True
                else:
                    print_log("Already attempted retransmission. Message dropped.")
                    # Message is not re-queued, effectively dropped.

            else:  # Unknown status
                print_log(
                    f"My data packet returned with unknown status '{data_info['status']}'. "
                    "Treating as failed."
                )

            # In all cases of my unicast packet returning (ACK, NACK, NAOEXISTE), I pass the token.
            if has_token.is_set():
                forward_token()
            else:
                # This state (own packet returns but no token) should ideally not happen
                # if a machine only sends data when it has the token and waits.
                print_log(
                    "Warning: My data packet returned, but I don't have the token. "
                    "Cannot forward token now."
                )

        # Not for me, not broadcast, not mine returning -> just forward
        else:
            print_log(
                f"Forwarding data packet from {data_info['source_nickname']} for "
                f"{data_info['destination_nickname']}: '{packet_str[:100]}...'"
            )
            send_packet(packet_str, config.right_neighbor_ip, config.right_neighbor_port)
    else:
        print_log(f"Received unknown packet type or malformed data packet: '{packet_str[:50]}...'")


# --- Main Application Logic ---
def udp_listener_thread():
    """Thread function to listen for incoming UDP packets."""
    print_log(f"Listener thread started. Binding to 0.0.0.0:{config.listen_port}")
    try:
        # Bind the socket here, as it's specific to this node's listening.
        # The global udp_socket is used for both sending and receiving.
        udp_socket.bind(("0.0.0.0", config.listen_port))
    except OSError as e:
        print_log(f"ERROR: Could not bind to port {config.listen_port}. Is it already in use? {e}")
        return  # Exit thread if cannot bind

    while True:
        try:
            data, addr = udp_socket.recvfrom(2048)  # Increased buffer size for safety
            packet_str = data.decode("utf-8")
            # Offload processing to another thread or manage carefully if processing is long
            # For this assignment, direct call might be okay if processing is fast.
            process_incoming_packet(packet_str, addr)
        except UnicodeDecodeError:
            print_log(f"Received packet with undecodeable (non-UTF-8) content from {addr}.")
        except Exception as e:
            print_log(f"Error in listener thread: {e}")
            time.sleep(1)  # Avoid tight loop on continuous errors


def load_config(filepath="config.txt") -> Config | None:
    """Loads configuration from the specified file."""
    try:
        with open(filepath, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            if len(lines) != 4:
                print(f"Error: Config file '{filepath}' must have 4 lines. Found {len(lines)}.")
                return None

            dest_full_address = lines[0]
            nickname = lines[1]
            token_time_str = lines[2]
            is_gen_str = lines[3].lower()

            if ":" not in dest_full_address:
                print(
                    f"Error: Destination address '{dest_full_address}' must be in format IP:PORT."
                )
                return None
            dest_ip, dest_port_str = dest_full_address.split(":", 1)

            if not dest_port_str.isdigit():
                print(f"Error: Destination port '{dest_port_str}' must be a number.")
                return None
            dest_port = int(dest_port_str)

            if not token_time_str.replace(".", "", 1).isdigit():  # Allows float
                print(f"Error: Token time '{token_time_str}' must be a number.")
                return None
            token_time = float(token_time_str)

            if is_gen_str not in ["true", "false"]:
                print(f"Error: is_token_generator ('{is_gen_str}') must be 'true' or 'false'.")
                return None
            is_gen = is_gen_str == "true"

            # For simplicity, assume listen port is same as destination port of others in the ring
            # This means all nodes listen on the same port.
            # This information isn't directly in the config file per se, but is implied by the
            # ring structure. We can make it explicit or derive. If Node A sends to Node B on
            # port X, Node B must listen on X.
            # Let's assume the port specified in the *destination* line is the common ring port.
            listen_port = dest_port

            return Config(dest_ip, dest_port, nickname, token_time, is_gen, listen_port)

    except FileNotFoundError:
        print(f"Error: Config file '{filepath}' not found.")
        return None
    except ValueError as e:
        print(f"Error parsing config file '{filepath}': {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while loading config '{filepath}': {e}")
        return None


def main():
    global config  # Allow main to set the global config

    config_file_path = "config.txt"  # Default, can be made an argument
    print(f"Attempting to load configuration from: {config_file_path}")

    local_config = load_config(config_file_path)
    if not local_config:
        print("Exiting due to configuration errors.")
        return
    config = local_config  # Set the global config

    print_log(
        f"Configuration loaded: Neighbor={config.right_neighbor_ip}:{config.right_neighbor_port}, "
        f"Nick={config.nickname}, HoldTime={config.token_hold_time}s, "
        f"Generator={config.is_generator}, Listening on Port={config.listen_port}"
    )

    # Start the listener thread
    listener = threading.Thread(target=udp_listener_thread, daemon=True)
    listener.start()

    # If this machine is the token generator, it creates and sends the first token.
    if config.is_generator:
        print_log("This machine is the token generator. Initiating token.")
        # Give a slight delay for other nodes to potentially start their listeners
        time.sleep(2)
        receive_token(is_regenerated=True)  # Simulate receiving a fresh token to start the process

    print_log("Application started. Type 'send <dest_nick> <message>' or 'quit'.")
    if config.is_generator:
        print_log(
            "Generator commands: 'gentoken' (manual generate), 'stoptoken' "
            "(debug clear local token)."
        )

    # Main loop for user input
    while True:
        try:
            user_input = input(f"[{config.nickname}]> ").strip()
            if not user_input:
                continue

            if user_input.lower() == "quit":
                print_log("Quitting...")
                if config.token_timer:
                    config.token_timer.cancel()  # Clean up timer
                udp_socket.close()  # Release socket
                break

            parts = user_input.split(" ", 2)
            command = parts[0].lower()

            if command == "send" and len(parts) == 3:
                dest_nickname = parts[1]
                message_text = parts[2]
                if len(message_queue) < MESSAGE_QUEUE_MAX_SIZE:
                    message_queue.append(
                        (dest_nickname, message_text, False)
                    )  # False for not a retransmission attempt yet
                    print_log(
                        f"Message to {dest_nickname} added to queue: '{message_text[:30]}...'"
                    )
                else:
                    print_log("Message queue is full. Cannot add message.")
            elif command == "queue":
                print_log(f"Current message queue (size {len(message_queue)}):")
                for i, (dest, msg, retx) in enumerate(list(message_queue)):
                    print_log(
                        f"  {i + 1}. To: {dest}, Msg: '{msg[:30]}...', RetxAttempted: {retx}"
                    )
            elif command == "token":  # Debug command
                print_log(f"Holds token: {has_token.is_set()}")
            elif command == "gentoken" and config.is_generator:
                print_log("Manually generating a new token (as generator).")
                receive_token(is_regenerated=True)
            elif command == "stoptoken" and config.is_generator:  # Debug for generator
                if has_token.is_set():
                    has_token.clear()
                    print_log("Debug: Cleared local token flag (as generator).")
                if config.token_timer:
                    config.token_timer.cancel()
                    print_log("Debug: Stopped token timer (as generator).")

            else:
                print_log(f"Unknown command or incorrect format: '{user_input}'")
                print_log("Use: send <dest_nick> <message_content>")

        except KeyboardInterrupt:
            print_log("\nCtrl+C detected. Quitting...")
            if config.token_timer:
                config.token_timer.cancel()
            udp_socket.close()
            break
        except Exception as e:
            print_log(f"Error in main loop: {e}")


if __name__ == "__main__":
    main()
