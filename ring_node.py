import argparse
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
CRC_ERROR_PLACEHOLDER = "-1"  # Value to indicate CRC calculation failure due to encoding
DEBUG_VERBOSE_LOGGING = False  # NEW: Flag for verbose logging control


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

listener_should_stop = threading.Event()  # NEW: For graceful shutdown of listener

last_sent_message_details = None  # Holds info about the data packet this node sent


# --- Utility Functions ---
def calculate_crc32(data: str) -> str:
    """Calculates CRC32 for the given string data and returns as a string."""
    try:
        # Ensure bytes for CRC calculation
        crc_val = zlib.crc32(data.encode("utf-8"))
        return str(crc_val)
    except UnicodeEncodeError:
        if DEBUG_VERBOSE_LOGGING:
            print_log(
                f"Error: Could not encode message for CRC calculation due to invalid characters: '{data[:50]}...'"
            )
        return CRC_ERROR_PLACEHOLDER  # Return a specific value indicating encoding failure


def verify_crc32(data: str, expected_crc: str) -> bool:
    """Verifies if the calculated CRC32 matches the expected CRC."""
    # NEW: Check if expected_crc itself indicates a prior calculation error
    if expected_crc == CRC_ERROR_PLACEHOLDER:
        # This implies the sender couldn't calculate CRC, so it should be treated as an error by receiver if it also can't, or a mismatch.
        # Or, if the current node calculates CRC_ERROR_PLACEHOLDER, it's a mismatch against a valid CRC.
        # Effectively, if either is CRC_ERROR_PLACEHOLDER, it implies a problem somewhere.
        # For simplicity, if expected_crc is this, we assume the data is bad or unprocessable.
        return False

    calculated_crc = calculate_crc32(data)
    if calculated_crc == CRC_ERROR_PLACEHOLDER:
        return False  # Current node failed to calculate CRC on received data

    if not expected_crc.isdigit():  # Original check for valid numeric CRC format from sender
        if DEBUG_VERBOSE_LOGGING:
            print_log(f"Invalid expected CRC format: {expected_crc}. Assuming CRC check failed.")
        return False
    return calculated_crc == expected_crc


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
        if DEBUG_VERBOSE_LOGGING:
            print_log(
                f"Error parsing data packet: {packet_str}. Expected 5 parts, got {len(parts)}"
            )
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
    except socket.gaierror:
        print_log(f"Error: Hostname {dest_ip} could not be resolved. Message not sent.")
    except OSError as e:  # Catch OSError which can happen if socket is closed during send
        if e.errno == 9:  # Bad file descriptor
            print_log("Warning: Attempted to send packet on a closed socket.")
        else:
            print_log(f"Error sending packet to {dest_ip}:{dest_port}: {e}")
    except Exception as e:
        print_log(f"Error sending packet to {dest_ip}:{dest_port}: {e}")


def forward_token():
    """Forwards the token to the right neighbor."""
    global has_token
    if has_token.is_set():
        if DEBUG_VERBOSE_LOGGING:
            print_log(
                f"Forwarding token to {config.right_neighbor_ip}:{config.right_neighbor_port}"
            )
        send_packet(TOKEN_PACKET_ID, config.right_neighbor_ip, config.right_neighbor_port)
        has_token.clear()
        if config.is_generator:
            start_token_timer()


def start_token_timer():
    """For token generator: starts/restarts the timer to detect lost token."""
    if config.token_timer:
        config.token_timer.cancel()
    config.token_timer = threading.Timer(config.TOKEN_TIMEOUT_SECONDS, handle_token_timeout)
    config.token_timer.daemon = True  # Allow main program to exit even if timer is active
    config.token_timer.start()


def handle_token_timeout():
    """For token generator: called when token hasn't returned in time."""
    print_log("Token timeout! Token might be lost. Regenerating token.")
    has_token.clear()
    receive_token(is_regenerated=True)  # Simulate receiving a new token to kickstart


def receive_token(is_regenerated=False):
    """Handles this machine receiving the token."""
    global has_token

    if config.is_generator and not is_regenerated:
        if config.token_timer:
            config.token_timer.cancel()
        # else: pass - (original logic)

    if has_token.is_set() and not is_regenerated:
        if config.is_generator:
            print_log("Duplicate token detected by generator. Discarding incoming token.")
            return
        else:
            # Any node receiving a token when it already has one (and it wasn't just regenerated by self)
            # should probably discard it to help with multiple token scenarios.
            print_log(
                "Warning: Received token while already holding one. Discarding incoming token."
            )
            return

    has_token.set()
    print_log("Received token.")

    time.sleep(config.token_hold_time)

    if message_queue:
        dest_nick, msg_content, retransmission_attempted = message_queue.popleft()
        print_log(f"Have message for {dest_nick}: '{msg_content[:30]}...'. Preparing to send.")

        current_status = STATUS_NAOEXISTE
        message_to_send_after_fault_injection = msg_content

        # Fault Injection: Changed to be more robust against creating invalid UTF-8 sequences
        # The goal is for CRC to fail, not for encoding/decoding to fail.
        if (
            random.random() < 0.1
        ):  # 10% chance of fault (user had 0.9, reverting to lower for typical testing)
            if dest_nick == BROADCAST_NICKNAME:
                print_log(
                    "Fault Injection: Ensuring 'naoexiste' for broadcast (no data change for this type of fault)."
                )
            else:  # Unicast fault
                if msg_content:
                    # Simpler corruption: append a character or replace one.
                    # This is less likely to create encoding issues than bit flipping random bytes.
                    # faulty_char_index = random.randint(0, len(msg_content) - 1)
                    # char_list = list(msg_content)
                    # char_list[faulty_char_index] = 'X' # Corrupt with a known valid char
                    # message_to_send_after_fault_injection = "".join(char_list)
                    message_to_send_after_fault_injection = msg_content + "~"  # Append to corrupt
                    print_log(
                        f"Fault Injection: Corrupted message for {dest_nick}. "
                        f"Original: '{msg_content[:30]}...', Faulty: '{message_to_send_after_fault_injection[:30]}...'"
                    )
                else:
                    if DEBUG_VERBOSE_LOGGING:
                        print_log(
                            f"Fault Injection: Message for {dest_nick} is empty, no data corruption applied."
                        )

        crc = calculate_crc32(message_to_send_after_fault_injection)
        # If CRC calculation failed (e.g. encoding error despite simpler fault injection try)
        # we must still send *something* for CRC. The assignment implies CRC is always present.
        # Send the placeholder if calculate_crc32 returned it.
        # The receiver's verify_crc32 will handle this specific placeholder as an error.

        if dest_nick == BROADCAST_NICKNAME:
            current_status = STATUS_NAOEXISTE

        data_packet = create_data_packet(
            status=current_status,
            source_nickname=config.nickname,
            destination_nickname=dest_nick,
            message=message_to_send_after_fault_injection,
            crc_val=crc,  # This will be CRC_ERROR_PLACEHOLDER if calculate_crc32 failed
        )
        print_log(f"Sending data packet: '{data_packet[:100]}...'")
        send_packet(data_packet, config.right_neighbor_ip, config.right_neighbor_port)

        global last_sent_message_details
        last_sent_message_details = {
            "original_dest_nick": dest_nick,
            "original_msg_content": msg_content,
            "retransmission_attempted": retransmission_attempted,
            "is_broadcast": dest_nick == BROADCAST_NICKNAME,
            "crc_of_sent_msg": crc,
        }
    else:
        if DEBUG_VERBOSE_LOGGING:
            print_log("Message queue empty.")
        forward_token()


# --- Packet Processing Logic ---
def process_incoming_packet(packet_str: str, sender_address: tuple):
    global has_token, message_queue, last_sent_message_details
    # sender_ip, sender_port = sender_address # Unused, can be removed if not logging sender IP

    if packet_str == TOKEN_PACKET_ID:
        receive_token()
        return

    data_info = parse_data_packet(packet_str)
    if data_info:
        time.sleep(config.token_hold_time)

        is_dest_me = data_info["destination_nickname"] == config.nickname
        is_src_me = data_info["source_nickname"] == config.nickname
        is_broadcast = data_info["destination_nickname"] == BROADCAST_NICKNAME

        if is_dest_me or (is_broadcast and not is_src_me):
            if is_broadcast:
                print_log(
                    f"Broadcast packet from {data_info['source_nickname']} for {data_info['destination_nickname']}: '{data_info['message'][:30]}...'"
                )
                if DEBUG_VERBOSE_LOGGING:
                    print_log(f"Forwarding broadcast packet: '{packet_str[:100]}...'")
                send_packet(packet_str, config.right_neighbor_ip, config.right_neighbor_port)
                return
            else:
                print_log(
                    f"Data packet for me from {data_info['source_nickname']}: "
                    f"'{data_info['message'][:30]}...'"
                )
                crc_ok = verify_crc32(data_info["message"], data_info["crc"])
                new_status = STATUS_ACK if crc_ok else STATUS_NACK
                print_log(
                    f"CRC check: {'OK' if crc_ok else 'FAIL'}. "
                    # f"Original CRC: {data_info['crc']}, " # Reduced verbosity
                    # f"Calculated on: '{data_info['message']}'. " # Reduced verbosity
                    f"Sending {new_status}."
                )
                response_packet = create_data_packet(
                    status=new_status,
                    source_nickname=data_info["source_nickname"],
                    destination_nickname=data_info["destination_nickname"],
                    message=data_info["message"],
                    crc_val=data_info["crc"],
                )
                if DEBUG_VERBOSE_LOGGING:
                    print_log(f"Sending data packet response: '{response_packet[:100]}...'")
                send_packet(response_packet, config.right_neighbor_ip, config.right_neighbor_port)

        elif is_src_me:
            print_log(f"My data packet returned. Status from ring: {data_info['status']}")

            if not last_sent_message_details:
                print_log(
                    "Warning: Received self-originated packet, but no details of last sent message. Ignoring."
                )
                if has_token.is_set():
                    forward_token()
                return

            original_dest = last_sent_message_details["original_dest_nick"]
            original_msg = last_sent_message_details["original_msg_content"]
            was_retransmission_attempt = last_sent_message_details["retransmission_attempted"]
            is_sent_broadcast = last_sent_message_details["is_broadcast"]
            crc_of_sent_msg = last_sent_message_details["crc_of_sent_msg"]

            effective_status = data_info["status"]

            if original_dest == config.nickname and not is_sent_broadcast:
                if data_info["status"] == STATUS_NAOEXISTE and data_info["crc"] == crc_of_sent_msg:
                    print_log(
                        f"Self-addressed message '{original_msg[:30]}...' returned. Performing local ACK/NACK."
                    )
                    crc_ok_for_self = verify_crc32(data_info["message"], data_info["crc"])
                    effective_status = STATUS_ACK if crc_ok_for_self else STATUS_NACK
                    print_log(
                        f"Local CRC check for self-message: {'OK' if crc_ok_for_self else 'FAIL'}. Effective status: {effective_status}"
                    )

            last_sent_message_details = None

            if is_sent_broadcast:
                print_log(f"My broadcast '{original_msg[:30]}...' completed round.")
            elif effective_status == STATUS_ACK:
                print_log(f"Message to {original_dest} ACKed: '{original_msg[:30]}...'")
            elif effective_status == STATUS_NAOEXISTE:
                print_log(f"Message to {original_dest} return NAOEXISTE: '{original_msg[:30]}...'")
            elif effective_status == STATUS_NACK:
                print_log(f"Message to {original_dest} NACKed: '{original_msg[:30]}...'.")
                if not was_retransmission_attempt:
                    print_log("Will retransmit once.")
                    message_queue.appendleft((original_dest, original_msg, True))
                else:
                    print_log("Already attempted retransmission. Message dropped.")
            else:
                print_log(
                    f"My data packet returned with unknown status '{effective_status}'. Treating as failed."
                )

            if has_token.is_set():
                forward_token()
            else:
                print_log("Warning: My data packet returned, but I don't have the token.")

        elif not is_dest_me and not is_src_me and not is_broadcast:
            if DEBUG_VERBOSE_LOGGING:
                print_log(
                    f"Forwarding data packet from {data_info['source_nickname']} for {data_info['destination_nickname']}"
                )
            send_packet(packet_str, config.right_neighbor_ip, config.right_neighbor_port)

    else:
        if DEBUG_VERBOSE_LOGGING:
            print_log(f"Received unknown/malformed packet: '{packet_str[:50]}...'")
        pass


# --- Main Application Logic ---
def udp_listener_thread():
    if DEBUG_VERBOSE_LOGGING:
        print_log(f"Listener thread started. Binding to 0.0.0.0:{config.listen_port}")
    try:
        udp_socket.bind(("0.0.0.0", config.listen_port))
        udp_socket.settimeout(1.0)
    except OSError as e:
        print_log(f"ERROR: Could not bind to port {config.listen_port}. {e}")
        listener_should_stop.set()
        return

    while not listener_should_stop.is_set():
        try:
            data, addr = udp_socket.recvfrom(2048)
            packet_str = data.decode("utf-8")
            process_incoming_packet(packet_str, addr)
        except socket.timeout:
            continue
        except UnicodeDecodeError:
            if DEBUG_VERBOSE_LOGGING:
                print_log(f"Received packet with undecodeable content from {addr}.")
            pass
        except OSError as e:
            if listener_should_stop.is_set() and e.errno == 9:
                if DEBUG_VERBOSE_LOGGING:
                    print_log("Listener thread: socket closed during shutdown.")
                break
            print_log(f"OS Error in listener thread: {e}")
            time.sleep(0.1)
        except Exception as e:
            print_log(f"Unhandled error in listener thread: {e}")
            time.sleep(0.1)
    if DEBUG_VERBOSE_LOGGING:
        print_log("Listener thread stopped.")


def load_config(filepath="config.txt") -> Config | None:
    try:
        with open(filepath, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            if len(lines) != 5:
                print(f"Error: Config file '{filepath}' must have 5 lines. Found {len(lines)}.")
                return None

            my_listen_port_str = lines[0]
            dest_full_address = lines[1]
            nickname = lines[2]
            token_time_str = lines[3]
            is_gen_str = lines[4].strip().lower()

            if not my_listen_port_str.isdigit():
                print(f"Error: My listen port '{my_listen_port_str}' must be a number.")
                return None
            my_listen_port_val = int(my_listen_port_str)

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

            if not token_time_str.replace(".", "", 1).isdigit():
                print(f"Error: Token time '{token_time_str}' must be a number.")
                return None
            token_time = float(token_time_str)

            if is_gen_str not in ["true", "false"]:
                print(f"Error: is_token_generator ('{is_gen_str}') must be 'true' or 'false'.")
                return None
            is_gen = is_gen_str == "true"

            listen_port = my_listen_port_val

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


listener_thread_obj = None


def main():
    global config, listener_thread_obj

    parser = argparse.ArgumentParser(description="Token Ring Node Simulator")
    parser.add_argument(
        "--config",
        type=str,
        default="config.txt",
        help="Path to the configuration file (default: config.txt)",
    )
    args = parser.parse_args()
    config_file_path = args.config

    print(f"Attempting to load configuration from: {config_file_path}")
    local_config = load_config(config_file_path)
    if not local_config:
        print("Exiting due to configuration errors.")
        return
    config = local_config

    print_log(
        f"Init: Nick={config.nickname}, Neighbor={config.right_neighbor_ip}:{config.right_neighbor_port}, "
        f"Hold={config.token_hold_time}s, Gen={config.is_generator}, ListenPort={config.listen_port}"
    )

    listener_thread_obj = threading.Thread(target=udp_listener_thread, daemon=True)
    listener_thread_obj.start()

    if config.is_generator:
        print_log("This machine is the token generator. Initiating token.")
        time.sleep(1)
        receive_token(is_regenerated=True)

    print_log("App started. CLI: 'send <nick> <msg>', 'queue', 'gentoken', 'token', 'quit'.")
    # if config.is_generator: # Removed to allow gentoken from any node later
    #     print_log("Generator commands: 'stoptoken' (debug clear local token).")

    while True:
        try:
            if listener_should_stop.is_set() and (
                not listener_thread_obj or not listener_thread_obj.is_alive()
            ):
                print_log("Listener inactive. Exiting main loop.")
                break

            user_input = input(f"[{config.nickname}]> ").strip()
            if not user_input:
                continue

            if user_input.lower() == "quit":
                print_log("Quitting...")
                listener_should_stop.set()
                if config.token_timer:
                    config.token_timer.cancel()
                if listener_thread_obj:
                    listener_thread_obj.join(timeout=2.0)
                    if listener_thread_obj.is_alive() and DEBUG_VERBOSE_LOGGING:
                        print_log("Warning: Listener thread did not stop in time.")
                udp_socket.close()
                print_log("Socket closed. Exiting.")
                break

            parts = user_input.split(" ", 2)
            command = parts[0].lower()

            if command == "send" and len(parts) == 3:
                dest_nickname = parts[1]
                message_text = parts[2]
                if len(message_queue) < MESSAGE_QUEUE_MAX_SIZE:
                    message_queue.append((dest_nickname, message_text, False))
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
            elif command == "token":
                print_log(f"Holds token: {has_token.is_set()}")
            # MODIFIED: gentoken can be called by any node
            elif command == "gentoken":
                print_log("User command: Manually generating a new token.")
                # Any node can attempt to generate. It will set its own `has_token`
                # and then try to send a message or forward the token.
                # The existing duplicate detection in receive_token() will help if multiple tokens appear.
                receive_token(is_regenerated=True)
            elif (
                command == "stoptoken" and config.is_generator
            ):  # stoptoken remains for original generator for debug
                if has_token.is_set():
                    has_token.clear()
                    print_log("Debug: Cleared local token flag (as generator).")
                if config.token_timer:
                    config.token_timer.cancel()
                    print_log("Debug: Stopped token timer (as generator).")
            else:
                print_log(f"Unknown command or incorrect format: '{user_input}'")

        except KeyboardInterrupt:
            print_log("\nCtrl+C. Graceful shutdown...")
            listener_should_stop.set()
            if config.token_timer:
                config.token_timer.cancel()
            if listener_thread_obj:
                listener_thread_obj.join(timeout=2.0)
            udp_socket.close()
            print_log("Socket closed. Exiting.")
            break
        except EOFError:
            print_log("EOF. Graceful shutdown...")
            listener_should_stop.set()
            if config.token_timer:
                config.token_timer.cancel()
            if listener_thread_obj:
                listener_thread_obj.join(timeout=2.0)
            udp_socket.close()
            print_log("Socket closed. Exiting.")
            break
        except Exception as e:
            print_log(f"Error in main loop: {e}")
            listener_should_stop.set()
            if listener_thread_obj and listener_thread_obj.is_alive():
                listener_thread_obj.join(timeout=1.0)
            # Check if socket is already closed before trying to close again
            # This check might be tricky if error was from udp_socket itself being None or invalid
            try:
                if udp_socket.fileno() != -1:  # Check if socket is open
                    udp_socket.close()
            except Exception:  # Broad except for socket status check/close issues
                if DEBUG_VERBOSE_LOGGING:
                    print_log("Exception during final socket close attempt in error handler.")
                pass
            break


if __name__ == "__main__":
    main()
