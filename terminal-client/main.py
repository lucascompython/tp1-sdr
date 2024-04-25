import base64
import json
import os
import socket
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Type

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared import CryptographyUtils, Packets
from colors import Colors


HOST, PORT = "localhost", 12345
CURRENT_CHAT: str | None = None  # None for global chat, username for private chat


def clear_screen() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def get_centered_title(term_width: int) -> str:

    title = "Global Chat Room"
    if CURRENT_CHAT:
        title = f"Private Chat Room - {CURRENT_CHAT}"

    title = f"{Colors.BOLD + title + Colors.RESET}"

    left_padding = (term_width - len(title)) // 2
    return " " * left_padding + title


def receive_messages(
    sock: socket.socket,
    messages: deque,
    username: str,
    term_size: os.terminal_size,
    private_key: RSAPrivateKey,
    public_keys: list[RSAPublicKey],
    usernames: list[str],
) -> None:
    while True:
        data = Packets.recv_with_length(sock)
        if not data:
            break

        data, signature = data[:-256], data[-256:]
        decrypted_data = CryptographyUtils.decrypt(data, private_key)

        json_decoded = json.loads(decrypted_data)

        match json_decoded["type"]:
            case Packets.PacketType.JOIN.value:
                if json_decoded["username"] not in usernames:
                    usernames.append(json_decoded["username"])

                pk = base64.b64decode(json_decoded["public_key"])
                if pk not in public_keys:
                    public_keys.append(CryptographyUtils.deserialize_public_key(pk))

                messages.append(
                    Colors.color_underline_user(
                        json_decoded["username"], "has joined the chat.", Colors.GREEN
                    )
                )

            case Packets.PacketType.STATUS.value:
                if json_decoded["username"] not in usernames:
                    usernames.append(json_decoded["username"])

                if messages and messages[-1].startswith(Colors.CYAN):
                    messages[-1] = (
                        f"{Colors.CYAN}Online users: {', '.join(usernames)}{Colors.RESET}"
                    )

                else:
                    messages.append(
                        f"{Colors.CYAN}Online users: {', '.join(usernames)}{Colors.RESET}"
                    )

        index = usernames.index(json_decoded["username"])
        pk = public_keys[index]
        # fake_random_signature = b"0" * 256
        if not CryptographyUtils.verify(signature, data, pk):
            messages.append(
                f"{Colors.RED}Invalid signature from {json_decoded['username']}{Colors.RESET}"
            )

        match json_decoded["type"]:

            case Packets.PacketType.STATUS_REQUEST.value:
                status_packet = Packets.StatusPacket(username=username)
                send_direct_message(sock, status_packet, private_key, pk)

            case Packets.PacketType.MESSAGE.value:
                prefix = ""
                if json_decoded["dm"]:
                    if not CURRENT_CHAT or CURRENT_CHAT != json_decoded["username"]:
                        prefix = "(DM) "
                else:
                    if CURRENT_CHAT:
                        prefix = "(GC) "

                messages.append(
                    f"{prefix}{json_decoded['username']}: {json_decoded['message']}"
                )

            case Packets.PacketType.LEAVE.value:
                if json_decoded["username"] in usernames:
                    usernames.remove(json_decoded["username"])

                pk = base64.b64decode(json_decoded["public_key"])

                for i, key in enumerate(public_keys):
                    if CryptographyUtils.serialize_public_key(key) == pk:
                        public_keys.pop(i)
                        break

                messages.append(
                    Colors.color_underline_user(
                        json_decoded["username"], "has left the chat.", Colors.YELLOW
                    )
                )

        clear_screen()
        print((get_centered_title(term_size.columns)))
        padding = term_size.lines - len(messages) - 2
        print("\n".join(messages) + "\n" * padding + f"\n{username}> ", end="")


def send_direct_message(
    sock: socket.socket,
    packet: Type[Packets.BasePacket],
    private_key: RSAPrivateKey,
    public_key: RSAPublicKey,
) -> None:
    encrypted_packet = CryptographyUtils.encrypt(packet.to_json().encode(), public_key)
    signature = CryptographyUtils.sign(encrypted_packet, private_key)

    Packets.send_with_length(
        sock,
        CryptographyUtils.serialize_public_key(public_key)
        + encrypted_packet
        + signature,
    )


def send_packet(
    sock: socket.socket,
    packet: Type[Packets.BasePacket],
    private_key: RSAPrivateKey,
    public_keys: list[RSAPublicKey],
):
    """Sends an encrypted packet with a signature to the server

    Args:
        sock (socket.socket): The socket to send the packet to
        packet (Type[Packets.BasePacket]): The packet to send
        private_key (RSAPrivateKey): The private key to sign the packet
        public_keys (list[RSAPublicKey]): The public keys to encrypt the packet
    """

    if not public_keys:
        return

    encrypted_packets = [
        CryptographyUtils.encrypt(packet.to_json().encode(), key) for key in public_keys
    ]

    signatures = [
        CryptographyUtils.sign(data, private_key) for data in encrypted_packets
    ]

    for encrypted_packet, signature, key in zip(
        encrypted_packets, signatures, public_keys
    ):
        Packets.send_with_length(
            sock,
            CryptographyUtils.serialize_public_key(key) + encrypted_packet + signature,
        )


def client_join(
    sock: socket.socket,
    username: str,
    public_key: RSAPublicKey,
    private_key: RSAPrivateKey,
) -> list[RSAPublicKey]:

    Packets.send_with_length(sock, CryptographyUtils.serialize_public_key(public_key))

    # Receive all the public keys from the server
    clients_public_keys = Packets.recv_with_length(sock)

    # Load the public keys
    clients_public_keys: list[bytes] = json.loads(clients_public_keys)

    clients_public_keys = [
        CryptographyUtils.deserialize_public_key(base64.b64decode(key))
        for key in clients_public_keys
    ]

    join_packet = Packets.JoinPacket(
        username=username, public_key=CryptographyUtils.serialize_public_key(public_key)
    )
    send_packet(sock, join_packet, private_key, clients_public_keys)

    status_request = Packets.StatusRequestPacket(username=username)
    send_packet(sock, status_request, private_key, clients_public_keys)

    return clients_public_keys


def main() -> None:
    global CURRENT_CHAT
    clear_screen()

    term_size = os.get_terminal_size()
    messages = deque(maxlen=term_size.lines - 2)

    private_key, public_key = CryptographyUtils.generate_key_pair()
    usernames = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        username = ""
        while not username:
            username = input("Enter your username: ").strip()

        clients_public_keys = client_join(sock, username, public_key, private_key)

        receive_thread = threading.Thread(
            target=receive_messages,
            args=(
                sock,
                messages,
                username,
                term_size,
                private_key,
                clients_public_keys,
                usernames,
            ),
            daemon=True,
        )
        receive_thread.start()

        clear_screen()
        messages.append("")

        try:
            while True:
                print((get_centered_title(term_size.columns)))
                padding = term_size.lines - len(messages) - 2
                padding = "\n" * padding

                print("\n".join(messages))

                message = input(f"{padding + username}> ").strip()

                if not message:
                    continue

                messages.append(
                    f"{Colors.UNDERLINE + username + Colors.RESET}: {message}"
                )

                message = message.lower().strip()
                if message in ("/exit", "/quit", "/q", "/e"):
                    print("Closing connection...")
                    break
                elif message == "/status":
                    status_request = Packets.StatusRequestPacket(username=username)
                    send_packet(sock, status_request, private_key, clients_public_keys)
                    continue
                elif message.startswith("/dm"):
                    message, user = message.split(" ")

                    if user not in usernames:
                        messages.append(f"{Colors.RED}User not found{Colors.RESET}")
                        continue
                    CURRENT_CHAT = user
                    continue

                elif message in ("/g", "/global"):
                    CURRENT_CHAT = None
                    continue

                elif message in ("/h", "/help"):
                    messages.append(Colors.BOLD + "Commands:")
                    messages.append("\t/exit, /quit, /q, /e: Exit the chat")
                    messages.append("\t/status: Check the status of all users")
                    messages.append("\t/dm <username>: Send a direct message to a user")
                    messages.append("\t/g, /global: Return to global chat")
                    messages.append("\t/h, /help: Show this message" + Colors.RESET)
                    continue
                elif message in ("/c", "/clear"):
                    messages.clear()
                    messages.append("")
                    continue

                if CURRENT_CHAT:
                    message_packet = Packets.MessagePacket(
                        username=username, message=message, dm=True
                    )
                    index = usernames.index(CURRENT_CHAT)
                    pk = clients_public_keys[index]
                    send_direct_message(sock, message_packet, private_key, pk)
                    continue

                packet = Packets.MessagePacket(username=username, message=message)

                send_packet(sock, packet, private_key, clients_public_keys)

        except KeyboardInterrupt:
            print("\nClosing connection...")
        finally:
            leave_packet = Packets.LeavePacket(
                username=username,
                public_key=CryptographyUtils.serialize_public_key(public_key),
            )
            send_packet(sock, leave_packet, private_key, clients_public_keys)
            sock.close()


if __name__ == "__main__":
    main()
