import base64
import json
import os
import socket
import sys
import threading
from collections import deque
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

sys.path.append(str(Path(__file__).resolve().parent.parent))
from colors import Colors

from shared import CryptographyUtils, Packets

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
    global CURRENT_CHAT
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

                pk = CryptographyUtils.deserialize_public_key(
                    base64.b64decode(json_decoded["public_key"])
                )
                if pk not in public_keys:
                    public_keys.append(pk)

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
                Packets.send_direct_message(sock, status_packet, private_key, pk)

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

                if json_decoded["username"] == CURRENT_CHAT:
                    CURRENT_CHAT = None

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

        clients_public_keys = Packets.client_join(
            sock, username, public_key, private_key
        )

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
                    Packets.send_packet(
                        sock, status_request, private_key, clients_public_keys
                    )
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
                    Packets.send_direct_message(sock, message_packet, private_key, pk)
                    continue

                packet = Packets.MessagePacket(username=username, message=message)

                Packets.send_packet(sock, packet, private_key, clients_public_keys)

        except KeyboardInterrupt:
            print("\nClosing connection...")
        finally:
            leave_packet = Packets.LeavePacket(
                username=username,
                public_key=CryptographyUtils.serialize_public_key(public_key),
            )
            Packets.send_packet(sock, leave_packet, private_key, clients_public_keys)
            sock.close()


if __name__ == "__main__":
    main()
