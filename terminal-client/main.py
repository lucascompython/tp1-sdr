import json
import socket
import sys
import threading
from pathlib import Path
import os
from collections import deque

sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared import MessagePacket, PacketType

HOST, PORT = "localhost", 12345


def clear_screen() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def receive_messages(
    sock: socket.socket, messages: deque, username: str, term_size: os.terminal_size
) -> None:
    while True:
        message = sock.recv(1024)

        json_decoded = json.loads(message)

        match json_decoded["type"]:
            case PacketType.MESSAGE.value:
                messages.append(
                    f"{json_decoded['username']}: {json_decoded['message']}"
                )
            case PacketType.LEAVE.value:
                messages.append(f"{json_decoded['username']} has left the chat.")
            case PacketType.JOIN.value:
                messages.append(f"{json_decoded['username']} has joined the chat.")
            case _:
                messages.append(json_decoded)

        clear_screen()
        padding = term_size.lines - len(messages) - 1
        print("\n".join(messages) + "\n" * padding + f"\n{username}> ", end="")


def main() -> None:

    clear_screen()

    messages = deque(maxlen=256)

    term_size = os.get_terminal_size()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        username = input("Enter your username: ")

        receive_thread = threading.Thread(
            target=receive_messages,
            args=(sock, messages, username, term_size),
            daemon=True,
        )
        receive_thread.start()

        clear_screen()

        sock.sendall(username.encode())

        try:
            while True:
                padding = term_size.lines - len(messages) - 1
                padding = "\n" * padding

                print("\n".join(messages))

                message = input(f"{padding + username}> ")
                messages.append(f"{username}: {message}")

                packet: MessagePacket = {
                    "type": PacketType.MESSAGE.value,
                    "username": username,
                    "message": message,
                }

                sock.sendall(json.dumps(packet).encode())

                if message.lower() in ("/exit", "/quit", "/q", "/e"):
                    break
        except KeyboardInterrupt:
            print("\nClosing connection...")
        finally:
            sock.close()


if __name__ == "__main__":
    main()
