import json
import socket
import sys
import threading
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared import MessagePacket, PacketType

HOST, PORT = "localhost", 12345


def receive_messages(sock: socket.socket) -> None:
    while True:
        message = sock.recv(1024)

        json_decoded = json.loads(message)

        match json_decoded["type"]:
            case PacketType.MESSAGE.value:
                print(f"{json_decoded['username']}: {json_decoded['message']}")
            case PacketType.LEAVE.value:
                print(f"{json_decoded['username']} has left the chat.")
            case PacketType.JOIN.value:
                print(f"{json_decoded['username']} has joined the chat.")
            case _:
                print(json_decoded)


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        receive_thread = threading.Thread(
            target=receive_messages, args=(sock,), daemon=True
        )
        receive_thread.start()

        username = input("Enter your username: ")

        sock.sendall(username.encode())

        try:
            while True:
                message = input("> ")
                packet: MessagePacket = {
                    "type": PacketType.MESSAGE.value,
                    "username": username,
                    "message": message,
                }

                sock.sendall(json.dumps(packet).encode())

                if message.lower() == "/exit":
                    break
        except KeyboardInterrupt:
            print("\nClosing connection...")
        finally:
            sock.close()


if __name__ == "__main__":
    main()
