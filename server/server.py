import json
import socket
import socketserver
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from shared import BasePacket, JoinPacket, LeavePacket, PacketType


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.users: dict[str, socket.socket] = {}


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server: ThreadedTCPServer

        self.username = self.authenticate_user()

        self.server.users[self.username] = self.request

        self.broadcast_message(
            JoinPacket(username=self.username, type=PacketType.JOIN.value)
        )

        try:
            while True:
                data: bytes = self.request.recv(1024).strip()
                if not data:
                    break

                packet: BasePacket = json.loads(data.decode())
                if packet["type"] == PacketType.MESSAGE.value:
                    print(f"Received data from {self.username}: {packet['message']}")

                    self.broadcast_message(packet)

        finally:
            del self.server.users[self.username]

            self.broadcast_message(
                LeavePacket(username=self.username, type=PacketType.LEAVE.value)
            )

    def authenticate_user(self) -> str:
        username: bytes = self.request.recv(1024).strip()
        return username.decode()

    def broadcast_message(self, packet: BasePacket, exclude_user: bool = True) -> None:
        """Sends a message to all connected users.

        Args:
            message (bytes): The message to send.
            exclude_user (bool, optional): If True, will send the message to all the users except itself. If False, sends to all users. Defaults to True.
        """
        for user, sock in self.server.users.items():
            if user != self.username or not exclude_user:
                sock.sendall(json.dumps(packet).encode())
