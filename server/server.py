import base64
import json
import socket
import socketserver
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from shared import Packets


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.clients: dict[bytes, socket.socket] = {}


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server: ThreadedTCPServer

        self.authenticate_user()

        try:
            while True:
                data = Packets.recv_with_length(self.request)
                if not data:
                    break

                public_key = data[:451]

                if public_key not in self.server.clients:
                    continue

                Packets.send_with_length(self.server.clients[public_key], data[451:])

        finally:
            del self.server.clients[self.public_key]

    def authenticate_user(self) -> None:
        self.public_key = Packets.recv_with_length(self.request)
        self.server.clients[self.public_key] = self.request

        public_keys = [
            base64.b64encode(key).decode()
            for key in self.server.clients
            if key != self.public_key
        ]

        Packets.send_with_length(self.request, json.dumps(public_keys).encode())

    def broadcast_message(self, message: bytes) -> None:
        """Sends a message to all connected users.

        Args:
            message (bytes): The message to send.
            exclude_user (bool, optional): If True, will send the message to all the users except itself. If False, sends to all users. Defaults to True.
        """
        for client_pk, sock in self.server.clients.items():
            if client_pk != self.public_key:
                Packets.send_with_length(sock, message)
