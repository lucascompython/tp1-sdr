import base64
import json
import socket
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from typing import Type


from shared import CryptographyUtils


class PacketType(Enum):
    MESSAGE = 1
    JOIN = 2
    LEAVE = 3
    NICKNAME = 4
    CHANGE_ROOM = 5
    STATUS_REQUEST = 6
    STATUS = 7


class BasePacket:

    def __init__(self, type: PacketType, username: str):
        self.type = type
        self.username = username

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, data: str) -> "BasePacket":
        return cls(**json.loads(data))

    def to_message_packet(self) -> "MessagePacket":
        return MessagePacket(username=self.username, message=self.message)

    def to_join_packet(self) -> "JoinPacket":
        return JoinPacket(username=self.username)

    def to_leave_packet(self) -> "LeavePacket":
        return LeavePacket(username=self.username)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__dict__})"


class MessagePacket(BasePacket):
    def __init__(
        self,
        username: str,
        message: str,
        dm: bool = False,
        type: PacketType = PacketType.MESSAGE.value,
    ):
        super().__init__(type=type, username=username)

        self.message = message
        self.dm = dm


class JoinPacket(BasePacket):
    def __init__(
        self, username: str, public_key: bytes, type: PacketType = PacketType.JOIN.value
    ):
        super().__init__(type=type, username=username)
        self.public_key = base64.b64encode(public_key).decode()


class LeavePacket(BasePacket):
    def __init__(
        self,
        username: str,
        public_key: bytes,
        type: PacketType = PacketType.LEAVE.value,
    ):
        super().__init__(type=type, username=username)
        self.public_key = base64.b64encode(public_key).decode()


class StatusRequestPacket(BasePacket):
    def __init__(
        self, username: str, type: PacketType = PacketType.STATUS_REQUEST.value
    ):
        super().__init__(type=type, username=username)


class StatusPacket(BasePacket):
    def __init__(
        self,
        username: str,
        type: PacketType = PacketType.STATUS.value,
    ):
        super().__init__(type=type, username=username)


def send_with_length(
    sock: socket.socket,
    data: bytes,
) -> None:
    length = len(data).to_bytes(4, "big")

    sock.sendall(length + data)


def recv_with_length(
    sock: socket.socket,
) -> bytes:
    length = int.from_bytes(sock.recv(4), "big")
    return sock.recv(length)


def send_direct_message(
    sock: socket.socket,
    packet: Type[BasePacket],
    private_key: RSAPrivateKey,
    public_key: RSAPublicKey,
) -> None:
    encrypted_packet = CryptographyUtils.encrypt(packet.to_json().encode(), public_key)
    signature = CryptographyUtils.sign(encrypted_packet, private_key)

    send_with_length(
        sock,
        CryptographyUtils.serialize_public_key(public_key)
        + encrypted_packet
        + signature,
    )


def send_packet(
    sock: socket.socket,
    packet: Type[BasePacket],
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
        send_with_length(
            sock,
            CryptographyUtils.serialize_public_key(key) + encrypted_packet + signature,
        )


def client_join(
    sock: socket.socket,
    username: str,
    public_key: RSAPublicKey,
    private_key: RSAPrivateKey,
) -> list[RSAPublicKey]:

    send_with_length(sock, CryptographyUtils.serialize_public_key(public_key))

    # Receive all the public keys from the server
    clients_public_keys = recv_with_length(sock)

    # Load the public keys
    clients_public_keys: list[bytes] = json.loads(clients_public_keys)

    clients_public_keys = [
        CryptographyUtils.deserialize_public_key(base64.b64decode(key))
        for key in clients_public_keys
    ]

    join_packet = JoinPacket(
        username=username, public_key=CryptographyUtils.serialize_public_key(public_key)
    )
    send_packet(sock, join_packet, private_key, clients_public_keys)

    status_request = StatusRequestPacket(username=username)
    send_packet(sock, status_request, private_key, clients_public_keys)

    return clients_public_keys
