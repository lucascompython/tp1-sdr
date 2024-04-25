import base64
import json
import socket
from enum import Enum


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

    def to_change_room_packet(self) -> "ChangeRoomPacket":
        return ChangeRoomPacket(username=self.username, room=self.room)

    def to_nickname_packet(self) -> "NicknamePacket":
        return NicknamePacket(username=self.username, new_nickname=self.new_nickname)

    def to_join_packet(self) -> "JoinPacket":
        return JoinPacket(username=self.username)

    def to_leave_packet(self) -> "LeavePacket":
        return LeavePacket(username=self.username)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__dict__})"


class MessagePacket(BasePacket):
    def __init__(
        self, username: str, message: str, type: PacketType = PacketType.MESSAGE.value
    ):
        super().__init__(type=type, username=username)

        self.message = message


class ChangeRoomPacket(BasePacket):
    def __init__(
        self,
        username: str,
        room: str,
        type: PacketType = PacketType.CHANGE_ROOM.value,
    ):
        super().__init__(type=type, username=username)
        self.room = room


class NicknamePacket(BasePacket):
    def __init__(
        self,
        username: str,
        new_nickname: str,
        type: PacketType = PacketType.NICKNAME.value,
    ):
        super().__init__(type=type, username=username)
        self.new_nickname = new_nickname


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


class MessageType(Enum):
    GLOBAL = 0
    DIRECT = 1


def send_with_length(
    sock: socket.socket,
    data: bytes,
    type: MessageType = MessageType.GLOBAL.value,
) -> None:
    type_length = type.to_bytes(1, "big")  # type is an int here

    length = len(data).to_bytes(4, "big")

    sock.sendall(length + type_length + data)


def recv_with_length(
    sock: socket.socket,
) -> tuple[bytes, bool]:
    length = int.from_bytes(sock.recv(4), "big")
    is_direct = bool(int.from_bytes(sock.recv(1), "big"))
    return sock.recv(length), is_direct
