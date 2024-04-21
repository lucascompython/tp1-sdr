import json
from enum import Enum

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class PacketType(Enum):
    MESSAGE = 1
    JOIN = 2
    LEAVE = 3
    NICKNAME = 4
    CHANGE_ROOM = 5


class BasePacket:
    type: PacketType
    username: str

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
    def __init__(self, username: str, type: PacketType = PacketType.JOIN.value):
        super().__init__(type=type, username=username)


class LeavePacket(BasePacket):
    def __init__(self, username: str, type: PacketType = PacketType.LEAVE.value):
        super().__init__(type=type, username=username)


def generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key


def serialize_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_key(data: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(data, backend=default_backend())


def deserialize_public_key(data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(data, backend=default_backend())


def encrypt(data: bytes, key: rsa.RSAPublicKey) -> bytes:
    return key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )


def verify(signature: bytes, data: bytes, key: rsa.RSAPublicKey) -> None:
    key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
