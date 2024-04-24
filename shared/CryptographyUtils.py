from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import hashlib


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


def _encrypt(data: bytes, key: rsa.RSAPublicKey) -> bytes:
    return key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _decrypt(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _encrypt_chunks(data: bytes, key: rsa.RSAPublicKey) -> bytes:
    return b"".join(_encrypt(data[i : i + 190], key) for i in range(0, len(data), 190))


def _decrypt_chunks(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return b"".join(_decrypt(data[i : i + 256], key) for i in range(0, len(data), 256))


def encrypt(data: bytes, key: rsa.RSAPublicKey) -> bytes:
    if len(data) > 190:
        return _encrypt_chunks(data, key)
    return _encrypt(data, key)


def decrypt(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    if len(data) > 251:
        return _decrypt_chunks(data, key)
    return _decrypt(data, key)


def sign(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    return key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )


def verify(signature: bytes, data: bytes, key: rsa.RSAPublicKey) -> bool:
    try:
        key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
