import base64
import hashlib
import hmac
import os
import struct
import time
from io import BytesIO
from pathlib import Path
from urllib.parse import urlencode

import qrcode
from cryptography.fernet import Fernet, InvalidToken


def _key(data_directory):
    key_path = Path(data_directory) / "instance" / ".two_factor.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return key_path.read_bytes()


def _cipher(data_directory):
    return Fernet(_key(data_directory))


def create_secret():
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def encrypt_secret(secret, data_directory):
    return _cipher(data_directory).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(token, data_directory):
    try:
        return _cipher(data_directory).decrypt(token.encode("ascii")).decode("ascii")
    except (InvalidToken, AttributeError, UnicodeDecodeError):
        return None


def provisioning_uri(secret, username):
    label = f"Cyberseek:{username}"
    return "otpauth://totp/" + label + "?" + urlencode({
        "secret": secret,
        "issuer": "Cyberseek",
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    })


def qr_data_uri(uri):
    image = qrcode.make(uri, border=2)
    output = BytesIO()
    image.save(output, format="PNG")
    return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")


def _code(secret, counter):
    padding = "=" * (-len(secret) % 8)
    digest = hmac.new(base64.b32decode(secret + padding), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000
    return f"{value:06d}"


def valid_code(secret, submitted, now=None):
    code = "".join(character for character in str(submitted or "") if character.isdigit())
    if len(code) != 6 or not secret:
        return False
    counter = int((now if now is not None else time.time()) // 30)
    return any(hmac.compare_digest(code, _code(secret, counter + skew)) for skew in (-1, 0, 1))
