"""Text encryption with Caesar, Vigenere, and XOR ciphers.

Covers: bytes/bytearray, bitwise operations, zip, enumerate,
        classmethod, property, abstract base class, __bytes__,
        memoryview, struct-like packing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Protocol


class CipherType(Enum):
    """Supported cipher types."""

    CAESAR = auto()
    VIGENERE = auto()
    XOR = auto()
    ROT13 = auto()
    ATBASH = auto()


class Cipher(ABC):
    """Abstract base for all ciphers."""

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext."""

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext."""

    @property
    @abstractmethod
    def cipher_type(self) -> CipherType:
        """Return the cipher type."""


class Encodable(Protocol):
    """Protocol for objects that can be encoded to bytes."""

    def to_bytes(self) -> bytes: ...


class CaesarCipher(Cipher):
    """Classic Caesar shift cipher."""

    def __init__(self, shift: int = 3) -> None:
        self._shift = shift % 26

    @property
    def cipher_type(self) -> CipherType:
        return CipherType.CAESAR

    @property
    def shift(self) -> int:
        return self._shift

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, self._shift)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, -self._shift)

    @staticmethod
    def _transform(text: str, shift: int) -> str:
        result: list[str] = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shifted = (ord(ch) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(ch)
        return "".join(result)

    @classmethod
    def brute_force(cls, ciphertext: str) -> list[tuple[int, str]]:
        """Try all 26 shifts and return results."""
        return [
            (shift, cls(shift).decrypt(ciphertext))
            for shift in range(26)
        ]


class VigenereCipher(Cipher):
    """Vigenere cipher with repeating key."""

    def __init__(self, key: str) -> None:
        if not key or not key.isalpha():
            raise ValueError("Key must be non-empty alphabetic string")
        self._key = key.upper()

    @property
    def cipher_type(self) -> CipherType:
        return CipherType.VIGENERE

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext, encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext, encrypt=False)

    def _transform(self, text: str, encrypt: bool) -> str:
        result: list[str] = []
        key_index = 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                key_shift = ord(self._key[key_index % len(self._key)]) - ord("A")
                if not encrypt:
                    key_shift = -key_shift
                shifted = (ord(ch) - base + key_shift) % 26 + base
                result.append(chr(shifted))
                key_index += 1
            else:
                result.append(ch)
        return "".join(result)


class XORCipher(Cipher):
    """XOR cipher operating on bytes."""

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("Key must not be empty")
        self._key = key

    @property
    def cipher_type(self) -> CipherType:
        return CipherType.XOR

    def encrypt(self, plaintext: str) -> str:
        """Encrypt and return hex-encoded string."""
        data = plaintext.encode("utf-8")
        encrypted = self._xor_bytes(data)
        return encrypted.hex()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt hex-encoded string."""
        data = bytes.fromhex(ciphertext)
        decrypted = self._xor_bytes(data)
        return decrypted.decode("utf-8")

    def _xor_bytes(self, data: bytes) -> bytes:
        """XOR data with repeating key."""
        result = bytearray(len(data))
        for i, byte in enumerate(data):
            result[i] = byte ^ self._key[i % len(self._key)]
        return bytes(result)

    @classmethod
    def from_passphrase(cls, passphrase: str) -> XORCipher:
        """Create cipher from a passphrase."""
        import hashlib
        key = hashlib.sha256(passphrase.encode()).digest()[:16]
        return cls(key)


class ROT13Cipher(Cipher):
    """ROT13 — special case of Caesar with shift 13."""

    def __init__(self) -> None:
        self._caesar = CaesarCipher(13)

    @property
    def cipher_type(self) -> CipherType:
        return CipherType.ROT13

    def encrypt(self, plaintext: str) -> str:
        return self._caesar.encrypt(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return self._caesar.encrypt(ciphertext)  # ROT13 is self-inverse


class AtbashCipher(Cipher):
    """Atbash cipher — reverses the alphabet."""

    @property
    def cipher_type(self) -> CipherType:
        return CipherType.ATBASH

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext)  # Atbash is self-inverse

    @staticmethod
    def _transform(text: str) -> str:
        result: list[str] = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr(base + 25 - (ord(ch) - base)))
            else:
                result.append(ch)
        return "".join(result)


@dataclass
class EncryptedMessage:
    """An encrypted message with metadata."""

    ciphertext: str
    cipher_type: CipherType
    original_length: int

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        header = self.cipher_type.value.to_bytes(1, "big")
        length = self.original_length.to_bytes(4, "big")
        payload = self.ciphertext.encode("utf-8")
        return header + length + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedMessage:
        """Deserialize from bytes."""
        cipher_type = CipherType(data[0])
        original_length = int.from_bytes(data[1:5], "big")
        ciphertext = data[5:].decode("utf-8")
        return cls(ciphertext=ciphertext, cipher_type=cipher_type, original_length=original_length)


class CipherFactory:
    """Factory for creating cipher instances."""

    _registry: dict[CipherType, type[Cipher]] = {
        CipherType.CAESAR: CaesarCipher,
        CipherType.VIGENERE: VigenereCipher,
        CipherType.XOR: XORCipher,
        CipherType.ROT13: ROT13Cipher,
        CipherType.ATBASH: AtbashCipher,
    }

    @classmethod
    def create(cls, cipher_type: CipherType, **kwargs) -> Cipher:
        """Create a cipher by type."""
        cipher_cls = cls._registry.get(cipher_type)
        if cipher_cls is None:
            raise ValueError(f"Unknown cipher type: {cipher_type}")
        return cipher_cls(**kwargs)

    @classmethod
    def register(cls, cipher_type: CipherType, cipher_cls: type[Cipher]) -> None:
        """Register a new cipher type."""
        cls._registry[cipher_type] = cipher_cls


class FrequencyAnalyzer:
    """Letter frequency analysis for breaking simple ciphers."""

    ENGLISH_FREQ: dict[str, float] = {
        "E": 12.7, "T": 9.1, "A": 8.2, "O": 7.5, "I": 7.0,
        "N": 6.7, "S": 6.3, "H": 6.1, "R": 6.0, "D": 4.3,
    }

    @staticmethod
    def count_frequencies(text: str) -> dict[str, float]:
        """Count letter frequencies as percentages."""
        letters = [ch.upper() for ch in text if ch.isalpha()]
        total = len(letters)
        if total == 0:
            return {}
        freq: dict[str, int] = {}
        for ch in letters:
            freq[ch] = freq.get(ch, 0) + 1
        return {ch: (count / total) * 100 for ch, count in sorted(freq.items())}

    @classmethod
    def score_english(cls, text: str) -> float:
        """Score how likely text is English (lower = more likely)."""
        freq = cls.count_frequencies(text)
        score = 0.0
        for letter, expected in cls.ENGLISH_FREQ.items():
            actual = freq.get(letter, 0.0)
            score += abs(expected - actual)
        return score

    @classmethod
    def guess_caesar_shift(cls, ciphertext: str) -> int:
        """Guess the most likely Caesar shift."""
        best_shift = 0
        best_score = float("inf")
        for shift in range(26):
            decrypted = CaesarCipher(shift).decrypt(ciphertext)
            score = cls.score_english(decrypted)
            if score < best_score:
                best_score = score
                best_shift = shift
        return best_shift
