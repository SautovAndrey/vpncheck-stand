#!/usr/bin/env python3
"""Создать ключ подписи обновлений агентов (Ed25519) - один раз, на компьютере со стендом.

    python tools/make_keys.py

Кладёт %APPDATA%/VPNCheckStand/keys/manifest_ed25519.key (секрет, 32 байта) и .pub (публичный) и печатает
публичный ключ в hex - его вписать в agent/keystore.properties как manifestPubKey (или он приедет
агенту в QR-ссылке подключения). Уже существующий ключ не трогает никогда: с новым ключом агенты
перестанут принимать ваши обновления. Сделайте копию keys/ вне этого компьютера.
"""
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stand.agentapi import KEY_PATH, PUB_PATH  # noqa: E402


def main():
    if os.path.exists(KEY_PATH):
        print("key already exists, not touching it:", KEY_PATH)
        with open(KEY_PATH, "rb") as handle:
            key = ed25519.Ed25519PrivateKey.from_private_bytes(handle.read())
        print("public key:", key.public_key().public_bytes(serialization.Encoding.Raw,
                                                           serialization.PublicFormat.Raw).hex())
        return 0
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, "wb") as handle:
        handle.write(private)
    if hasattr(os, "chmod"):
        os.chmod(KEY_PATH, 0o600)
    with open(PUB_PATH, "wb") as handle:
        handle.write(public)
    print("created:", KEY_PATH)
    print("public key (manifestPubKey):", public.hex())
    print("back up this folder somewhere safe:", os.path.dirname(KEY_PATH))
    return 0


if __name__ == "__main__":
    sys.exit(main())
