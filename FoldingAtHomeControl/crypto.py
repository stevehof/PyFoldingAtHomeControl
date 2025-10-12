# -*- coding: windows-1252 -*-



from base64 import b64decode, b64encode
import gzip
from hashlib import sha256
import json
from os import urandom
from typing import Union
from requests import Session, get

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding, aes_key_unwrap_with_padding, aes_key_unwrap, bytes_eq, InvalidUnwrap
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key
from cryptography.hazmat.primitives.padding import PKCS7 as PKCS7_padding

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPrivateKey
from hashlib import sha256
import hashlib
from jwcrypto.jwk import JWK

from FoldingAtHomeControl.util import json_dump_payload

def base64_decode(data: bytes) -> bytes:
    """Decode base64url to bytes"""
    # Add padding if needed
    if not isinstance(data, bytes):
       raise Exception("Not Bytes")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b'=' * padding
    data = data.replace(b'-', b'+').replace(b'_', b'/')
    # Replace URL-safe chars
    return  b64decode(data)

def base64_encode(data: bytes, url=False) -> bytes:
    """Encode bytes to base64url"""
    if not isinstance(data, bytes):
       raise Exception("Not Bytes")
    data = b64encode(data)
    if url:
       data = data.rstrip(b"=").replace(b'+', b'-').replace(b'/', b'_')
    return data

def get_private_public_key_pair():
  priv_key = rsa.generate_private_key(65537 , 4096)
  pub_key = priv_key.public_key()
  return [priv_key, pub_key]

def salt_text(text: bytes):
    return sha256(text).digest()

def derive_password(passphrase: bytes, salt: bytes):
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations=100000)
    key = kdf.derive(passphrase)
    hash = hashlib.sha256(key).digest()
    hash_encoded = base64_encode(hash).decode().strip()
    return [key, hash_encoded]

def get_pubkey_id(pubkey: RSAPublicKey)->str:
    jwk = JWK().from_pem(pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)).export(as_dict=True)
    return base64_encode(sha256(base64_decode(jwk['n'].encode())).digest(),True).decode()

def verify(pubkey: RSAPublicKey, signature_encoded: bytes, data: bytes):
   pubkey.verify(base64_decode(signature_encoded), data, padding=padding.PKCS1v15(), algorithm=hashes.SHA256())

def sign(key, data):
   return key.sign(data, 
                   padding=padding.PKCS1v15(), 
                   algorithm=hashes.SHA256())

def pkcs8_wrap(key, priv_bytes):
  return aes_key_wrap_with_padding(key, priv_bytes)

def pkcs8_unwrap(key, wrapped_key, salt, passphrase):
  cipher = Cipher(algorithms.AES(key), modes.CBC(salt[0:16]))
  dec = cipher.decryptor()
  decrypted_wrapped_key = dec.update(wrapped_key) + dec.finalize()
  return b64encode(decrypted_wrapped_key.rstrip(b"\t"))

def load_public_key(public_key_b64: bytes):
   return serialization.load_der_public_key(base64_decode(public_key_b64), None)

  
def get_signature(key, payload: bytes):
  payload = payload.replace(b" ", b"")
  return base64_encode(key.sign(payload, 
                                padding=padding.PKCS1v15(), 
                                algorithm=hashes.SHA256()),
                        True)
    
def encrypt_aes(key, data: bytes, iv_size: int = 16) -> list[bytes, bytes]:
    iv = urandom(iv_size)
    padder = PKCS7_padding(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = get_cipher(key, iv)
    enc = cipher.encryptor()
    enc_payload = enc.update(padded_data) + enc.finalize()
    return [base64_encode(enc_payload, True), base64_encode(iv, True)]

def get_cipher(key, iv):
   return Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(iv))

def decrypt_aes(key, message: bytes, iv: bytes) -> bytes:
  message = base64_decode(message)
  iv = base64_decode(iv)

  cipher = get_cipher(key, iv)
  dec = cipher.decryptor()
  decrypted_message = dec.update(message) + dec.finalize()
  unpadder = PKCS7_padding(128).unpadder()
  decrypted_message = unpadder.update(decrypted_message) + unpadder.finalize()
  return decrypted_message

def decompress_payload(s: bytes, type:str = 'gzip') -> bytes:
  if type == 'gzip':
    return gzip.decompress(s)
  return None

def decrypt_rsa_oaep(key: RSAPrivateKey, data: bytes) -> bytes:
  oaep_padding=padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(), 
                            label=None)
  return key.decrypt(data, oaep_padding)

def load_rsa_key(key: bytes, private=True):
  if private:
    return load_der_private_key(key, None)
  return load_der_public_key(key, None)  
   