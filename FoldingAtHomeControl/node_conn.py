import gzip
import json
from os import urandom

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import logging

from FoldingAtHomeControl.crypto import base64_encode, decompress_payload, decrypt_aes, encrypt_aes, get_pubkey_id, base64_decode, load_public_key, verify
from FoldingAtHomeControl.util import json_dump_payload

logging.basicConfig(
    format="%(asctime)s %(message)s",
    level=logging.DEBUG,
)

class MachNodeConnection:

  def __init__ (self, name, machine_id, host, acc):
    self.host = host
    self.name = name
    self.machine_id = machine_id
    self.acc = acc
    self.key = None # AES Secret given on initialize
    self.ivs = {}
    self.ws = None

  async def initialize(self, key: bytes, ws):
    self.key = key
    self.ws = ws
    return await self.open_session()
    

  async def open_session(self):
    return await self.send_ws({'type':'session-open','session':self.acc.session_id})
               

  async def send_ws(self, msg: dict):
    msg = json_dump_payload(msg).encode()
    print(msg)
    [enc_payload, iv] = encrypt_aes(self.key, msg)
    self.ivs[iv] = True
    message = json_dump_payload({'type': 'message', 
                               'id': self.machine_id, 
                               'iv': iv.decode(), 
                               'payload': enc_payload.decode()})
    return await self.ws.send(message)

  def receive_message(self, ws, msg):
    return self.extract_message(msg)

  def extract_message(self, message: dict):
    iv = message['iv']
    if self.ivs.get(iv,None):
      raise Exception("Can't use IV again")
    if 1e6 < len(self.ivs):
      raise Exception("Too many IV's")
    self.ivs[iv] = True

    payload = decrypt_aes(self.key, message['payload'].encode(),iv.encode())

    if message.get('compression', None):
      payload = decompress_payload(payload, message.get('compression', 'gzip'))

    payload = json.loads(payload.decode())
    print(payload)

    if payload['session'] != self.acc.session_id:
      raise Exception("Message not for this session")
    
    return payload