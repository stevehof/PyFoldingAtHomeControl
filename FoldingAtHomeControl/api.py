
from contextlib import asynccontextmanager, contextmanager
import datetime
import json
import logging
from requests import Session
import websockets
import random
import string
import websockets

from FoldingAtHomeControl.crypto import decompress_payload, decrypt_aes, decrypt_rsa_oaep, derive_password, get_signature, pkcs8_unwrap, salt_text
from FoldingAtHomeControl.node_conn import MachNodeConnection
from FoldingAtHomeControl.util import get_random_chars, store

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPrivateKey

import logging

from FoldingAtHomeControl.crypto import base64_encode, get_pubkey_id, base64_decode, load_public_key, verify
from FoldingAtHomeControl.util import json_dump_payload

class API:
  private_key: RSAPrivateKey
  nodes: dict[bytes, MachNodeConnection]
  session_id: bytes

  def __init__(self):
      self.session = None
      self._origin = "https://v8-4.foldingathome.org"
      self.ws_headers = {"Pragma": "no-cache",
                         "Cache-Control": 'no-cache',
                         'Origin': "https://v8-4.foldingathome.org",
                         "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
                         "Accept-Encoding": "gzip, deflate, br, zstd"}

  def login_with_passphrase(self, email, passphrase):
      if self.session is None:
        self.session = Session()

      if not self.session_id:

        [key, hash] = derive_password(passphrase, salt_text(email))
        results = self.get("login", {'email': email, 'password': hash}, action="Login")
        self.cookies = results.cookies
        results_json = results.json()
        self.session_id = results_json["id"]
        self.uid = results_json["uid"]

  def put(self, path, data, action):
      results = self.session.put(f"{HOST}/{path}", data=data, headers={"Content-Type": "application/json"})
      return results

  def get(self, path, data, action):
      results = self.session.get(f"{HOST}/{path}", params=data)
      return results

  def retrieve_secret(self, passphrase, text_for_salt, key, iv):
      salted = salt_text(text_for_salt)
      [key, hash] = derive_password(passphrase, salt_text(text_for_salt))
      results = self.get("account/secret", data={'password': hash}, action="Get Secret")
      secret = results.json()
      unwrapped = pkcs8_unwrap(key, base64_decode(secret['secret']), salted, passphrase)
      store("privateKey", "secret", unwrapped)
      return unwrapped




  def new_session_id(self):
    self.session_id = base64_encode(get_random_chars(12).encode(), True).decode()
    return self.session_id

  def handle_message(self, ws, msg):
    mach_id = msg['client']
    machine = self.nodes.get(mach_id, None)
    if machine:
       machine.receive_message(msg)

  async def login_ws(self, ws):
    payload = {
      'time': datetime.datetime.now().isoformat(), 
      'session': self.new_session_id()
    }
    logging.info(f"Logging in with session {payload['session']}")
    sig = get_signature(self.private_key, json.dumps(payload).encode())
    self.session_id = payload['session']
    ws_send = json.dumps({'type': "login", 
                          'payload': payload, 
                          'pubkey': self.data['pubkey'], 
                          'signature':sig.decode()})
    return await ws.send(ws_send)



