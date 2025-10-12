
from contextlib import asynccontextmanager, contextmanager
import datetime
import json
import logging
from typing import Optional, Union
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

from FoldingAtHomeControl.crypto import base64_encode, get_pubkey_id, base64_decode, verify, load_rsa_key
from FoldingAtHomeControl.util import json_dump_payload

class APIConn:
  def __init__(self, host):
      self.host: str = host
      self.session: Optional[Session] = None
      self.session_id: bytes = b''
      self.account_data: dict[str, Union[str,dict[str,dict]]] = {}
      self.secret: bytes = b''
      self.nodes: dict[str, MachNodeConnection] = {}
      
  def login_with_passphrase(self, email, passphrase):
      if self.session is None:
        self.session = Session()

      if not self.session_id:
        [_, hash] = derive_password(passphrase, salt_text(email))
        results = self.get("login", {'email': email, 'password': hash})
        self.cookies = results.cookies
        results_json = results.json()
        self.session_id = results_json.get("id",None)
        self.uid = results_json.get("uid",None)

        self.update_account()


  def get(self, path, data):
      results = self.session.get(f"{self.host}/{path}", params=data)
      return results

  def get_account(self):
      if not self.data:
        self.update_account()
      return self.data
  
  def update_account(self):
    results = self.get("account")
    self.data = results.json()
    existing_nodes = list(self.nodes.keys())
    for mach in self.get_machines():
      if  mach['id'] in existing_nodes:
        machine = self.nodes[mach['id']]
        machine.name = mach['name']
        machine.host = self.data['node']
        existing_nodes.remove(mach['id'])
      else:
        self.nodes[mach['id']] = MachNodeConnection(mach['name'], mach['id'], self.data['node'])
    for remaining_node in existing_nodes:
       self.nodes.pop(remaining_node)

  def get_machines(self):
      return self.data["machines"]


