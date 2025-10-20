
from typing import Optional, Union

from httpx import Client

from FoldingAtHomeControl.crypto import base64_decode, derive_password, pkcs8_unwrap, salt_text
from FoldingAtHomeControl.exceptions import FoldingAtHomeControlAuthenticationRequired
from FoldingAtHomeControl.node_conn import MachNodeConnection

class APIConn:
  def __init__(self, session):
      self.session: Client = session
      self.session_id: bytes = b''
      self.account_data: dict[str, Union[str,dict[str,dict]]] = {}
      self.secret: bytes = b''
      self.nodes: dict[str, MachNodeConnection] = {}
      
  def login_with_passphrase(self, email: str, passphrase: str):
      if not self.session_id:
        [_, hash] = derive_password(passphrase.encode(), salt_text(email.encode()))
        results = self.get("login", {'email': email, 'password': hash})
        self.cookies = results.cookies
        results_json = results.json()
        if results_json.get("group", {}).get("authenticated", False):
          self.session_id = results_json.get("id",None)
          self.uid = results_json.get("uid",None)

          self.update_account()
          return
        raise FoldingAtHomeControlAuthenticationRequired("Failed to login")

  def retrieve_secret(self, passphrase:str, text_for_salt:str):
    salted = salt_text(text_for_salt.encode())
    [key, hash] = derive_password(passphrase.encode(), salted)
    results = self.get("account/secret", data={'password': hash})
    secret = results.json()
    return pkcs8_unwrap(key, base64_decode(secret['secret'].encode()), salted, passphrase.encode())

  def get(self, path, data=None):
      results = self.session.get(f"/{path}", params=data)
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


