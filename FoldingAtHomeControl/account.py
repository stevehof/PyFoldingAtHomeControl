import asyncio
import json
import time


from FoldingAtHomeControl.api import API, derive_password
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key

from FoldingAtHomeControl.crypto import base64_decode, pkcs8_unwrap, salt_text
from FoldingAtHomeControl.node_conn import MachNodeConnection
from FoldingAtHomeControl.util import read_file, retrieve, store
HTTPS_HOST = "https://api.foldingathome.org"
WSS_HOST = "wss://{host}/{path}"

class Account (API):


  def __init__(self, email, passphrase):
    super().__init__()
    self.email = email
    self.passphrase = passphrase
    self.session_id = None
    self.uid = None
    self.data = {}
    self.nodes: dict[str, MachNodeConnection] = {}
    self.private_key = None
    self.public_key = None
    self.cmd_queue = None

  def initialize(self):
      self.login_with_passphrase(self.email, self.passphrase)
      self.private_key = load_der_private_key(base64_decode(self.get_secret()), None)
      self.public_key = load_der_public_key(base64_decode(self.get_attr("pubkey").encode()), None)


  def get_attr(self, name, ttl_hash=None):
      del ttl_hash
      return self.get_account().get(name)
      
  def get_ttl_hash(seconds=60):
      return round(time.time() / seconds)
  
  def get_account(self):
      if not self.data:
        self.update_account()
      return self.data
  
  def update_account(self):
    results = self.session.get("https://api.foldingathome.org/account")
    self.data = results.json()
    existing_nodes = list(self.nodes.keys())
    for mach in self.get_machines():
      if  mach['id'] in existing_nodes:
        machine = self.nodes[mach['id']]
        machine.name = mach['name']
        machine.host = self.data['node']
        existing_nodes.remove(mach['id'])
      else:
        self.nodes[mach['id']] = MachNodeConnection(mach['name'], mach['id'], self.data['node'], self)
      
    return self.data

  def get_machines(self):
      return self.data["machines"]
  
  def retrieve_secret(self, passphrase, text_for_salt):
    salted = salt_text(text_for_salt)
    [key, hash] = derive_password(passphrase, salt_text(text_for_salt))
    results = self.get("account/secret", data={'password': hash}, action="Get Secret")
    secret = results.json()
    unwrapped = pkcs8_unwrap(key, base64_decode(secret['secret']), salted, passphrase)
    store("privateKey", "secret", unwrapped)
    return unwrapped
    return None
  
  def get_secret(self) -> bytes:
     secret = retrieve("privateKey", "secret")
     if not secret:
      secret = self.retrieve_secret(self.passphrase, self.email)
     return secret.encode()
      

  async def receiving_loop(self, ws):
    loop = asyncio.get_running_loop()
    async for msg in ws:
      msg = json.loads(msg)
      if "type" not in msg:
        continue
      if msg["type"] == "connect":
        loop.create_task(self.handle_connect(ws, msg['client']))
      elif msg["type"] == "message":
        self.handle_message(ws, msg)
      else:
        print("unhandled: ", msg)

  async def sending_loop(self, ws, cmd_queue):
    async for command in await cmd_queue.get():
      self.nodes[self.data['machines'][0]['id']].send_cmd(command['cmd'], command['state'])
    
  async def connect_service(self):
    loop = asyncio.get_running_loop()
    self.cmd_queue = asyncio.Queue(maxsize=None,loop=loop)
    recv_task = None
    sending_task = None
    try:
      async with self.get_ws_connection(self.data['node']) as ws:
        await self.login_ws(ws)
        recv_task = loop.create_task(self.receiving_loop(ws))
        sending_task = loop.create_task(self.sending_loop(ws, self.cmd_queue))
        return await asyncio.gather(recv_task, sending_task)
    finally:
      if recv_task:
        recv_task.cancel()
      if sending_task:
        sending_task.cancel()
            

  # def create_secret(self):

  #   text_for_salt = self.email
  #   passphrase = self.passphrase

  #   salt = salt_text(text_for_salt)
  #   [key, hash] = derive_password(passphrase, salt)

  #   [priv_key, pub_key] = get_private_public_key_pair()
  #   priv_bytes = priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
  #   pub_bytes = pub_key.public_bytes(Encoding.PEM, PublicFormat.PKCS1)
  #   wrapped_key = pkcs8_wrap(key, priv_bytes)
    

  #   return {'pub_key': b64encode(pub_bytes), 
  #           'password': hash, 
  #           'secret': b64encode(wrapped_key),
  #           'key': priv_bytes}

  # def new_secret(self):
  #    secret = self.create_secret()
  #    data = {'pub_key': secret['pub_key'], 
  #           'password': secret['password'], 
  #           'secret': secret['secret']}
  #    # TODO send secret = /account/secret


  #    store("privateKey", "secret", b64encode(secret['key']))

  # def put_secret(self, secret_data):
  #    self.session()