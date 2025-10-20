import asyncio
import datetime
import json
import logging

from FoldingAtHomeControl.crypto import decompress_payload, decrypt_aes, encrypt_aes, get_signature
from FoldingAtHomeControl.util import json_dump_payload

class MachNodeConnection:

  def __init__ (self, name, machine_id, host):
    self.host = host
    self.name = name
    self.machine_id = machine_id
    self.mach_key = None # AES Secret given on initialize
    self.ivs = {}

  async def initialize(self, key: bytes, ws, session_id):
    self.mach_key = key
    return await self.open_session(ws, session_id)
    

  async def open_session(self, ws, session_id):
    return await self.send_ws(ws, {'type':'session-open','session':session_id})
               

  async def send_ws(self,ws, msg: dict):
    msg = json_dump_payload(msg).encode()
    [enc_payload, iv] = encrypt_aes(self.mach_key, msg)
    self.ivs[iv] = True
    message = json_dump_payload({'type': 'message', 
                               'id': self.machine_id, 
                               'iv': iv.decode(), 
                               'payload': enc_payload.decode()})
    return await ws.send_text(message)

  def receive_message(self, msg, session_id):
    return self.extract_message(msg, session_id)

  def extract_message(self, message: dict, session_id):
    iv = message['iv']
    if self.ivs.get(iv,None):
      raise Exception("Can't use IV again")
    if 1e6 < len(self.ivs):
      raise Exception("Too many IV's")
    self.ivs[iv] = True

    payload = decrypt_aes(self.mach_key, message['payload'].encode(),iv.encode())

    if message.get('compression', None):
      payload = decompress_payload(payload, message.get('compression', 'gzip'))

    payload = json.loads(payload.decode())

    if payload['session'] != session_id:
      raise Exception("Message not for this session")
    
    return payload
  
  @classmethod
  async def _send_cmd(cls, ws, message: str):
      return await ws.send_text(message)


  def send_cmd(self, ws, key, cmd: str, state: str):
    payload = {"cmd": cmd, "state": state, 'time': datetime.datetime.now().isoformat()}
    payload_str = json_dump_payload(payload)
    signature = get_signature(key, payload_str.encode())
    message = json.dumps({'payload':payload, 'signature': signature.decode(), 'type': 'broadcast'})
    asyncio.create_task(self._send_cmd(ws, message))

