from functools import wraps
import json
from os.path import dirname, abspath, join, exists
from os import makedirs, remove
import datetime
import string
FOLDER = '.store'
ROOT = join(dirname(dirname(abspath(__file__))), FOLDER)
STORE_TIMEOUT = store_timeout = 24 * 60 * 60

import random
from threading import RLock

store_lock = RLock()

def lock(f):
  @wraps(f)
  def wrapper(*args, **kwargs):
    if store_lock.acquire():
      return f(*args, **kwargs)
  return wrapper


@lock
def store(name, filetype, text):
  makedirs(join(ROOT, filetype), exist_ok=True)
  with open(join(ROOT, filetype, name), 'w') as filestore:
    filestore.write(text.decode())
  with open(join(ROOT, filetype, name+".ts"), 'w') as filestore:
    filestore.write(datetime.datetime.now().isoformat())

@lock
def is_expired(name, filetype):
  file_path = join(ROOT, filetype, name)
  ts_file_path = join(ROOT, filetype, name+".ts")
  if exists(file_path) and exists(ts_file_path):
    ts = read_file(ts_file_path)
    if ts:
      ts_offset = datetime.datetime.fromisoformat(ts) + datetime.timedelta(seconds=STORE_TIMEOUT)
      return ts_offset < datetime.datetime.now()
  return True

def read_file(filename):
  with open(filename, 'r') as filestore:
    return filestore.read() 

@lock
def retrieve(name, filetype):
  makedirs(join(ROOT, filetype), exist_ok=True)
  if is_expired(name, filetype):
    remove_file(name, filetype)
    return None
  return read_file(join(ROOT, filetype, name))
  
@lock
def remove_file(name, filetype):
  if exists(join(ROOT, filetype, name)):
    print("remove ", join(ROOT, filetype, name))
    # remove(join(ROOT, filetype, name))


def json_dump_payload(payload: dict) -> str:
  return json.dumps(payload).replace(" ","")

def get_random_chars(num):
  return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(num))