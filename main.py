from abc import ABC
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor
from os import sys
import paramiko
import pymongo
import subprocess
import threading

lock = threading.Lock()

class Router(ABC):

  def __init__(self, ip):
    self.ip = ip

  def check_ping(self):
    result = local_access_run([
      '/bin/ping',
      '-c', '1',
      '-W', '32',
      self.ip
    ])
    try:
      result.check_returncode()
      return True
    except subprocess.CalledProcessError:
      return False

  def check_valid(self, credentials):
    output = remote_access_run(self.ip, self.command_valid, credentials)
    if output == None:
      return False
    for line in output:
      if line.find(self.key) != -1:
        return True
    return False

class Juniper(Router):
  command_valid = 'show version'
  key = 'JUNOS'
  manufacturer = 'Juniper'

class Cisco_XR(Router):
  command_valid = 'show version'
  key = 'IOS XR'
  manufacturer = 'Cisco-XR'

class Cisco_XE(Router):
  command_valid = 'show version'
  key = 'IOS Software'
  manufacturer = 'Cisco-XE'

class Huawei(Router):
  command_valid = 'display version'
  key = 'HUAWEI'
  manufacturer = 'Huawei'

def build_credentials(credentials_filepath):
  try:
    with open(credentials_filepath, 'r') as file:
      credentials = []
      v = file.readlines()
      for i in range(2):
        credentials.append(v[i].split('\'')[1].strip())
      return credentials
  except FileNotFoundError:
    print(
      'Failed to read file: \"' + credentials_filepath + '\"',
      file = sys.stderr
    )

def build_ips():
  ip_prefixes = [
    '189.39.3.',
    '200.225.196.',
    '200.225.199.',
    '200.225.200.',
    '200.225.254.',
  ]
  ips = []
  for prefix in ip_prefixes:
    for suffix in range(256):
      ip = prefix + str(suffix)
      ips.append(ip)
  return ips

def build(credentials_filepath):
  credentials = build_credentials(credentials_filepath)
  # ips = build_ips()
  # jobs = []
  # for ip in ips:
  #   jobs.append([guess, ip, credentials])
  # results = multi_threaded_execution(jobs)
  # for result in results:
  #   if result != None:
  #     print(str(result.ip) + ': ' + str(result.manufacturer))
  print(remote_access_run('200.225.196.107', 'show version', credentials))

def guess(ip, credentials):
  router = None
  if Router(ip).check_ping() == False:
    return router
  print('ping: ' + ip)
  for subclass in Router.__subclasses__():
    current = subclass(ip)
    if current.check_valid(credentials) == True:
      router = current
      break
  return router

def local_access_run(command):
  return subprocess.run(
    args = command,
    stdout = subprocess.PIPE,
    stderr = subprocess.STDOUT,
  )

def multi_threaded_execution(jobs, workers = 256):
  ans = []
  threads = []
  with ThreadPoolExecutor(max_workers = workers) as executor:
    for parameters in jobs:
      threads.append(
        executor.submit(
          parameters[0],
          *parameters[1:]
        )
      )
  for thread in threads:
    ans.append(thread.result())
  return ans

def remote_access_run(ip, command, credentials):
  allowed_errors = [
    '[Errno 104] Connection reset by peer',
  ]
  timeout = 64
  remaining_attempts = 64
  while remaining_attempts > 0:
    remaining_attempts -= 1
    with paramiko.SSHClient() as ssh:
      try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
          ip,
          username = credentials[0],
          password = credentials[1],
          timeout = timeout,
          banner_timeout = timeout,
          auth_timeout = timeout,
        )
        stdin, stdout, stderr = ssh.exec_command(
          command,
          timeout = timeout
        )
        ans = []
        for line in stdout.readlines():
          ans.append(line)
        return ans
      except Exception as exception:
        allowed = False
        s = str(exception)
        with lock:
          print(ip, file = sys.stderr)
          print(exception, file = sys.stderr)
        for error in allowed_errors:
          if s.find(error) != -1:
            allowed = True
            break
        if allowed == False:
          return None

build(input())