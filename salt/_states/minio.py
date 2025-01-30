import subprocess
import tempfile
import os
import logging
import json


minion_client_binary   = "/usr/bin/minio-client"
salt_minion_config_dir = "/etc/salt/minio-client/"

from subprocess import PIPE, Popen
from salt.exceptions import SaltConfigurationError, SaltRenderError
import salt.utils.json

log = logging.getLogger(__name__)

cmdenv = os.environ.copy()
instance_name = "devel"

"""
root@fortress /srv/cfgmgmt # /usr/bin/minio-client --config-dir /etc/salt/minio-client/ --json --no-color --disable-pager mb devel/restic_pdp11 ; echo $?
{
 "status": "error",
 "error": {
  "message": "Unable to make bucket `devel/restic_pdp11`.",
  "cause": {
   "message": "Bucket name contains invalid characters",
   "error": {}
  },
  "type": "error"
 }
}
1
root@fortress /srv/cfgmgmt # /usr/bin/minio-client --config-dir /etc/salt/minio-client/ --json --no-color --disable-pager mb devel/restic-pdp11 ; echo $?
{
 "status": "success",
 "bucket": "devel/restic-pdp11",
 "region": ""
}
0
"""

def run_dmc_to_json(args):
  cmd=[minion_client_binary, "--config-dir", salt_minion_config_dir, "--json", "--no-color", "--disable-pager"]
  cmd.extend(args)
  try:
      proc = Popen(cmd, stdout=PIPE, stderr=PIPE, env=cmdenv, encoding="utf-8")
      mc_data, mc_error = proc.communicate()
      mc_returncode = proc.returncode
  except (OSError, UnicodeDecodeError) as e:
      mc_data, mc_error = "", str(e)
      mc_returncode = 1

  # unlike in our gopass tool we can not just raise here. The real raise has to happen in the specific function
  # that called us and knows how to handle the specific error
  # if mc_returncode:
  #   raise SaltRenderError(f"Running {cmd} failed. Please check the log.")

  if not mc_data:
    return_data={}
  else:
    # TODO: error handling
    return_data=json.load(mc_data)

  return mc_returncode, return_data

def site_config(name, config={}):
  # config_array = []

  # for key, value config.items():
  #   if value is String:
  #     final_value = value
  #   else:
  #     final_value = "".join(value)

  #   config_array.append(f"{key}={final_value}")
  #   cmd [minion_client_binary]
  return {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}

def bucket(name, data={}):
  return_data = {'name': name, 'result': True, 'changes': {"muahah": "wooohoo"}, 'comment': "darix was here"}

  return_code, bucket_list = run_dmc_to_json(["ls", instance_name])

  if not name in bucket_list:
    return_data["changes"]= {"what": f"Bucket {name} missing"}

  return return_data

def policy(name, data={}):
  return {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}

def user(name, data={}):
  return {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}