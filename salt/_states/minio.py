#
# TODO: implement test mode - currently the code is always active
#       see filetreedeployer for how Georg implemented it theres
# TODO: implement proper result_data
#

import tempfile
import os
import logging
import json
import minio as pyminio


minion_client_binary   = "/usr/bin/minio-client"
salt_minion_config_dir = "/etc/salt/minio-client/"
salt_minion_config_file = f"{salt_minion_config_dir}/config.json"
salt_minion_alias       = "salt"

from subprocess import PIPE, Popen
from salt.exceptions import SaltConfigurationError, SaltRenderError
from urllib.parse import urlparse

log = logging.getLogger(__name__)

__cmdenv = os.environ.copy()

__policy_templates = {
"pgbackrest-append-only": """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%"
            ],
            "Condition": {
                "StringLike": {
                    "s3:prefix": [
                        "archive/local/*",
                        "backup/local/*"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%/backup/%%bucket_subdir%%/latest"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObjectTagging",
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%/archive/%%bucket_subdir%%/*",
                "arn:aws:s3:::%%bucket_name%%/backup/%%bucket_subdir%%/*"
            ]
        }
    ]
}""",

"pgbackrest-full-permissions": """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::pgbackrest"
            ],
            "Condition": {
                "StringLike": {
                    "s3:prefix": [
                        "backup/%%bucket_subdir%%/*",
                        "archive/%%bucket_subdir%%/*"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:DeleteObject",
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject",
                "s3:PutObjectTagging"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%/backup/%%bucket_subdir%%/*",
                "arn:aws:s3:::%%bucket_name%%/archive/%%bucket_subdir%%/*"
            ]
        }
    ]
}""",
"restic-append-only": """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::%%bucket_name%%/*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:DeleteObject",
            "Resource": "arn:aws:s3:::%%bucket_name%%/locks/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:CreateBucket",
                "s3:GetBucketLocation",
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::%%bucket_name%%"
        }
    ]
}""",
"restic-full-permissions": """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::%%bucket_name%%"
            ]
        }
    ]
}""",
}

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

def __run_dmc_to_json(args):
  cmd=[minion_client_binary, "--config-dir", salt_minion_config_dir, "--json", "--no-color", "--disable-pager"]
  cmd.extend(args)
  try:
      proc = Popen(cmd, stdout=PIPE, stderr=PIPE, env=__cmdenv, encoding="utf-8")
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
    try:
      return_data=json.loads(mc_data)
    except (json.decoder.JSONDecodeError) as e:
      message=f"Failed to parse output from {' '.join(cmd)}: {mc_data}"
      log.error(message)
      raise SaltRenderError(message)

  return mc_returncode, return_data

def __parse_json_string(data):
    try:
      log.error(f"class: {data.__class__()} data: {data}")
      return_data=json.loads(data)
      return return_data
    except (json.decoder.JSONDecodeError) as e:
      message=f"Failed to parse json string: {e}: {data}"
      log.error(message)
      raise SaltRenderError(message)

def __parse_json_file(filename):
    try:
      return_data=json.load(open(filename))
      return return_data
    except (json.decoder.JSONDecodeError) as e:
      message=f"Failed to parse json string from filename: {e}"
      log.error(message)
      raise SaltRenderError(message)

def __minio_credentials():
  return pyminio.credentials.MinioClientConfigProvider(salt_minion_config_file, alias=salt_minion_alias)

def __minio_config():
  parsed_config = __parse_json_file(salt_minion_config_file)
  if not("aliases" in parsed_config and salt_minion_alias in parsed_config["aliases"] and "url" in parsed_config["aliases"][salt_minion_alias]):
      messsage = f"Can not find alias {salt_minion_alias} in {salt_minion_config_file}"
      log.error(message)
      raise SaltConfigurationError(message)

  url = parsed_config["aliases"][salt_minion_alias]["url"]
  netloc = urlparse(url).netloc
  return netloc, parsed_config

def __minio_client():
  netloc, parsed_config = __minio_config()
  return pyminio.Minio(endpoint=netloc, credentials=__minio_credentials())

def __minio_admin():
  netloc, parsed_config = __minio_config()
  return pyminio.MinioAdmin(endpoint=netloc, credentials=__minio_credentials())

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

def bucket_present(name, data={}):
  return_data = {'name': name, 'result': True, 'changes': {"muahah": "wooohoo"}, 'comment': "darix was here"}

  mc = __minio_client()
  found=mc.bucket_exists(name)

  if found:
    # TODO: implement update mode for settings
    return_data["changes"]= {"what": f"Bucket {name} already there"}
  else:
    try:
      if not("minio" in __pillar__ and "location" in __pillar__["minio"]):
        raise SaltConfigurationError("Missing location in minio pillar")
      location = __pillar__["minio"]["location"]
      locking = False
      if "locking" in data:
        locking = data["locking"]
      mc.make_bucket(bucket_name=name, location=location, object_lock=locking)
      return_data["changes"]= {"what": f"Bucket {name} was missing and is now added"}
    except (ValueError) as e:
      raise e

  return return_data

def policy_present(name, data={}):
  return_data = {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}

  ma = __minio_admin()
  policy_list = __parse_json_string(ma.policy_list())

  if name in policy_list:
    # TODO: implement update mode
    return_data["changes"]= {"what": f"Policy {name} already there"}
  else:
    if not data["type"] in __policy_templates:
      raise SaltConfigurationError(f'No template for policy type {data["type"]}')
    template=__policy_templates[data["type"]]
    with tempfile.NamedTemporaryFile(mode="w+", encoding='utf-8', delete=False) as policy_file:
      try:
        policy_string=template
        for k,v in data.items():
          policy_string=policy_string.replace(f"%%{k}%%", v)
        policy_file.write(policy_string)
        policy_file.close()
        ma.policy_add(name, policy_file.name)
      except (pyminio.error.MinioAdminException) as e:
        log.error(f"Adding policy {name} failed: {e} {policy_string}")
        raise
      finally:
        os.remove(policy_file.name)

    return_data["changes"]= {"what": f"Policy {name} is missing"}

  return return_data

def user_present(name, data={}):
  return_data = {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}

  ma = __minio_admin()
  user_list = ma.user_list()

  if name in user_list:
    # TODO: implement update mode
    return_data["changes"]= {"what": f"User '{name}' already there"}
  else:
    if not("password" in data):
      raise SaltConfigurationError(f"missing password for user '{name}'")
    ma.user_add(name, data["password"])
    if "policies" in data:
      ma.attach_policy(policies=data["policies"], user=name)
      if "service_accounts" in data:
         for account_name, account_data in data["service_accounts"].items():
           if not("access_key" in account_data and "secret_key" in account_data):
             raise SaltConfigurationError(f"missing data for service account '{account_name}' for user '{name}' ")
           ma.add_service_account(access_key=account_data["access_key"], secret_key=account_data["secret_key"], name=account_name)

  return return_data

def user_missing(name):
  return_data = {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}
  ma = __minio_admin()
  try:
    ma.user_remove(name)
    return_data["changes"]= {"what": f"User '{name}' removed"}
  except (pyminio.error.MinioAdminException) as e:
    return_data["changes"]= {"what": f"User '{name}' already missing"}

  return return_data