import subprocess
import tempfile
import os
import logging
import json
import minio


minion_client_binary   = "/usr/bin/minio-client"
salt_minion_config_dir = "/etc/salt/minio-client/"
salt_minion_config_file = f"{salt_minion_config_dir}/config.json"
salt_minion_alias       = "salt"

from subprocess import PIPE, Popen
from salt.exceptions import SaltConfigurationError, SaltRenderError
from urllib.parse import urlparse

log = logging.getLogger(__name__)

cmdenv = os.environ.copy()
instance_name = "devel"

policy_templates = {
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
    try:
      return_data=json.loads(mc_data)
    except (json.decoder.JSONDecodeError) as e:
      message=f"Failed to parse output from {' '.join(cmd)}: {mc_data}"
      log.error(message)
      raise SaltRenderError(message)

  return mc_returncode, return_data

def parse_json_string(data):
    try:
      log.error(f"class: {data.__class__()} data: {data}")
      return_data=json.loads(data)
      return return_data
    except (json.decoder.JSONDecodeError) as e:
      message=f"Failed to parse json string: {e}: {data}"
      log.error(message)
      raise SaltRenderError(message)

def parse_json_file(filename):
    try:
      return_data=json.load(open(filename))
      return return_data
    except (json.decoder.JSONDecodeError) as e:
      message=f"Failed to parse json string from filename: {e}"
      log.error(message)
      raise SaltRenderError(message)

def minio_credentials():
  return minio.credentials.MinioClientConfigProvider(salt_minion_config_file, alias=salt_minion_alias)

def minio_config():
  parsed_config = parse_json_file(salt_minion_config_file)
  if not("aliases" in parsed_config and salt_minion_alias in parsed_config["aliases"] and "url" in parsed_config["aliases"][salt_minion_alias]):
      messsage = f"Can not find alias {salt_minion_alias} in {salt_minion_config_file}"
      log.error(message)
      raise SaltConfigurationError(message)

  url = parsed_config["aliases"][salt_minion_alias]["url"]
  netloc = urlparse(url).netloc
  return netloc, parsed_config

def minio_client():
  netloc, parsed_config = minio_config()
  return minio.Minio(endpoint=netloc, credentials=minio_credentials())

def minio_admin():
  netloc, parsed_config = minio_config()
  return minio.MinioAdmin(endpoint=netloc, credentials=minio_credentials())

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
  mc = minio_client()

  bucket_list = mc.list_buckets()

  found=False

  for bucket in bucket_list:
    log.error(f"Checking {name} against {bucket.name}")
    if bucket.name == name:
      found=True
      break

  if found:
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

def policy(name, data={}):
  return {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}

def user(name, data={}):
  return {'name': name, 'result': True, 'changes': {}, 'comment': "darix was here"}