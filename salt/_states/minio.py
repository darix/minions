#
# TODO: implement test mode - currently the code is always active
#       see filetreedeployer for how Georg implemented it theres
# TODO: implement proper result_data
#

import json
import logging
import os
import random
import string
import tempfile
import re

import minio as pyminio

from salt.exceptions import SaltConfigurationError, SaltRenderError
from urllib.parse import urlparse


minion_client_binary    = "/usr/bin/minio-client"
salt_minion_config_dir  = "/etc/salt/minio-client/"
salt_minion_config_file = f"{salt_minion_config_dir}/config.json"
salt_minion_alias       = "salt"


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


def __parse_json_string(data):
  try:
    log.error(f"class: {data.__class__()} data: {data}")
    return_data = json.loads(data)
    return return_data
  except (json.decoder.JSONDecodeError) as e:
    message = f"Failed to parse json string: {e}: {data}"
    log.error(message)
    raise SaltRenderError(message)


def __parse_json_file(filename):
  try:
    return_data = json.load(open(filename))
    return return_data
  except (json.decoder.JSONDecodeError) as e:
    message = f"Failed to parse json string from filename: {e}"
    log.error(message)
    raise SaltRenderError(message)


def __minio_credentials():
  return pyminio.credentials.MinioClientConfigProvider(salt_minion_config_file, alias=salt_minion_alias)


def __minio_config():
  parsed_config = __parse_json_file(salt_minion_config_file)
  if not ("aliases" in parsed_config and salt_minion_alias in parsed_config["aliases"] and "url" in
          parsed_config["aliases"][salt_minion_alias]):
    message = f"Can not find alias {salt_minion_alias} in {salt_minion_config_file}"
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

def _parse_site_setting(input_string):
  section_name, section_data_string = input_string.split(' ', 1)
  settings = {}
  is_value = False
  key = None
  r=re.compile(r'\s*(?P<config_option>\S+)=(?P<config_value>".*?"|\S+)\s*')
  fields=r.split(section_data_string)
  for chunk in fields:
    if chunk == '':
      continue
    if is_value:
      settings[key] = chunk
      is_value = False
    else:
      key = chunk
      is_value = True
  return section_name, settings


def _is_site_config_set(ma, section_name, section_data):
   set_section_name, set_section_data = _parse_site_setting(ma.config_get(section_name))
   for k, v in section_data.items():
     try:
       if set_section_data[k] != v:
         return False
     except KeyError as e:
       pass
   return True


def site_config(name):
  return_data = {'name': name, 'result': None, 'changes': {},  'comment': ""}
  if "minio" in __pillar__ and "config" in __pillar__["minio"]:
    ma = __minio_admin()

    for section_name, section_data in __pillar__["minio"]["config"].items():
      try:
        ma.config_set(section_name, section_data)
        if _is_site_config_set(ma, section_name, section_data):
          return_data["changes"][f"site_setting_{section_name}"] = f"successfully set settings for {section_name}"
      except pyminio.error.MinioAdminException as e:
        exception_data = __parse_json_string(e._body)
        message = exception_data["Message"]
        return_data["result"] = False
        return_data["changes"][f"site_setting_{section_name}"] = f"Failed to set all settings for {section_name}: {message}"


  return return_data


def bucket_present(name, data={}):
  return_data = {'name': name, 'result': None,  'changes': {},  'comment': ""}

  mc = __minio_client()
  found = mc.bucket_exists(name)

  if found:
    # TODO: implement update mode for settings
    return_data["changes"] = {"what": f"Bucket {name} already there"}
  else:
    try:
      if not ("minio" in __pillar__ and "location" in __pillar__["minio"]):
        raise SaltConfigurationError("Missing location in minio pillar")
      location = __pillar__["minio"]["location"]
      locking = False
      if "locking" in data:
        locking = data["locking"]
      mc.make_bucket(bucket_name=name, location=location, object_lock=locking)
      return_data["changes"] = {"what": f"Bucket {name} was missing and is now added"}
    except (ValueError) as e:
      raise e

  return return_data


def bucket_missing(name):
  return_data = {'name': name, 'result': None,  'changes': {},  'comment': ""}

  mc = __minio_client()
  found = mc.bucket_exists(name)

  if found:
    mc.remove_bucket(name)
    return_data["changes"] = {"what": f"Bucket {name} removed"}
  else:
    return_data["changes"] = {"what": f"Bucket {name} already missing"}

  return return_data


def policy_present(name, data={}):
  return_data = {'name': name, 'result': None, 'changes': {},  'comment': ""}

  ma = __minio_admin()
  policy_list = __parse_json_string(ma.policy_list())

  if name in policy_list:
    # TODO: implement update mode
    return_data["changes"] = {"what": f"Policy {name} already there"}
  else:
    if not data["type"] in __policy_templates:
      raise SaltConfigurationError(f'No template for policy type {data["type"]}')
    template = __policy_templates[data["type"]]
    with tempfile.NamedTemporaryFile(mode="w+", encoding='utf-8', delete=False) as policy_file:
      try:
        policy_string = template
        for k, v in data.items():
          policy_string = policy_string.replace(f"%%{k}%%", v)
        policy_file.write(policy_string)
        policy_file.close()
        ma.policy_add(name, policy_file.name)
      except (pyminio.error.MinioAdminException) as e:
        log.error(f"Adding policy {name} failed: {e} {policy_string}")
        raise
      finally:
        os.remove(policy_file.name)

    return_data["changes"] = {"what": f"Policy {name} is missing"}

  return return_data


def policy_missing(name):
  return_data = {'name': name, 'result': None, 'changes': {},  'comment': ""}

  ma = __minio_admin()
  policy_list = __parse_json_string(ma.policy_list())

  if name in policy_list:
    ma.policy_remove(name)
    return_data["changes"] = {"what": f"Policy {name} removed"}
  else:
    return_data["changes"] = {"what": f"Policy {name} is already missing"}

  return return_data


def _gimme_random_string(length=20):
  return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def _filter_existing_policies(current_policies_string, new_policies_list=[]):
  current_policies_list = current_policies_string.split(',')
  for policy in current_policies_list:
    if policy in new_policies_list:
      new_policies_list.remove(policy)
  return new_policies_list


def _get_existing_service_accounts(ma, name):
  parsed_json = __parse_json_string(ma.list_service_account(name))
  if "accounts" in parsed_json:
    current_service_account_list = parsed_json["accounts"]
    if current_service_account_list is None:
      current_service_account_list = []
  else:
    raise SaltConfigurationError(f"No idea how to parse the list of current service accounts: {parsed_json}")
  return current_service_account_list


def _existing_service_account(current_service_account_list, account_data):
  for current_service_account in current_service_account_list:
    if current_service_account["accessKey"] == account_data["access_key"]:
      return True
  return False


def _verify_service_account(return_data, account_data):
  parsed_data = __parse_json_string(return_data)
  return (parsed_data["credentials"]["accessKey"] == account_data["access_key"] and parsed_data["credentials"]["secretKey"] == account_data["secret_key"])


def _verify_user_exists(name, ma):
  user_list = __parse_json_string(ma.user_list())
  return(name in user_list)

def user_present(name, data={}):
  return_data = {'name': name, 'result': None, 'changes': {},  'comment': ""}

  ma = __minio_admin()
  user_list = __parse_json_string(ma.user_list())

  if name in user_list:
    # TODO: implement update mode
    return_data["changes"]["what"] = f"User '{name}' already there"
    user_data = user_list[name]
  else:
    user_data = {}
    if not ("password" in data):
      raise SaltConfigurationError(f"missing password for user '{name}'")
    ma.user_add(name, data["password"])
    if _verify_user_exists(name, ma):
      return_data["changes"]["user"] = f"User '{name}' already created"
    else:
      raise SaltRenderError(f"Something went wrong when trying to create user {name}")

  if "policies" in data:
    new_policies = data["policies"]
    if "policyName" in user_data:
      new_policies = _filter_existing_policies(user_data["policyName"], new_policies)
    if len(new_policies) > 0:
      if ma.attach_policy(policies=new_policies, user=name):
        return_data["changes"]["policies"] = f"Policies {','.join(data['policies'])} attached to user '{name}'"
    else:
      return_data["changes"]["policies"] = f"All Policies were already attached to user '{name}'"

  if "service_accounts" in data:
    current_service_account_list = _get_existing_service_accounts(ma, name)
    for account_name, account_data in data["service_accounts"].items():
      if not ("access_key" in account_data and "secret_key" in account_data):
        raise SaltConfigurationError(f"missing data for service account '{account_name}' for user '{name}' ")

      if _existing_service_account(current_service_account_list, account_data):
        return_data["changes"][f"svsacct_{account_name}"] = f"Service account {account_name}  with {account_data['access_key']} for user {name} already exists"
      else:
        rd = ma.add_service_account(access_key=account_data['access_key'], secret_key=account_data['secret_key'], name=account_name, targetUser=name)
        if _verify_service_account(rd, account_data):
          return_data["changes"][f"svsacct_{account_name}"] = f"Created service account {account_name} for user {name}"
        else:
          raise SaltConfigurationError(f"Something went wrong while configuring service account {account_name} for user {name}")

  return return_data


def user_missing(name):
  return_data = {'name': name, 'result': None, 'changes': {},  'comment': ""}
  ma = __minio_admin()
  try:
    ma.user_remove(name)
    return_data["changes"] = {"what": f"User '{name}' removed"}
  except (pyminio.error.MinioAdminException) as e:
    if e._code == '404':
      return_data["changes"] = {"what": f"User '{name}' already missing"}
    else:
      raise e

  return return_data
