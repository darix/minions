#
# TODO: implement test mode - currently the code is always active
#       see filetreedeployer for how Georg implemented it theres
# TODO: implement proper result_data
#

import json
import logging
import os
import re
import tempfile
from urllib.parse import urlparse

from salt.exceptions import SaltConfigurationError, SaltRenderError

import minio as pyminio

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
    ret = json.loads(data)
    return ret
  except (json.decoder.JSONDecodeError) as e:
    message = f"Failed to parse json string: {e}: {data}"
    log.error(message)
    raise SaltRenderError(message)


def __parse_json_file(filename):
  try:
    ret = json.load(open(filename))
    return ret
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
  r = re.compile(r'\s*(?P<config_option>\S+)=(?P<config_value>".*?"|\S+)\s*')
  fields = r.split(section_data_string)
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
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}
  if "minio" in __pillar__ and "config" in __pillar__["minio"]:
    ma = __minio_admin()

    for section_name, section_data in __pillar__["minio"]["config"].items():
      try:
        ma.config_set(section_name, section_data)
        if _is_site_config_set(ma, section_name, section_data):
          ret["changes"][f"site_setting_{section_name}"] = f"successfully set settings for {section_name}"
      except pyminio.error.MinioAdminException as e:
        exception_data = __parse_json_string(e._body)
        message = exception_data["Message"]
        ret["result"] = False
        ret["changes"][f"site_setting_{section_name}"] = f"Failed to set all settings for {section_name}: {message}"

  return ret


def bucket_present(name, data={}):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}

  mc = __minio_client()
  found = mc.bucket_exists(name)

  if found:
    # TODO: implement update mode for settings
    ret["result"] = True
    ret["comment"] = f"Bucket {name} already there"
  else:
    if __opts__["test"]:
      ret["comment"] = f"Bucket {name} would be created"
      return ret
    try:
      if not ("minio" in __pillar__ and "location" in __pillar__["minio"]):
        raise SaltConfigurationError("Missing location in minio pillar")
      location = __pillar__["minio"]["location"]
      locking = False
      if "locking" in data:
        locking = data["locking"]
      mc.make_bucket(bucket_name=name, location=location, object_lock=locking)
      if mc.bucket_exists(name):
        ret["result"] = True
        ret["changes"]["bucket_present"] = f"Bucket {name} was created successfully"
      else:
        ret["result"] = False
        ret["comment"] = f"Bucket {name} failed to be created"
    except (ValueError) as e:
      raise e

  return ret


def bucket_missing(name):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}

  mc = __minio_client()
  found = mc.bucket_exists(name)

  if found:
    if __opts__["test"]:
      ret["comment"] = f"Bucket {name} would be removed"
      return ret

    mc.remove_bucket(name)

    if mc.bucket_exists(name):
      ret["result"] = False
      ret["comment"] = f"Bucket {name} failed to be removed"

    ret["result"] = True
    ret["changes"]["bucket_missing"] = f"Bucket {name} removed"
  else:
    ret["result"] = True
    ret["comment"] = "Bucket {name} was already missing"

  return ret


def __policy_list(ma):
  return __parse_json_string(ma.policy_list())


def __policy_exists(ma, name):
  return name in __policy_list(ma)


def policy_present(name, data={}):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}

  ma = __minio_admin()
  policy_list = __policy_list(ma)

  if __policy_exists(ma, name):
    # TODO: implement update mode
    ret["result"] = True
    ret["comment"] = f"Policy {name} already there"
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
        if __policy_exists(ma, name):
          ret["result"] = True
          ret["changes"]["policy_present"] = f"Policy {name} created successfully"
      except (pyminio.error.MinioAdminException) as e:
        log.error(f"Adding policy {name} failed: {e} {policy_string}")
        raise
      finally:
        os.remove(policy_file.name)

  return ret


def policy_missing(name):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}

  ma = __minio_admin()
  policy_list = __parse_json_string(ma.policy_list())

  if __policy_exists(ma, name):
    if __opts__["test"]:
      ret["comment"] = f"Policy {name} would be removed"
      return ret
    ma.policy_remove(name)
    if __policy_exists(ma, name):
      ret["result"] = False
      ret["comment"] = f"Policy {name} failed to be removed"
    else:
      ret["result"] = True
      ret["changes"]["policy_missing"] = f"Policy {name} removed"
  else:
    ret["result"] = True
    ret["comment"] = f"Policy {name} is already missing"

  return ret


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


def _existing_service_account(current_service_account_list, access_key):
  for current_service_account in current_service_account_list:
    if current_service_account["accessKey"] == access_key:
      return True
  return False


def _verify_service_account(ret, access_key, secret_key):
  parsed_data = __parse_json_string(ret)
  return (parsed_data["credentials"]["accessKey"] == access_key and parsed_data["credentials"]["secretKey"] == secret_key)


def _verify_user_exists(name, ma):
  user_list = __parse_json_string(ma.user_list())
  return (name in user_list)


def user_present(name, password):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}

  ma = __minio_admin()
  user_list = __parse_json_string(ma.user_list())

  if _verify_user_exists(name, ma):
    # TODO: implement update mode
    ret["result"] = True
    ret["comment"] = f"User '{name}' already there"
  else:
    if __opts__["test"]:
      ret["comment"] = f"User '{name}' would be created"
    else:
      ma.user_add(name, password)
      if _verify_user_exists(name, ma):
        ret["result"] = True
        ret["changes"]["user"] = f"User '{name}' already created"
      else:
        ret["result"] = False
        ret["comment"] = f"Something went wrong when trying to create user {name}"
        return ret

  return ret


def user_policies_present(name, username, assigned_policies):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}
  ma = __minio_admin()
  user_list = __parse_json_string(ma.user_list())
  user_data = user_list[username]

  # TODO: we should probably check if assigned_policies is a list

  new_policies = assigned_policies
  if "policyName" in user_data:
    new_policies = _filter_existing_policies(user_data["policyName"], new_policies)

  if len(new_policies) > 0:
    if __opts__["test"]:
      ret["changes"]["policies"] = f"Policies {','.join(assigned_policies)} would be attached to user '{username}'"
    else:
      if ma.attach_policy(policies=new_policies, user=username):
        ret["result"] = True
        ret["changes"]["policies"] = f"Policies {','.join(new_policies)} attached to user '{username}'"
  else:
    ret["result"] = True
    ret["comment"] = f"All Policies were already attached to user '{username}'"

  return ret


def user_svcacct_present(name, username, svcacct, access_key, secret_key):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}

  ma = __minio_admin()
  current_service_account_list = _get_existing_service_accounts(ma, username)
  if _existing_service_account(current_service_account_list, access_key):
    ret["result"] = True
    ret["comment"] = f"Service account {svcacct}  with {access_key} for user {username} already exists"
    return ret

  if __opts__["test"]:
    ret["changes"][f"svsacct_{svcacct}"] = f"service account {svcacct} for user {username} would be created"
  else:
    rd = ma.add_service_account(access_key=access_key, secret_key=secret_key, name=svcacct, targetUser=username)
    if _verify_service_account(rd, access_key, secret_key):
      ret["result"] = True
      ret["changes"][f"svsacct_{svcacct}"] = f"Created service account {svcacct} for user {username}"
    else:
      raise SaltConfigurationError(f"Something went wrong while configuring service account {svcacct} for user {username}")
  return ret


def user_missing(name):
  ret = {'name': name, 'result': None, 'changes': {}, 'comment': ""}
  ma = __minio_admin()

  try:
    if __opts__["test"]:
      ret["comment"] = f"User '{name}' would be removed"
      return ret

    ma.user_remove(name)
    ret["result"] = True
    ret["changes"]["user_missing"] = f"User '{name}' was removed"
  except (pyminio.error.MinioAdminException) as e:
    if e._code == '404':
      ret["result"] = True
      ret["comment"] = f"User '{name}' already missing"
    else:
      raise e

  return ret
