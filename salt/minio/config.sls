#
# minions
#
# Copyright (C) 2025   darix
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#!py
from salt.exceptions import SaltConfigurationError

def run():
  config = {}
  if not ("minio" in __pillar__):
    return config

  minio_pillar = __pillar__["minio"]
  minio_settings_deps = ["salt_minio_client_config", "minio_service"]

  if "config" in minio_pillar:
    for config_section, config_data in minio_pillar["config"].items():
      config[f"deploy_site_config_{config_section}"] = {
        "minio.site_config": [
          {"section": config_section},
          {"config": config_data},
          {"require": minio_settings_deps},
        ]
      }

  policies_list = []
  policies_state_list = []
  if "policies" in minio_pillar:
    for policy_name, policy_data in minio_pillar["policies"].items():
      policy_state = f"minio_policy_{policy_name}"

      policies_list.append(policy_name)
      policies_state_list.append(policy_state)

      config[policy_state] = {
        "minio.policy_present": [
          {"name": policy_name},
          {"data": policy_data},
          {"require": minio_settings_deps},
        ]
      }

  if "users" in minio_pillar:
    for user_name, user_data in minio_pillar["users"].items():
      if not ("password" in user_data):
        raise SaltConfigurationError(f"No password assigned to user {user_name}")

      if not ("policies" in user_data):
        raise SaltConfigurationError(f"No policies assigned to user {user_name}")

      policies = user_data["policies"]
      for policy in policies:
        if not (policy in policies_list):
          raise SaltConfigurationError(f"Policy {policy} assigned to user {user_name} does not exists")

      user_policy_deps = [f"minio_policy_{x}" for x in user_data["policies"]]
      user_policy_deps.extend(minio_settings_deps)
      user_key = f"minio_user_{user_name}"
      user_policy_assignment_key = f"minio_user_policies_{user_name}"

      config[user_key] = {
        "minio.user_present": [
          {"name": user_name},
          {"password": user_data["password"]},
          {"require": user_policy_deps},
        ]
      }

      config[user_policy_assignment_key] = {
        "minio.user_policies_present": [
          {'username': user_name},
          {'assigned_policies': policies},
          {'require': [user_key]},
        ]
      }

      if "service_accounts" in user_data:
        for svcacct, svc_data in user_data["service_accounts"].items():
          user_service_account_key = f"minio_user_{user_name}_svcacct_{svcacct}"
          if not ("access_key" in svc_data) or not (svc_data["secret_key"]):
            raise SaltConfigurationError(f"missing access_key/secret_key for {user_name}/{svcacct}")

          params = [
            {'username': user_name},
            {'svcacct': svcacct},
            {'access_key': svc_data["access_key"]},
            {'secret_key': svc_data["secret_key"]},
            {'require': [user_key]},
          ]

          config[user_service_account_key] = {
            "minio.user_svcacct_present": params
          }

  if "buckets" in minio_pillar:
    for bucket_name, bucket_data in minio_pillar["buckets"].items():
      config[f"minio_bucket_{bucket_name}"] = {
        "minio.bucket_present": [
          {"name": bucket_name},
          {"data": bucket_data},
          {"require": minio_settings_deps}
        ]
      }

  return config
