#!py
from salt.exceptions import SaltConfigurationError, SaltRenderError

def run():
  config = {}
  if not("minio" in __pillar__):
    return config

  minio_pillar = __pillar__["minio"]

  config["minio_packages"] = {
    "pkg.installed": [
      {"pkgs": ["rclone", "minio", "minio-client"]},
    ]
  }

  if "environment" in minio_pillar:
    config["minio_config"] = {
      "file.managed": [
        {"name":     "/etc/default/minio"},
        {"user":     "root"},
        {"group":    "root"},
        {"mode":     "0640"},
        {"template": "jinja"},
        {"require":  ["minio_packages"]},
        {"source":   "salt://minio/files/etc/default/minio.j2"},
      ]
    }

    service_deps = ["minio_config"]
    config["minio_service"] = {
      "service.running": [
        {"name": "minio.service"},
        {"enable": True},
        {"watch": service_deps},
        {"require": service_deps},
        {"onchanges": service_deps},
      ]
    }

    config["salt_minio_client_config_dir"] = {
      "file.directory": [
        {"name": "/etc/salt/minio-client"},
        {"user": "root"},
        {"group": "salt"},
        {"mode": "0750"},
      ]
    }

    config["salt_minio_client_config"] = {
      "file.directory": [
        {"name": "/etc/salt/minio-client/config.json"},
        {"user": "root"},
        {"group": "salt"},
        {"mode": "0640"},
        {"require": ["salt_minio_client_config_dir"] },
        {"source": "salt://minio/files/etc/salt/minio-client/config.json.j2"},
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
        "minio.policy": [
          {"name": policy_name},
          {"data": policy_data},
        ]
      }

  if "users" in minio_pillar:
    for user_name, user_data in minio_pillar["users"].items():
      if not("policies" in user_data):
          raise SaltConfigurationError(f"No policies assigned to user {user_name}")

      policies = user_data["policies"]
      for policy in policies:
        if not(policy in policies_list):
          raise SaltConfigurationError(f"Policy {policy} assigned to user {user_name} does not exists")

      user_policy_deps = [f"minio_policy_{x}" for x in user_data["policies"]]
      config[f"minio_user_{user_name}"] = {
        "minio.user": [
          {"name":    user_name},
          {"data":    user_data},
          {"require": user_policy_deps},
        ]
      }

  if "buckets" in minio_pillar:
    for bucket_name, bucket_data in minio_pillar["buckets"].items():
      config[f"minio_bucket_{bucket_name}"] = {
        "minio.bucket": [
          {"name": bucket_name},
          {"data": bucket_data},
        ]
      }

  return config