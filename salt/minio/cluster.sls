#!py
from salt.exceptions import SaltConfigurationError

from urllib.parse import urlparse
import re

def __subdir_list():
  ret = []
  up=urlparse(__pillar__["minio"]["environment"]["volumes"])
  path_re=re.compile(r'^(?P<basedir>\S+)\{(?P<start>\d+)\.{2,3}(?P<end>\d+)\}$')
  mo=path_re.match(up.path)
  if mo:
     ret.append(mo.group('basedir'))
  else:
     ret.append(up.path)

  # start=int(mo.group('start'))
  # end=int(mo.group('end'))
  # i=start
  # while i<=end:
  #   ret.append(f"{mo.group('basedir')}{i}")
  #   i=i+1
  return ret

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
    i=0
    for dir in __subdir_list():
      dir_key = f"minio_cluster_dir_{i}"
      service_deps.append(dir_key)
      config[dir_key] = {
        "file.directory": [
          {"name": dir},
          {"user": "minio"},
          {"group": "minio"},
          {"mode": "0750"},
          {"require": ["minio_packages"]},
        ]
      }

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
      "file.managed": [
        {"name": "/etc/salt/minio-client/config.json"},
        {"user": "root"},
        {"group": "salt"},
        {"mode": "0640"},
        {"template": "jinja"},
        {"require": ["salt_minio_client_config_dir"] },
        {"source": "salt://minio/files/etc/salt/minio-client/config.json.j2"},
      ]
    }

    config["root_minio_client_config_dir"] = {
      "file.directory": [
        {"name": "/root/.minio-client"},
        {"user": "root"},
        {"group": "root"},
        {"mode": "0750"},
      ]
    }

    config["root_minio_client_config"] = {
      "file.managed": [
        {"name": "/root/.minio-client/config.json"},
        {"user": "root"},
        {"group": "root"},
        {"mode": "0640"},
        {"template": "jinja"},
        {"require": ["root_minio_client_config_dir"] },
        {"source": "salt://minio/files/etc/salt/minio-client/config.json.j2"},
      ]
    }

  return config