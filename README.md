# Minions

A small formula for saltstack to handle minio.

see pillar.example

Requires [python-minio][0] with the patch for [service accounts per user][1]


## cfgmgmt-template integration

if you are using our [cfgmgmt-template](https://github.com/darix/cfgmgmt-template) as a starting point the saltmaster you can simplify the setup with:

```
git submodule add https://github.com/darix/minions formulas/minions
ln -s /srv/cfgmgmt/formulas/minions/config/enable_minions.conf /etc/salt/master.d/
systemctl restart saltmaster
```


[0]: https://build.opensuse.org/package/show/home:darix:apps/python-minio
[1]: https://build.opensuse.org/projects/home:darix:apps/packages/python-minio/files/target-user-for-service-account.patch?expand=1
