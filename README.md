# Scanning for security vulnarabilities on IBM AIX

This repo contains many of IBM AIX security advisories published by IBM and checks for them, written for Chef Inspec.

To scan your system you must have Chef Inspec (https://inspec.io or https://www.power-devops.com/chef-inspec).

Clone the repository locally and run:

```
for i in * ; do [[ -d $i ]] && inspec exec $i -t ssh://user@server -i ~/.ssh/my_priv_key ; done
```

For more options look at ```inspec exec --help```

