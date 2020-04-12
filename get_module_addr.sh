#!/bin/bash
# ./get_mod_addr.sh procfs1
#ssh -p 8022 -i bastian_id.rsa -t bastian@localhost "sudo cat /proc/modules | awk '{if(\$1 == \"$1\") print \$6}'"
ssh -p 8022  ss@localhost "sudo -S cat /sys/module/procfs1/sections/.text"
