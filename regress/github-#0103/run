#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2014
. "`dirname "$0"`/../functions"; init

sippbg -sf uas-modified.xml -i 127.0.0.1 -p 5070 -m 1
sippbg 127.0.0.1:5070 -sn uac -i 127.0.0.1 -m 1
job2=$!

# If job2 was finished (ran the entire scenario), we have success.
if ! /bin/kill -0 $job2 2>/dev/null; then
    ok
else
    fail
fi
