#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2015
. "`dirname "$0"`/../functions"; init

# Test whether sipp will run without a proper TERM setting.
# After pull request #130 it will, as long as stdout is not a tty.
TERM=bad_term sippbg -sn uas -i 127.0.0.1 -p 5070 -m 1
TERM=bad_term sippbg -sn uac -i 127.0.0.1 -m 1 127.0.0.1:5070
job2=$!

# If job2 was finished (ran the entire scenario), we have success.
if ! /bin/kill -0 $job2 2>/dev/null; then
    ok
else
    fail
fi
