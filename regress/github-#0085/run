#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2015
. "`dirname "$0"`/../functions"; init

# Test that out-of-dialog INFO, NOTIFY, UPDATE and OPTIONS get an
# automatic 200 reply with automaticResponseMode (-aa):
sippbg -sn uas -i 127.0.0.1 -p 5070 -m 1 -aa
sippbg -sf uac.xml -i 127.0.0.1 -m 1 127.0.0.1:5070
job2=$!

# If job2 did not finish, we have failure.
if /bin/kill -0 $job2 2>/dev/null; then
    fail
fi

# Remove all running sipp instances manually.
cleanup

# Test that out-of-dialog INFO, NOTIFY, UPDATE and OPTIONS do *NOT*
# get the automatic 200 if we don't use automaticResponseMode (-aa).
sippbg -sn uas -i 127.0.0.1 -p 5070 -m 1
sippbg -sf uac.xml -i 127.0.0.1 -m 1 127.0.0.1:5070
job2=$!

# If job2 did not finish, it is waiting for job1 to send a 200. This
# is expected behaviour.
if /bin/kill -0 $job2 2>/dev/null; then
    ok
else
    fail
fi
