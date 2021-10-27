#!/bin/sh
# This regression test is a part of SIPp.
# Author: Pietro Bertera, Snom Technology AG, 2016
#
# Start the UAS scenario, UAS stops the rtp_echo 
# for some seconds
#
. "`dirname "$0"`/../functions"; init

sippbg -sf uas.xml -p 5070 -rtp_echo
sippfg -m 1 -sf uac.xml 127.0.0.1:5070 \
    -timeout 10 -timeout_error >/dev/null 2>&1
status=$?

test $status -ne 0 && fail "SIPp UAC job failed"
ok
