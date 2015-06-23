#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2015
. "`dirname "$0"`/../functions"; init

sippbg -sn uas -p 5070

# Problem which appears to goes away when -nostdin or when screen is
# not initialized.
`get_sipp` -m 1 -sn uac -p 5071 127.0.0.1:5070 -timeout 2 -timeout_error \
    >/dev/null 2>&1
status=$?

if test $status -eq 0; then
    ok
else
    fail "uac packets seem not to arrive at uas"
fi
