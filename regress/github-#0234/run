#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2016
. "`dirname "$0"`/../functions"; init

sippfg -m 1 -sf uas.xml -p 5070 >/dev/null 2>&1 &
job=$!
sippfg -m 1 -sf uac.xml 127.0.0.1:5070 \
    -timeout 4 -timeout_error >/dev/null 2>&1
status=$?
wait $job || status=1

if test $status -eq 0; then
    ok
else
    fail "bad R-URI through [next_url]?"
fi
