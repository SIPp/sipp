#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2015
. "`dirname "$0"`/../functions"; init

sippbg -sf uas.xml -p 5070
sippfg -m 20 -sf uac.xml 127.0.0.1:5070 \
    -timeout 4 -timeout_error -trace_stat -stf tmp.log \
    >/dev/null 2>&1
status=$?

# (it's not a log, it's a csv)
calls=`cut -d';' -f12 tmp.log | tail -n1`
failed=`cut -d';' -f18 tmp.log | tail -n1`
if test $calls -eq 20 && test $failed -gt 0; then
    ok
else
    fail "got $calls calls, and $failed failed"
fi
