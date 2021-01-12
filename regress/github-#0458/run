#!/bin/sh
# This regression test is a part of SIPp.
. "`dirname "$0"`/../functions"; init

sippfg -m 1 -sf uas.xml -p 5070 >/dev/null 2>&1 &
job=$!

sippfg -m 1 -sf uac.xml 127.0.0.1:5070 \
    -trace_err -error_file err.log \
    -timeout 4 -timeout_error >/dev/null 2>&1
status=$?
wait $job || status=1

if test $status -eq 0; then
    ok
else
    if grep -q 'Matching Error' err.log; then
        fail "matching error - escaping?"
    else
        fail "unknown failure"
    fi
fi
