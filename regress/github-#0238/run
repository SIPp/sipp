#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2016
. "`dirname "$0"`/../functions"; init

sippfg -m 1 -sf uas.xml -p 5070 >/dev/null 2>&1 &
job=$!
sippfg -m 1 -sf uac.xml 127.0.0.1:5070 \
    -trace_msg -message_file tmp.log \
    -timeout 4 -timeout_error >/dev/null 2>&1
status=$?
wait $job || status=1

if test $status -eq 0; then
    bye=$(sed -e '/^BYE/,/^[[:blank:]]*$/!d' tmp.log)
    if echo "$bye" | grep -qF 'From: tom.jones@wales.uk'; then
        fail "header match unjustly finds headers by value"
    elif echo "$bye" | grep -qF '"Fromage" <sip:cheese@paris.fr>'; then
        ok
    else
        fail "unknown failure"
    fi
else
    fail "process failure"
fi
