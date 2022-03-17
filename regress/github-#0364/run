#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2019
. "`dirname "$0"`/../functions"; init

tcplisten 5070 >empty-keyword-allowed.log 2>&1 &
listen=$!
sleep 1

( sippbg -m 1 -sf empty-keyword-allowed.xml -t t1 127.0.0.1:5070 \
    -key keyword '' ); ret=$?
/bin/kill -9 $listen 2>&1
test $ret -ne 0 && exit 1

if grep -q "X-Keyword: --" empty-keyword-allowed.log; then
    ok
else
    fail "on$fail"
fi
