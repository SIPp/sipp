#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2016
. "`dirname "$0"`/../functions"; init

tcplisten 5070 >tmp.log 2>&1 &
pid=$!
sleep 1
sippbg -m 1 -sf notify-brackets.xml -t t1 127.0.0.1:5070
/bin/kill -9 $pid 2>/dev/null

if grep -qF 'X-Literal: [date]' tmp.log &&
        ! grep -q 'X-Keyword: .*[][].*$' tmp.log; then
    ok
else
    fail
fi
