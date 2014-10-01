#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2014
. "`dirname "$0"`/../functions"; init

sippbg 127.0.0.1:5070 -sn 3pcc-C-B -3pcc 127.0.0.1:9000 -i 127.0.0.1 -p 5071 -m 1
sippbg 127.0.0.1:5072 -sn 3pcc-C-A -3pcc 127.0.0.1:9000 -i 127.0.0.1 -p 5073 -m 1 -trace_msg -message_file tmp.log

if grep -q Via.*127.0.0.1:5073 tmp.log; then
    ok
else
    fail
fi
