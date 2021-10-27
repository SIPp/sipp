#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2018
. "`dirname "$0"`/../functions"; init

# Listen on UDP port 6002 to block SIPp from getting that port.
udplisten 6002 >tmp.log 2>&1 &
listenjob=$!

sippbg -sn uas -i 127.0.0.1 -p 5070 -m 1 \
    -min_rtp_port 6200  # media port at 6200
sippfg -sn uac -i 127.0.0.1 -m 1 127.0.0.1:5070 >uac.log 2>&1
fgok=$?

# Don't care about 6002 getting any traffic or not
wait $listenjob

# Our fg job succeeded; did not fail on missing 6002
if test $fgok -eq 0; then
    ok
else
    fail "$(grep errno uac.log | sed -e 's/.*: //')"
fi
