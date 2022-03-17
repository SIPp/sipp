#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2016
#
# Test Record-Route and [routes].
#
. "`dirname "$0"`/../functions"; init

sippbg -sf uas.xml -p 5070 -i 127.0.127.1 -trace_msg -message_file uas.log
sippfg -m 1 -sf uac.xml 127.0.127.1:5070 -i 127.0.127.1 \
    -trace_msg -message_file uac.log \
    -timeout 5 -timeout_error >/dev/null 2>&1
status=$?

test $status -ne 0 && fail "SIPp UAC job failed"

uac_route=`sed -e '/^ACK /,/^$/!d;/^Route:/!d;s/[[:cntrl:]]//g' uac.log`
uac_expected="Route:\
 <sip:127.0.127.1:2;lr>,\
 <sip:127.0.127.1:3;lr>,\
 <sip:127.0.127.1:5060;lr>"

uas_route=`sed -e '/^BYE /,/^$/!d;/^Route:/!d;s/[[:cntrl:]]//g' uas.log`
uas_expected="Route:\
 <sip:127.0.127.1:5060;lr>,\
 <sip:127.0.127.1:3;lr>,\
 <sip:127.0.127.1:2;lr>"

if test "$uac_route" != "$uac_expected"; then
    fail "UAC Route unexpected, got: \"$uac_route\" (not \"$uac_expected\")"
elif test "$uas_route" != "$uas_expected"; then
    fail "UAS Route unexpected, got: \"$uas_route\" (not \"$uas_expected\")"
else
    ok
fi
