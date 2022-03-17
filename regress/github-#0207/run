#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2019
. "`dirname "$0"`/../functions"; init

sippbg -m 1 -sf uas.xml -p 5070
if ! sippfg -m 1 -sf uac.xml 127.0.0.1:5070 \
      -trace_msg -message_file tmp.log -trace_err \
      -timeout 4 -timeout_error >/dev/null 2>&1; then
    fail "call failed"
fi

from="$(sed -e '/message received/,$!d;/^From/!d;s/[[:cntrl:]]*$//' tmp.log)"
if test "$from" = "From: Alice <sip:alice@localhost>;tag=uniquetag"; then
    # From: Alice <sip:alice@localhost>;tag=uniquetag
    # ^-- last_From only gets the SIP-body from
    ok
else
    # From: Alice <sip:alice@localhost>;tag=uniquetag, <sip:anonymous@anonymous.invalid>)
    # ^-- last_From incorrectly gets the body-from too
    fail "got From from body? ($from)"
fi
