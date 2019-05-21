#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2016
. "`dirname "$0"`/../functions"; init

tcplisten 5070 >reply488.log 2>&1 &
reply488=$!
sleep 1

sippfg -m 1 -sf reply488.xml -t t1 127.0.0.1:5070 >/dev/null 2>&1

last_bytes_equal() {
    size=`stat -c%s $1`
    tail=`dd if=$1 bs=1 skip=$((size - $2)) 2>/dev/null`
    test "$tail" = "$3"
}

fail=
last_bytes_equal reply488.log 5 "`printf 'ncy\r\n'`" || fail="$fail bad-EOF"
grep -q 'Content-Length: *232[[:cntrl:]]$' reply488.log || fail="$fail bad-len"

if test -z "$fail"; then
    ok
else
    fail "on$fail"
fi
