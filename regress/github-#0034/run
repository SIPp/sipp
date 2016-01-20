#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2016
. "`dirname "$0"`/../functions"; init

tcplisten 5070 >notify-1234.log 2>&1 &
notify_1234=$!
tcplisten 5071 >notify-manylf.log 2>&1 &
notify_manylf=$1
tcplisten 5072 >notify-nocrlf.log 2>&1 &
notify_nocrlf=$1
tcplisten 5073 >notify-withlf.log 2>&1 &
notify_withlf=$1
sleep 1

sippbg -m 1 -sf notify-1234.xml -t t1 127.0.0.1:5070
sippbg -m 1 -sf notify-manylf.xml -t t1 127.0.0.1:5071
sippbg -m 1 -sf notify-nocrlf.xml -t t1 127.0.0.1:5072
sippbg -m 1 -sf notify-withlf.xml -t t1 127.0.0.1:5073
/bin/kill -9 $notify_1234 $notify_manylf $notify_nocrlf $notify_withlf 2>&1

last_bytes_equal() {
	size=`stat -c%s $1`
	tail=`dd if=$1 bs=1 skip=$((size - $2)) 2>/dev/null`
	test "$tail" = "$3"
}

fail=
last_bytes_equal notify-1234.log 5 "`printf '\n\1\2\3\4'`" || fail="$fail notify-1234"
last_bytes_equal notify-manylf.log 5 "`printf '0\r\n\r\n'`" || fail="$fail notify-manylf"
last_bytes_equal notify-nocrlf.log 5 "`printf '0\r\n\r\n'`" || fail="$fail notify-nocrlf"
last_bytes_equal notify-withlf.log 8 "`printf '3\r\n\r\nX\r\n'`" || fail="$fail notify-withlf"

if test -z "$fail"; then
    ok
else
    fail "on$fail"
fi
