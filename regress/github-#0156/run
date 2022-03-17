#!/bin/sh
# This regression test is a part of SIPp.
# Author: Walter Doekes, OSSO B.V., 2015
. "`dirname "$0"`/../functions"; init

# Make the test skippable
test -n "$TEST_SKIP_VALGRIND" && exit 0

# Check that we have valgrind
which valgrind >/dev/null || fail "no valgrind installed"

# Valgrind on UAS.
valgrind --xml=yes --xml-file=uas.log --partial-loads-ok=yes \
    --show-leak-kinds=all --leak-check=full `get_sipp` -m 10 -sn uas \
    >/dev/null 2>&1 &
uaspid=$!
sleep 1

# Valgrind on UAC.
valgrind --xml=yes --xml-file=uac.log --partial-loads-ok=yes \
    --show-leak-kinds=all --leak-check=full `get_sipp` -m 10 -sn uac \
    127.0.0.1 >/dev/null 2>&1 &
uacpid=$!

wait $uaspid
test $? -ne 0 && fail "UAS returned non-zero (might be benign(*))"

wait $uacpid
test $? -ne 0 && fail "UAC returned non-zero (might be benign(*))"

grep -q '<error>' uas.log && fail "valgrind reported leaks in UAS"
grep -q '<error>' uac.log && fail "valgrind reported leaks in UAC"

ok

# (*) https://bugs.kde.org/show_bug.cgi?id=345307
# In some cases, leaks are reported that shouldn't be. If you're looking
# at dl-init.c, it might be one of those cases. Upgrading gcc (from 5 to
# higher) can help. Or upgrading valgrind.
