#!/bin/sh
# This regression test is a part of SIPp.
. "`dirname "$0"`/../functions"; init

sippfg -m 1 -sf ../../sipp_scenarios/pfca_uas_both_crypto_simple.xml \
  -t u1 -i 127.0.0.3 -p 5060 -srtpcheck_debug -trace_msg \
  >/dev/null 2>&1 &
job=$!

sippfg -m 1 -sf ../../sipp_scenarios/pfca_uac_bpattern_crypto_simple.xml \
  -t u1 -i 127.0.0.2 -p 5060 -srtpcheck_debug 127.0.0.3:5060 \
  >/dev/null 2>&1
status=$?
wait $job || status=1

# Rename * to *.log here. The srtpcheck stuff spits out lots of files
# without extensions.
find . -type f '!' -name 'run' '!' -name '*.log' '!' -name '*.xml' -print0 |
  xargs --no-run-if-empty -0 -IX env file=X sh -c 'mv "$file" "$file.log"'

if test $status -eq 0; then
    ok
else
    fail
fi
