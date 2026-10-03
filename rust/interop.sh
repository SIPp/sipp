#!/bin/bash
# Interop checks: sipp-rs against C SIPp in both directions, and against
# itself. Every pair runs at once on its own loopback addresses.
# usage: interop.sh [path/to/c/sipp]   (N calls per pair, default 20)
# The default C SIPp is the one built from this checkout, which carries the
# fixes interop found (cmake -B build-c && ninja -C build-c sipp).
cd "$(dirname "$0")/tests" || exit 1
C=$(realpath "${1:-../../build-c/sipp}")
R=../target/release/sipp-rs
N=${N:-20}; RATE=${RATE:-50}
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT

# TLS, with a throwaway certificate.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$out/cakey.pem" -out "$out/cacert.pem" -days 1 -subj /CN=sipp-rs >/dev/null 2>&1
tls="-tls_cert $out/cacert.pem -tls_key $out/cakey.pem"

pairs=0
run() { # name uas-cmd uac-cmd [uac extra args]
    pairs=$((pairs + 1))
    local i=$pairs a=127.0.$((100 + pairs)).2 b=127.0.$((100 + pairs)).3
    (
        # Each its own control port: a failed bind takes ~20 ms on WSL, and
        # thirty processes scanning up from 8888 kept the last ones from
        # answering a TLS handshake for seconds.
        timeout 60 $2 -i $b -p 5060 -m $N -cp $((9000 + 2 * i)) > "$out/$i.uas" 2>&1 & up=$!
        sleep 0.3
        timeout 60 $3 $b:5060 -i $a -p 5060 -m $N -r $RATE $4 -cp $((9001 + 2 * i)) > "$out/$i.uac" 2>&1; uac=$?
        wait $up; uas=$?
        printf '%-36s uac=%s uas=%s\n' "$1" $uac $uas > "$out/$i.result"
    ) &
}

# Over TCP and TLS, a SIPp without "Don't fail a call whose connection
# closes just before its timewait" fails the UAS's last calls.
for t in u1 t1 tn l1 ln; do
    run "rust uac -> C uas ($t)"    "$C -sn uas -nostdin -t $t $tls"  "$R -sn uac -t $t"
    run "C uac -> rust uas ($t)"    "$R -sn uas -t $t $tls"           "$C -sn uac -nostdin -t $t $tls"
    run "rust uac -> rust uas ($t)" "$R -sn uas -t $t $tls"           "$R -sn uac -t $t"
done
# SIP over WebSocket, on TCP and TLS; with C SIPp once it has it (SIPp
# pull request #1028).
c_ws=$("$C" -h 2>&1 | grep -q 'w1: SIP over WebSocket' && echo yes)
for t in w1 wn x1 xn; do
    if [ -n "$c_ws" ]; then
        run "rust uac -> C uas ($t)"    "$C -sn uas -nostdin -t $t $tls"  "$R -sn uac -t $t"
        run "C uac -> rust uas ($t)"    "$R -sn uas -t $t $tls"           "$C -sn uac -nostdin -t $t $tls"
    fi
    run "rust uac -> rust uas ($t)" "$R -sn uas -t $t $tls"           "$R -sn uac -t $t"
done
# SCTP, with a C SIPp built with it (-v says so).
if "$C" -v 2>&1 | grep -q -- '-SCTP'; then
    for t in s1 sn; do
        run "rust uac -> C uas ($t)"    "$C -sn uas -nostdin -t $t"  "$R -sn uac -t $t"
        run "C uac -> rust uas ($t)"    "$R -sn uas -t $t"           "$C -sn uac -nostdin -t $t"
        run "rust uac -> rust uas ($t)" "$R -sn uas -t $t"           "$R -sn uac -t $t"
    done
fi
# Digest auth, each side verifying the other's credentials, and -inf fields.
for n in auth_MD5_auth-int auth_SHA-256_auth; do
    run "$n: rust uac -> C uas" "$C -sf ${n}_uas.xml -nostdin" "$R -sf ${n}_uac.xml"
    run "$n: C uac -> rust uas" "$R -sf ${n}_uas.xml"          "$C -sf ${n}_uac.xml -nostdin"
done
# The -inf files, written here since *.csv is ignored by git.
printf 'SEQUENTIAL\nuser1;secret;[authentication username=user1 password=secret]\nuser1;secret;[authentication username=user1 password=secret]\n' > "$out/users.csv"
printf 'SEQUENTIAL,PRINTF=5\nuser1;%%08d\n' > "$out/printf.csv"
inf="-inf $out/users.csv -inf $out/printf.csv"
run "inject: rust uac -> C uas" "$C -sf auth_MD5_auth-int_uas.xml -nostdin" "$R -sf inject_uac.xml" "$inf"
run "inject: C uac -> rust uas" "$R -sf auth_MD5_auth-int_uas.xml"          "$C -sf inject_uac.xml -nostdin" "$inf"

wait
fail=0
for i in $(seq 1 $pairs); do
    cat "$out/$i.result"
    grep -q 'uac=0 uas=0' "$out/$i.result" || fail=1
done
exit $fail
