#!/bin/bash
# SIPp's sipp_scenarios/pfca_* SRTP/RTP-pattern pairs, each way between
# sipp-rs and C SIPp, and C against itself as the baseline.
# usage: pfca.sh [path/to/c/sipp]   (COMBOS="C C" for C against C only, etc.)
cd "$(dirname "$0")/../sipp_scenarios" || exit 1
C=$(realpath "${1:-../build-c/sipp}")
R=$(realpath ../rust/target/release/sipp-rs)
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
pairs=()
for uac in pfca_uac*.xml; do
    rest=${uac#pfca_uac}
    case $rest in
        _apattern*) uas=pfca_uas_audio${rest#_apattern} ;;
        _vpattern*) uas=pfca_uas_video${rest#_vpattern} ;;
        _bpattern*) uas=pfca_uas_both${rest#_bpattern} ;;
        _avpattern*) uas=pfca_uas_audiovideo${rest#_avpattern} ;;
        .xml) uas=pfca_uas.xml ;;
        *) continue ;;
    esac
    [ -f "$uas" ] && pairs+=("$uac $uas")
done
i=0
for p in "${pairs[@]}"; do
    set -- $p
    IFS=, read -ra combos <<< "${COMBOS:-C C,R C,C R}"
    for combo in "${combos[@]}"; do
        i=$((i + 1)); set -- $p $combo
        uac_bin=$C; [ $3 = R ] && uac_bin=$R
        uas_bin=$C; [ $4 = R ] && uas_bin=$R
        a=127.$((i / 250 + 10)).$((i % 250)).2; b=127.$((i / 250 + 10)).$((i % 250)).3
        (
            n1=; [ $uas_bin = $C ] && n1=-nostdin; n2=; [ $uac_bin = $C ] && n2=-nostdin
            # UAS scenarios without echo actions of their own expect -rtp_echo.
            echo=; grep -q 'rtp_echo=' $2 || echo=-rtp_echo
            timeout 30 $uas_bin $n1 -m 1 -sf $2 -i $b -p 5060 $echo > "$out/$i.uas" 2>&1 & up=$!
            sleep 0.5
            timeout 30 $uac_bin $n2 -m 1 -sf $1 -i $a -p 5060 $b:5060 > "$out/$i.uac" 2>&1; rc=$?
            wait $up; rs=$?
            echo "${1%.xml} $3 $4 $rc $rs" > "$out/$i.r"
        ) &
        # A few dozen processes at a time is plenty.
        (( i % 24 == 0 )) && wait
    done
done
wait
cat "$out"/*.r | sort | awk '
    { key = $1; res = ($4 == 0 && $5 == 0) ? "ok" : $4 "/" $5; r[key, $2 " -> " $3] = res; keys[key] = 1 }
    END {
        printf "%-58s %-9s %-9s %-9s\n", "uac scenario", "C->C", "rust->C", "C->rust"
        for (k in keys) printf "%-58s %-9s %-9s %-9s\n", k, r[k, "C -> C"], r[k, "R -> C"], r[k, "C -> R"]
    }' | sort
