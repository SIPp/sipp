#!/bin/bash
./sipp 127.0.0.3 -t t1 -p 3061 -sf scenarios/regIPSEC1.xml -m 1 -trace_err -trace_msg -au 001019901003516@ims.mnc001.mcc001.3gppnetwork.org -ap test -auth_pipe b.dat
./sipp 127.0.0.3:`cut -s -d";" -f4 spis.csv` -t t1 -p 12345 -sf scenarios/regIPSEC2.xml -m 1 -trace_err -trace_msg -inf spis.csv -au 001019901003516@ims.mnc001.mcc001.3gppnetwork.org -ap test -auth_pipe b.dat
./sipp 127.0.0.3 -t t1 -p 3062 -sf scenarios/regIPSEC3.xml -m 1 -trace_err -trace_msg
