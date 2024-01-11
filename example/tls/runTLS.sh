#!/bin/bash
./sipp -t u1 -i 127.0.0.1 -p 3062 127.0.0.1:4060 -sf scenarios/regbob.xml -m 1 -trace_err -auth_pipe b.dat
./sipp -t l1 -i 127.0.0.1 -p 3063 127.0.0.1:4061 -sf scenarios/regbob2.xml -m 1 -trace_err -auth_pipe b.dat
