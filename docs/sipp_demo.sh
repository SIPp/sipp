#!/bin/bash
#
# sipp remote_host[:remote_port] [options]
# 
# - m <n> 	   : Stop the call after n calls are processed
# -r               : Set the call rate (in calls per seconds). 
# -l               : Set the maximum number of simultaneous calls. Once this
#                      limit is reached, traffic is decreased until the number
#                      of open calls goes down. Default:
#                        (3 * call_duration (s) * rate).
# -p               : Set the local port number.
# -s               : Set the username part of the resquest URI. Default is
#                       'service'.
# -sf              : Loads an alternate xml scenario file.  To learn more
#                       about XML scenario syntax, use the -sd option to dump
#                       embedded scenarios. They contain all the necessary help.
# -inf             : Inject values from an external CSV file during calls into
#                      the scenarios.
#                      First line of this file say whether the data is to be
#                      read in sequence (SEQUENTIAL), random (RANDOM), or user
#                      (USER) order.
#                      Each line corresponds to one call and has one or more
#                      ';' delimited data fields. Those fields can be referred
#                      as [field0], [field1], ... in the xml scenario file.
#                      Several CSV files can be used simultaneously (syntax:
#                      -inf f1.csv -inf f2.csv ...)
#-nd              : No Default. Disable all default behavior of SIPp which
#                      are the following:
#                      - On UDP retransmission timeout, abort the call by
#                        sending a BYE or a CANCEL
#                      - On receive timeout with no ontimeout attribute, abort
#                        the call by sending a BYE or a CANCEL
#                      - On unexpected BYE send a 200 OK and close the call
#                      - On unexpected CANCEL send a 200 OK and close the call
#                      - On unexpected PING send a 200 OK and continue the call
#                      - On any other unexpected message, abort the call by
#                        sending a BYE or a CANCEL
#
#-rp              : Specify the rate period for the call rate.  Default is 1
#                      second and default unit is milliseconds.  This allows
#                      you to have n calls every m milliseconds (by using -r n
#                      -rp m).
#                      Example: -r 7 -rp 2000 ==> 7 calls every 2 seconds.
#                               -r 10 -rp 5s => 10 calls every 5 seconds.
# -aa              : Enable automatic 200 OK answer for INFO, UPDATE and NOTIFY messages.
#
#




ulimit -n 65533
# These should be set in the environment
LOGDIR=./
REMOTEHOST=172.29.31.14
LOCALIP=172.20.2.35

pidfile="$RUNDIR/sipp.pid"
logfiles="-ringbuffer_files 1000 -ringbuffer_size 50000000 -trace_msg -trace_logs -trace_err -message_file $LOGDIR/sipp_message.log  -message_overwrite false -error_file $LOGDIR/sipp_error.log -error_overwrite false -calldebug_file $LOGDIR/sipp_debug.log -calldebug_overwrite false -log_file $LOGDIR/sipp.log -log_overwrite false "

remotehost=$REMOTEHOST
username=demo
srchost=$LOCALIP
srcport=5060

if [ $# -eq 1 ] && [ $1 = "stop" ]
then
/bin/cat $pidfile | xargs kill -9
exit
fi

#
# Execute with custom script
#
sipp  -plugin libmyapp.so -lua_file sipp_demo.lua -pid_file $pidfile -aa  $logfiles -m 1000000 -l 1 -i $srchost -p $srcport -s $username -nd -sf ./uas_w_script.xml $remotehost 
