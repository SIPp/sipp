Error handling
==============

SIPp has advanced feature to handle errors and unexpected events. They
are detailed in the following sections.


Unexpected messages
```````````````````


+ When a SIP message that can be correlated to an existing call (with
  the Call-ID: header) but is not expected in the scenario is received,
  SIPp will send a CANCEL message if no 200 OK message has been received
  or a BYE message if a 200 OK message has been received. The call will
  be marked as failed. If the unexpected message is a 4XX or 5XX, SIPp
  will send an ACK to this message, close the call and mark the call as
  failed.
+ When a SIP message that can't be correlated to an existing call
  (with the Call-ID: header) is received, SIPp will send a BYE message.
  The call will not be counted at all.
+ When a SIP "PING" message is received, SIPp will send an ACK message
  in response. This message is not counted as being an unexpected
  message. But it is counted in the "AutoAnswered" statistic counter.
+ An unexpected message that is not a SIP message will be simply
  dropped.



Retransmissions (UDP only)
``````````````````````````

A retransmission mechanism exists in UDP transport mode. To activate
the retransmission mechanism, the "send" command must include the
"retrans" attribute.

When it is activated and a SIP message is sent and no ACK or response
is received in answer to this message, the message is re-sent.

.. note::
  The retransmission mechanism follows :RFC:`3261`, section 17.1.1.2.
  Retransmissions are differentiated between INVITE and non-INVITE
  methods.

<send retrans="500">: will initiate the T1 timer to 500 milliseconds.

Even if retrans is specified in your scenarios, you can override this
by using the -nr command line option to globally disable the
retransmission mechanism.


Log files
`````````

There are several ways to trace what is going on during your SIPp
runs.


+ You can log sent and received SIP messages in
  <name_of_the_scenario>_<pid>_messages.log by using the command line
  parameter -trace_msg. The messages are time-stamped so that you can
  track them back.
+ You also can trace it using the -trace_shortmsg parameter. This logs
  the most important values of a message as CSV into one line of the
  <scenario file name>_<pid>_shortmessages.log
+ You can trace all unexpected messages or events in
  <name_of_the_scenario>_<pid>_errors.log by using the command line
  parameter -trace_err.
+ You can trace the SIP response codes of unexpected messages in
  <name_of_the_scenario>_<pid>_error_codes.log by using the command line
  parameter -trace_error_codes.
+ You can trace the counts from the main scenario screen in
  <name_of_the_scenario>_<pid>_counts.csv by using the command line
  parameter -trace_counts.
+ You can trace the messages and state transitions of failed calls in
  <name_of_the_scenario>_<pid>_calldebug.log using the -trace_calldebug
  command line parameter. This is useful, because it has less overhead
  than -trace_msg yet allows you to debug call flows that were not
  completed successfully.
+ You can save in a file the statistics screens, as displayed in the
  interface. This is especially useful when running SIPp in background
  mode. This can be done in different ways:

    + When SIPp exits to get a final status report (-trace_screen option)
    + On demand by using USR2 signal (example: kill -SIGUSR2 738)
    + By pressing 's' key (if -trace_screen option is set)
    + If the -trace_logs option is set, you can use the <log> action to
      print some scenario traces in the <scenario file name>_<pid>_logs.log
      file. See the Log action section



SIPp can treat the messages, short messages, logs, and error logs as
ring buffers. This allows you to limit the total amount of space used
by these log files and keep only the most recent messages. To set the
maximum file size use the -ringbuffer_size option. Once the file
exceeds this size (the file size can be exceeded up to the size of a
single log message), it is rotated. SIPp can keep several of the most
recent files, to specify the number of files to keep use the
-ringbuffer_files option. The rotated files have a name of the form
<name_of_the_scenario>_<pid>_<logname>_<date>.log, where <date> is the
number of seconds since the epoch. If more than one log file is
rotated during a one second period, then the date is expressed as
<seconds.serial>, where serial is an increasing integer identifier.
