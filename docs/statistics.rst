Statistics
==========


Response times
``````````````

Response times can be gathered and reported. Response time names can
be arbitrary strings, but for backwards compatibility the value ``"true"``
is treated as if it were named ``"1"``. Each response time can be used to
compute time between two SIPp commands (``send``, ``recv`` or ``nop``). You can
start a timer by using the ``start_rtd`` attribute and stop it using the
``rtd`` attribute.

You can view the value of those timers in the SIPp interface by
pressing 3, 6, 7, 8 or 9. You can also save the values in a CSV file
using the ``-trace_stat`` option (see below).

If the ``-trace_rtt`` option is set, the response times are also dumped
in a file called ``<scenario name>_<pid>_rtt.csv``. There, each
line represents a RTD measure (triggered by a message reception with a
``rtd="n"`` attribute). The dump frequency can be tuned using the
``-rtt_freq`` parameter.


Available counters
``````````````````

The ``-trace_stat`` option dumps all statistics in the
``<scenario name>_<pid>.csv`` file. The dump starts with one header line with
all counters. All following lines are "snapshots" of statistics
counters given the statistics report frequency (``-fd`` option). When SIPp
exits, the last values of the statistics are also dumped in this file.

This file can be easily imported in any spreadsheet application, like
Excel.

In counter names, (P) means 'Periodic' - since last statistic row and
(C) means 'Cumulated' - since sipp was started.

Available statistics are:


+ StartTime: Date and time when the test has started.
+ LastResetTime: Date and time when periodic counters where last
  reseted.
+ CurrentTime: Date and time of the statistic row.
+ ElapsedTime: Elapsed time.
+ CallRate: Call rate (calls per seconds).
+ IncomingCall: Number of incoming calls.
+ OutgoingCall: Number of outgoing calls.
+ TotalCallCreated: Number of calls created.
+ CurrentCall: Number of calls currently ongoing.
+ SuccessfulCall: Number of successful calls.
+ FailedCall: Number of failed calls (all reasons).
+ FailedCannotSendMessage: Number of failed calls because Sipp cannot
  send the message (transport issue).
+ FailedMaxUDPRetrans: Number of failed calls because the maximum
  number of UDP retransmission attempts has been reached.
+ FailedUnexpectedMessage: Number of failed calls because the SIP
  message received is not expected in the scenario.
+ FailedCallRejected: Number of failed calls because of Sipp internal
  error. (a scenario sync command is not recognized or a scenario action
  failed or a scenario variable assignment failed).
+ FailedCmdNotSent: Number of failed calls because of inter-Sipp
  communication error (a scenario sync command failed to be sent).
+ FailedRegexpDoesntMatch: Number of failed calls because of regexp
  that doesn't match (there might be several regexp that don't match
  during the call but the counter is increased only by one).
+ FailedRegexpShouldntMatch: Number of failed calls because of regexp
  that shouldn't match (there might be several regexp that shouldn't
  match during the call but the counter is increased only by one).
+ FailedRegexpHdrNotFound: Number of failed calls because of regexp
  with hdr option but no matching header found.
+ FailedOutboundCongestion: Number of failed outgoing calls because of
  TCP congestion.
+ FailedTimeoutOnRecv: Number of failed calls because of a recv
  timeout statement.
+ FailedTimeoutOnSend: Number of failed calls because of a send
  timeout statement.
+ OutOfCallMsgs: Number of SIP messages received that cannot be
  associated with an existing call.
+ Retransmissions: Number of SIP messages being retransmitted.
+ AutoAnswered: Number of unexpected specific messages received for
  new Call-ID. The message has been automatically answered by a 200 OK
  Currently, implemented for 'PING' message only.


The counters defined in the scenario are also dumped in the stat file.
Counters that have a numeric name are identified by the GenericCounter
columns.

In addition, two other statistics are gathered:


+ ResponseTime (see previous section)
+ CallLength: this is the time of the duration of an entire call.


Both ResponseTime and CallLength statistics can be tuned using
ResponseTimeRepartition and CallLengthRepartition commands in the
scenario.

The standard deviation (STDev) is also available in the log stat file
for these two statistics.


Detailed Message Counts
```````````````````````

The SIPp screens provide detailed information about the number of
messages sent or recieved, retransmissions, messages lost, and the
number of unexpected messages for each scenario element. Although
these screens can be parsed, it is much simpler to parse a CSV file.
To produce a CSV file that contains the per-message information
contained in the main display screen pass the ``-trace_counts`` option.
Each column of the file represents a message and a particular count of
interest (e.g., ``1_INVITE_Sent`` or ``2_100_Unexp``). Each row
corresponds to those statistics at a given statistics reporting
interval.
