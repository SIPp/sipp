Performance testing with SIPp
=============================



Advice to run performance tests with SIPp
`````````````````````````````````````````

SIPp has been originally designed for SIP performance testing.
Reaching high call rates and/or high number of simultaneous SIP calls
is possible with SIPp, provided that you follow some guidelines:


+ Use a Linux system to reach high performances. The Windows port of
  SIPp (through CYGWIN) cannot handle high performances.
+ Limit the traces to a minimum (usage of ``-trace_msg``, ``-trace_logs``
  should be limited to scenario debugging only)
+ Understand internal SIPp's scheduling mechanism and use the
  ``-timer_resol``, ``-max_recv_loops`` and ``-max_sched_loops`` command line
  parameters to tune SIPp given the system it is running on.


Generally, running performance tests also implies measuring response
times. You can use SIPp's timers (start_rtd, rtd in scenarios and
-trace_rtt command line option) to measure those response times. The
precision of those measures are entirely dependent on the timer_resol
parameter (as described in `SIPp's internal scheduling`_ section). You
might want to use another "objective" method if you want to measure
those response times with a high precision (a tool like Wireshark
will allow you to do so).



SIPp's internal scheduling
``````````````````````````

SIPp has a single-threaded event-loop architecture, which allows it to
handle high SIP traffic loads. SIPp's event loop tracks various tasks,
most of which are the calls that are defined in your scenario. In
addition to tasks that represent calls there are several special
tasks: a screen update task, a statistics update task, a call opening
task, and a watchdog task. SIPp's main execution loop consists of:


#. Waking up tasks that have expired timers.
#. Running up to max_sched_loop tasks that are in a running state
   (each call is executed until it is no longer runnable).
#. Handling each of the sockets in turn, reading max_recv_loops
   messages from the various sockets.


SIPp executes this loop continuously, until some condition tells it to
stop (e.g., the user pressing the 'q' key or the global call limit or
timeout being reached).

Several parameters can be specified on the command line to fine tune
this scheduling.


+ timer_resol: during the main loop, the management of calls
  (management of wait, retransmission ...) is done for all calls, every
  "timer_resol" ms at best. The delay of retransmission must be higher
  than "timer_resol". The default timer resolution is 1 millisecond, and
  that is the most precise resolution that SIPp currently supports. If
  you increase this parameter, SIPp's traffic will be burstier and you
  are likely to encounter retransmissions at high load. If you have too
  many calls, or each call takes too long, the timer resolution will not
  be respected.
+ max_recv_loops and max_sched_loops: received messages are read and
  treated in batch. "max_recv_loops" is the maximum number of messages
  that can be read at one time. "max sched loops" is the maximum number
  of processing calls loops. These limits prevent SIPp from reading and
  processing new messages from sockets to the exclusion of processing
  existing calls, and vice versa. For heavy call rate, increase both
  values. Be careful, those two parameters have a large influence on the
  CPU occupation of SIPp.
+ watchdog_interval, watchdog_minor_threshold,
  watchdog_major_threshold, watchdog_minor_maxtriggers, and
  watchdog_major_maxtriggers: The watchdog timer is designed to provide
  feedback if your call load is causing SIPp's scheduler to be
  overwhelmed. The watchdog task sets a timer that should fire every
  watchdog_interval milliseconds (by defualt 400ms). If the timer is not
  serviced for more than watchdog_minor_threshold milliseconds (by
  default 500s), then a "minor" trigger is recorded. If the number of
  minor triggers is more than watchdog_minor_maxtriggers; the watchdog
  task terminates SIPp. Similarly, if the timer is not serviced for more
  than watchdog_major_threshold milliseconds (by default 3000ms), then a
  major trigger is recorded; and if more than watchdog_major_maxtriggers
  are recorded SIPp is terminated. If you only see occasional messages,
  your test is likely acceptable, but if these events are frequent you
  need to consider using a more powerful machine or set of machines to
  run your scenario.