Controlling SIPp
================

SIPp can be controlled interactively through the keyboard or via a UDP
socket. SIPp supports both 'hot' keys that can be entered at any time
and also a simple command mode. The hot keys are:


=====  ======
 Key   Action
=====  ======
\+     Increase the call rate by 1 * rate_scale
\*     Increase the call rate by 10 * rate_scale
\-     Decrease the call rate by 1 * rate_scale
/      Decrease the call rate by 10 * rate_scale
c      Enter command mode
q      Quit SIPp (after all calls complete, enter a second time to quit immediately)
Q      Quit SIPp immediately s Dump screens to the log file (if -trace_screen is passed)
p      Pause traffic
1      Display the scenario screen
2      Display the statistics screen
3      Display the repartition screen
4      Display the variable screen
5      Display the TDM screen
6-9    Display the second through fifth repartition screen.
=====  ======

In command mode, you can type a single line command that instructs
SIPp to take some action. Command mode is more versatile than the hot
keys, but takes more time to input some common actions. The following
commands are available:



List of Interactive Commands
````````````````````````````

- ``dump tasks`` Prints a list of active tasks (most tasks are calls) to the error log. dump tasks
- ``set rate X`` Sets the call rate. set rate 10
- ``set rate-scale X`` Sets the rate scale, which adjusts the speed of '+', '-', '*', and '/'. set rate-scale 10
- ``set users X`` Sets the number of users (only valid when -users is specified). set rate 10
- ``set limit X`` Sets the open call limit (equivalent to -l option) set limit 100
- ``set hide <true|false>`` Should the hide XML attribute be respected? set hide false
- ``set display <main|ooc>`` Changes the scenario that is displayed to either the main or the out-of-call scenario. set display main set display ooc
- ``trace <log> <on|off>`` Turns log on or off at run time. Valid values for log are "error", "logs", "messages", and "shortmessages". trace error on


Traffic control
```````````````

SIPp generates SIP traffic according to the scenario specified. You
can control the number of calls (scenario) that are started per
second. If you pass the -users option, then you need to control the
number of instantiated users. You can control the rate through:


+ Interactive hot keys (described in the previous section)
+ Interactive Commands
+ Startup Parameters


There are two commands that control rates: set rate X sets the current
call rate to X. Additionally, set rate-scale X sets the rate_scale
parameter to X. This enables you to use the '+', '-', '*', and '/'
keys to set the rate more quickly. For example, if you do set rate-
scale 100, then each time you press '+', the call rate is increased by
100 calls and each time you press '*', the call rate is increased by
1000 calls. Similarly, for a user based benchmark you can run set
users X.

At starting time, you can control the rate by specifying parameters on
the command line:

+ "-r" to specify the call rate in number of calls per seconds
+ "-rp" to specify the " r ate p eriod" in milliseconds for the call
  rate (default is 1000ms/1sec). This allows you to have n calls every m
  milliseconds (by using -r n -rp m).

.. note:: Example: run SIPp at 7 calls every 2 seconds (3.5 calls per second)

::

    ./sipp -sn uac -r 7 -rp 2000 127.0.0.1





You can also pause the traffic by pressing the 'p' key. SIPp will stop
placing new calls and wait until all current calls go to their end.
You can resume the traffic by pressing 'p' again.

To quit SIPp, press the 'q' key. SIPp will stop placing new calls and
wait until all current calls go to their end. SIPp will then exit.

You can also force SIPp to quit immediatly by pressing the 'Q' key.
Current calls will be terminated by sending a BYE or CANCEL message
(depending if the calls have been established or not). The same
behaviour is obtained by pressing 'q' twice.

.. tip::
  You can place a defined number of calls and have SIPp exit when
  this is done. Use the -m option on the command line.


Remote control
``````````````

SIPp can be "remote-controlled" through a UDP socket. This allows for
example


+ To automate a series of actions, like increasing the call rate
  smoothly, wait for 10 seconds, increase more, wait for 1 minute and
  loop
+ Have a feedback loop so that an application under test can remote
  control SIPp to lower the load, pause the traffic, ...


Each SIPp instance is listening to a UDP socket. It starts to listen
to port 8888 and each following SIPp instance (up to 60) will listen
to base_port + 1 (8889, 8890, ...).

It is then possible to control SIPp like this:

::

    echo p >/dev/udp/x.y.z.t/8888 -> put SIPp in pause state (p key)
    echo q >/dev/udp/x.y.z.t/8888 -> quit SIPp (q key)


.. note::
  All keys available through keyboard are also available in the remote
  control interface

You could also have a small shell script to automate a serie of
action. For example, this script will increase the call rate by 10
more new calls/s every 5 seconds, wait at this call rate for one
minute and exit SIPp:

::

    #!/bin/sh
    echo "*" >/dev/udp/127.0.0.1/8889
    sleep 5
    echo "*" >/dev/udp/127.0.0.1/8889
    sleep 5
    echo "*" >/dev/udp/127.0.0.1/8889
    sleep 5
    echo "*" >/dev/udp/127.0.0.1/8889
    sleep 60
    echo "q" >/dev/udp/127.0.0.1/8889


To send a command to SIPp, preface it with 'c'. For example: ``echo
"cset rate 100" >/dev/udp/127.0.0.1/8888 sets the call rate to 100.``
