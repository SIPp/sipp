Create your own XML scenarios
=============================

Of course embedded scenarios will not be enough. So it's time to
create your own scenarios. A SIPp scenario is written in XML (a DTD
that may help you write SIPp scenarios does exist and has been tested
with jEdit - this is described in a later section). A scenario will
always start with:

::

    <?xml version="1.0" encoding="ISO-8859-1" ?>
    <scenario name="Basic Sipstone UAC">


And end with:

::

    </scenario>


Easy, huh? Ok, now let's see what can be put inside. You are not
obliged to read the whole table now! Just go in the next section for
an example.

There are many common attributes used for flow control and statistics,
that can be used for all of the message commands (i.e., <send> ,
<recv> , <nop> , <pause> , <sendCmd> , and <recvCmd> ).



List of attributes common to all commands
`````````````````````````````````````````
Attribute(s) Description Example start_rtd Starts one of the " R
esponse T ime D uration" timer. (see statistics section). <send
start_rtd="invite">: the timer named "invite" will start when the
message is sent. rtd Stops one of the 5 " R esponse T ime D uration"
timer. <send rtd="2">: the timer number 2 will stop when the message
is sent. repeat_rtd Used with a rtd attribute, it allows the
corresponding " R esponse T ime D uration" timer to be counted more
than once per call (useful for loop call flows). <send rtd="1"
repeat_rtd="true">: the timer number 1 value will be printed but the
timer won't stop. crlf Displays an empty line after the arrow for the
message in main SIPp screen. <send crlf="true"> next You can put a
"next" in any command element to go to another part of the script when
you are done with sending the message. For optional receives, the next
is only taken if that message was received. See conditional branching
section for more info.
Example to jump to label "12" after sending an ACK:

::

      <send next="12">
        <![CDATA[
    
          ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: ...
          From: ...
          To: ...
          Call-ID: ...
          Cseq: ...
          Contact: ...
          Max-Forwards: ...
          Subject: ...
          Content-Length: 0
    
        ]]>
      </send>


Example to jump to label "5" when receiving a 403 message:

::

      <recv response="100"
            optional="true">
      </recv>
      <recv response="180" optional="true">
      </recv>
      <recv response="403" optional="true" next="5">
      </recv>
      <recv response="200">
      </recv>

test You can put a "test" next to a "next" attribute to indicate that
you only want to branch to the label specified with "next" if the
variable specified in "test" is set (through regexp for example). See
conditional branching section for more info. Example to jump to label
"6" after sending an ACK only if variable 4 is set:

::

      <send next="6" test="4">
        <![CDATA[
    
          ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: ...
          From: ...
          To: ...
          Call-ID: ...
          Cseq: ...
          Contact: ...
          Max-Forwards: ...
          Subject: ...
          Content-Length: 0
    
        ]]>
      </send>

chance In combination with "test", probability to actually branch to
another part of the scenario. Chance can have a value between 0
(never) and 1 (always). See conditional branching section for more
info.

::

      <recv response="403" optional="true" next="5" test="3" chance="0.90">
      </recv>

90% chance to go to label "5" if variable "3" is set. condexec
Executes an element only if the variable in the condexec attribute is
set. This attribute allows you to write complex XML scenarios with
fewer next attributes and labels. <nop condexec="executethis">
condexec_inverse If condexec is set, condexec_inverse inverts the
condition in condexec. This allows you to execute an element only when
a variable is **not** set. <nop condexec="skipthis"
condexec_inverse="true"> counter Increments the counter given as
parameter when the message is sent. The counters are saved in the
statistic file. <send counter="MsgA">: Increments counter "MsgA" when
the message is sent.
Each command also has its own unique attributes, listed here:



List of commands with their attributes
``````````````````````````````````````
Command Attribute(s) Description Example <send> retrans Used for UDP
transport only: it specifies the T1 timer value, as described in SIP
RFC 3261, section 17.1.1.2. <send retrans="500">: will initiate T1
timer to 500 milliseconds (RFC3261 default). lost Emulate packet lost.
The value is specified as a percentage. <send lost="10">: 10% of the
message sent are actually not sent :). start_txn Records the branch ID
of this sent message so that responses can be properly matched
(without this element the transaction matching is done based on the
CSeq method, which is imprecise). <send start_txn="invite">: Stores
the branch ID of this message in the transaction named "invite".
ack_txn Indicates that the ACK being sent corresponds to the
transaction started by a start_txn attribute. Every INVITE with a
start_txn tag must have a matching ACK with an ack_txn attribute.
<send ack_txn="invite">: References the branch ID of the transaction
named "invite". <recv> response Indicates what SIP message code is
expected. <recv response="200">: SIPp will expect a SIP message with
code "200". request Indicates what SIP message request is expected.
<recv request="ACK">: SIPp will expect an "ACK" SIP message. optional
Indicates if the message to receive is optional. In case of an
optional message and if the message is actually received, it is not
seen as a unexpected message. When an unexpected message is received,
Sipp looks if this message matches an optional message defined in the
previous step of the scenario.
If optional is set to "global", Sipp will look every previous steps of
the scenario. <recv response="100" optional="true">: The 100 SIP
message can be received without being considered as "unexpected". rrs
R ecord R oute S et. if this attribute is set to "true", then the
"Record-Route:" header of the message received is stored and can be
recalled using the [routes] keyword. <recv response="100" rrs="true">.
auth Authentication. if this attribute is set to "true", then the
"Proxy-Authenticate:" header of the message received is stored and is
used to build the [authentication] keyword. <recv response="407"
auth="true">. lost Emulate packet lost. The value is specified as a
percentage. <recv lost="10">: 10% of the message received are thrown
away. timeout Specify a timeout while waiting for a message. If the
message is not received, the call is aborted, unless an ontimeout
label is defined. <recv timeout="100000"> ontimeout Specify a label to
jump to if the timeout popped before the message to be received.
Example to jump to label "5" when not receiving a 100 message after
100 seconds:

::

      <recv response="100" timeout="100000" ontimeout="5">
      </recv>

action Specify an action when receiving the message. See Actions
section for possible actions. Example of a "regular expression"
action:

::

    <recv response="200">
     <action>
      <ereg regexp="([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]*"
        search_in="msg"
        check_it="true"
        assign_to="1,2"/>
      </action>
     </recv>

regexp_match Boolean. Indicates if 'request' ('response' is not
available) is given as a regular expression. If so, the recv command
will match against the regular expression. This allows to catch
several cases in the same receive command. Example of a recv command
that matches MESSAGE or PUBLISH or SUBSCRIBE requests:


::

    <recv request="MESSAGE|PUBLISH|SUBSCRIBE" crlf="true" regexp_match="true">
    </recv>

response_txn Indicates that this is a response to a transaction that
was previously started. To match, the branch ID of the first via
header must match the stored transaction ID. <recv response="200"
response_txn="invite" />: Matches only responses to the message sent
with start_txn="invite" attribute. <pause> milliseconds Specify the
pause delay, in milliseconds. When this delay is not set, the value of
the -d command line parameter is used. <pause milliseconds="5000"/>:
pause the scenario for 5 seconds. variable Indicates which call
variable to use to determine the length of the pause. <pause
variable="1" /> pauses for the number of milliseconds specified by
call variable 1. distribution Indicates which statistical distribution
to use to determine the length of the pause. Without GSL, you may use
uniform or fixed. With GSL, normal, exponential, gamma, lambda,
lognormal, negbin, (negative binomial), pareto, and weibull are
available. Depending on the distribution you select, you must also
supply distribution specific parameters. The following examples show
the various types of distributed pauses:

+ <pause distribution="fixed" value="1000" /> pauses for 1 second.
+ <pause distribution="uniform" min="2000" max="5000"/> pauses between
  2 and 5 seconds.

The remaining distributions require GSL. In general The parameter
names were chosen to be as consistent with Wikipedia's distribution
description pages.

+ <pause distribution="normal" mean="60000" stdev="15000"/> provides a
  normal pause with a mean of 60 seconds (i.e. 60,000 ms) and a standard
  deviation of 15 seconds. The mean and standard deviation are specified
  as integer milliseconds. The distribution will look like:
+ <pause distribution="lognormal" mean="12.28" stdev="1" /> creates a
  distribution's whose natural logarithm has a mean of 12.28 and a
  standard deviation of 1. The mean and standard deviation are specified
  as double values (in milliseconds). The distribution will look like:
+ <pause distribution="exponential" mean="900000"/> creates an
  exponentially distributed pause with a mean of 15 minutes. The
  distribution will look like:
+ <pause distribution="weibull" lambda="3" k ="4"/> creates a Weibull
  distribution with a scale of 3 and a shape of 4 (see `Weibull on
  Wikipedia`_ for a description of the distribution).
+ <pause distribution="pareto" k="1" x_m="2"/> creates a Pareto
  distribution with k and x m of 1 and 2, respectively (see `Pareto on
  Wikipedia`_ for a description of the distribution).
+ <pause distribution="gamma" k="3" theta="2"/> creates a Gamma
  distribution with k and theta of 9 and 2, respectively (see `Gamma on
  Wikipedia`_ for a description of the distribution).
+ <pause distribution="negbin" p="0.1" n="2"/> creates a Negative
  binomial distribution with p and n of 0.1 and 2, respectively (see
  `Negative Binomial on Wikipedia`_ for a description of the
  distribution).

sanity_check By default, statistically distributed pauses are sanity
checked to ensure that their 99th percentile values are less than
INT_MAX. Setting sanity_check to false disables this behavior. <pause
distribution="lognormal" mean="10" stdev="10" sanity_check="false"/>
disables sanity checking of the lognormal distribution. <nop> action
The nop command doesn't do anything at SIP level. It is only there to
specify an action to execute. See Actions section for possible
actions. Execute the play_pcap_audio/video action:

::

    <nop>
      <action>
        <exec play_pcap_audio="pcap/g711a.pcap"/>
      </action>
    </nop>

<sendCmd> <![CDATA[]]> Content to be sent to the twin 3PCC SIPp
instance. The Call-ID must be included in the CDATA. In 3pcc extended
mode, the From must be included to.

::

    <sendCmd>
      <![CDATA[
        Call-ID: [call_id]
        [$1]
    
       ]]>
    </sendCmd>

dest 3pcc extended mode only: the twin sipp instance which the command
will be sent to <sendCmd dest="s1">: the command will be sent to the
"s1" twin instance <recvCmd> action Specify an action when receiving
the command. See Actions section for possible actions. Example of a
"regular expression" to retrieve what has been send by a sendCmd
command:

::

    <recvCmd>
      <action
         <ereg regexp="Content-Type:.*"
               search_in="msg"
               assign_to="2"/>
      </action>
    </recvCmd>

src 3pcc extended mode only: indicate the twin sipp instance which the
command is expected to be received from <recvCmd src = "s1">: the
command will be expected to be received from the "s1" twin instance
<label> id A label is used when you want to branch to specific parts
in your scenarios. The "id" attribute is an integer where the maximum
value is 19. See conditional branching section for more info. Example:
set label number 13:

::

    <label id="13"/>

<Response Time Repartition> value Specify the intervals, in
milliseconds, used to distribute the values of response times.
<ResponseTimeRepartition value="10, 20, 30"/>: response time values
are distributed between 0 and 10ms, 10 and 20ms, 20 and 30ms, 30 and
beyond. <Call Length Repartition> value Specify the intervals, in
milliseconds, used to distribute the values of the call length
measures. <CallLengthRepartition value="10, 20, 30"/>: call length
values are distributed between 0 and 10ms, 10 and 20ms, 20 and 30ms,
30 and beyond. <Globals> variables Specify the name of globally scoped
variables. <Globals variables="foo,bar" />. <User> variables Specify
the name of user-scoped variables. <User variables="foo,bar" />.
<Reference> variables Suppresses warnings about unused variables.
<Reference variables="dummy" />
There are not so many commands: send, recv, sendCmd, recvCmd, pause,
ResponseTimeRepartition, CallLengthRepartition, Globals, User, and
Reference. To make things even clearer, nothing is better than an
example...


Structure of client (UAC like) XML scenarios
````````````````````````````````````````````

A client scenario is a scenario that starts with a "send" command. So
let's start:

::

    <scenario name="Basic Sipstone UAC">
      <send>
        <![CDATA[
    
          INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port]
          From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
          To: sut <sip:[service]@[remote_ip]:[remote_port]>
          Call-ID: [call_id]
          Cseq: 1 INVITE
          Contact: sip:sipp@[local_ip]:[local_port]
          Max-Forwards: 70
          Subject: Performance Test
          Content-Type: application/sdp
          Content-Length: [len]
    
          v=0
          o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
          s=-
          t=0 0
          c=IN IP[media_ip_type] [media_ip]
          m=audio [media_port] RTP/AVP 0
          a=rtpmap:0 PCMU/8000
    
    
        ]]>
      </send>


Inside the "send" command, you have to enclose your SIP message
between the "<![CDATA" and the "]]>" tags. Everything between those
tags is going to be sent toward the remote system. You may have
noticed that there are strange keywords in the SIP message, like
[service], [remote_ip], ... . Those keywords are used to indicate to
SIPp that it has to do something with it.

Here is the list:



Keyword list
````````````
Keyword Default Description 
[service] service Service field, as passed
in the -s service_name 
[remote_ip] - Remote IP address, as passed on
the command line. [remote_port] 5060 Remote IP port, as passed on the
command line. You can add a computed offset [remote_port+3] to this
value. [transport] UDP Depending on the value of -t parameter, this
will take the values "UDP" or "TCP". [local_ip] Primary host IP
address Will take the value of -i parameter. [local_ip_type] -
Depending on the address type of -i parameter (IPv4 or IPv6),
local_ip_type will have value "4" for IPv4 and "6" for IPv6.
[local_port] Chosen by the system Will take the value of -p parameter.
You can add a computed offset [local_port+3] to this value. [len] -
Computed length of the SIP body. To be used in "Content-Length"
header. You can add a computed offset [len+3] to this value.
[call_number] - Index. The call_number starts from "1" and is
incremented by 1 for each call. [cseq] - Generates automatically the
CSeq number. The initial value is 1 by default. It can be changed by
using the -base_cseq command line option. [call_id] - A call_id
identifies a call and is generated by SIPp for each new call. In
client mode, it is mandatory to use the value generated by SIPp in the
"Call-ID" header. Otherwise, SIPp will not recognise the answer to the
message sent as being part of an existing call.
Note: [call_id] can be pre-pended with an arbitrary string using
'///'. Example: Call-ID: ABCDEFGHIJ///[call_id] - it will still be
recognized by SIPp as part of the same call. [media_ip] - Depending on
the value of -mi parameter, it is the local IP address for RTP echo.
[media_ip_type] - Depending on the address type of -mi parameter (IPv4
or IPv6), media_ip_type will have value "4" for IPv4 and "6" for IPv6.
Useful to build the SDP independently of the media IP type.
[media_port] - Depending on the value of -mp parameter, it set the
local RTP echo port number. Default is none. RTP/UDP packets received
on that port are echoed to their sender. You can add a computed offset
[media_port+3] to this value. [auto_media_port] - Only for pcap. To
make audio and video ports begin from the value of -mp parameter, and
change for each call using a periodical system, modulo 10000 (which
limits to 10000 concurrent RTP sessions for pcap_play) [last_*] - The
'[last_*]' keyword is replaced automatically by the specified header
if it was present in the last message received (except if it was a
retransmission). If the header was not present or if no message has
been received, the '[last_*]' keyword is discarded, and all bytes
until the end of the line are also discarded. If the specified header
was present several times in the message, all occurences are
concatenated (CRLF separated) to be used in place of the '[last_*]'
keyword. [field0-n file=<filename> line=<number>] - Used to inject
values from an external CSV file. See "Injecting values from an
external CSV during calls" section. The optional file and line
parameters allow you to select which of the injection files specified
on the command line to use and which line number from that file. [file
name=<filename>] - Inserts the entire contents of filename into the
message. Whitespace, including carriage returns and newlines at the
end of the line in the file are not processed as with other keywords;
thus your file must be formatted exactly as you would like the bytes
to appear in the message. [timestamp] - The current time using the
same format as error log messages. [last_message] - The last received
message. [$n] - Used to inject the value of call variable number n.
See "Actions" section [authentication] - Used to put the
authentication header. This field can have parameters, in the
following form: [authentication username=myusername
password=mypassword]. If no username is provided, the value from the
-au (authentication username) or -s (service) command line parameter
is used. If no password is provided, the value from -ap command line
parameter is used. See "Authentication" section [pid] - Provide the
process ID (pid) of the main SIPp thread. [routes] - If the "rrs"
attribute in a recv command is set to "true", then the "Record-Route:"
header of the message received is stored and can be recalled using the
[routes] keyword [next_url] - If the "rrs" attribute in a recv command
is set to "true", then the [next_url] contains the contents of the
Contact header (i.e within the '<' and '>' of Contact) [branch] -
Provide a branch value which is a concatenation of magic cookie
(z9hG4bK) + call number + message index in scenario.
An offset (like [branch-N]) can be appended if you need to have the
same branch value as a previous message. [msg_index] - Provide the
message number in the scenario. [cseq] - Provides the CSeq value of
the last request received. This value can be incremented (e.g.
[cseq+1] adds 1 to the CSeq value of the last request). [clock_tick] -
Includes the internal SIPp clock tick value in the message.
[sipp_version] - Includes the SIPp version string in the message.
[tdmmap] - Includes the tdm map values used by the call in the message
(see -tdmmap option). [fill] - Injects filler characters into the
message. The length of the fill text is equal to the call variable
stored in the variable=N parameter. By default the text is a sequence
of X's, but can be controlled with the text="text" parameter. [users]
- If the -users command line option is specified, then this keyword
contains the number of users that are currently instantiated. [userid]
- If the -users command line option is specified, then this keyword
containst he integer identifier of the current user (starting at zero
and ending at [users-1]).
Now that the INVITE message is sent, SIPp can wait for an answer by
using the "recv" command.

::

      <recv response="100"> optional="true"
      </recv>
    
      <recv response="180"> optional="true"
      </recv>
    
      <recv response="200">
      </recv>


100 and 180 messages are optional, and 200 is mandatory. In a "recv"
sequence, there must be one mandatory message .

Now, let's send the ACK:

::

      <send>
        <![CDATA[
    
          ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port]
          From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
          To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
          Call-ID: [call_id]
          Cseq: 1 ACK
          Contact: sip:sipp@[local_ip]:[local_port]
          Max-Forwards: 70
          Subject: Performance Test
          Content-Length: 0
    
        ]]>
      </send>


We can also insert a pause. The scenario will wait for 5 seconds at
this point.

::

      <pause milliseconds="5000"/>


And finish the call by sending a BYE and expecting the 200 OK:

::

        <send retrans="500">
         <![CDATA[
    
          BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port]
          From: sipp  <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
          To: sut  <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
          Call-ID: [call_id]
          Cseq: 2 BYE
          Contact: sip:sipp@[local_ip]:[local_port]
          Max-Forwards: 70
          Subject: Performance Test
          Content-Length: 0
    
        ]]>
       </send>
    
       <recv response="200">
       </recv>


And this is the end of the scenario:

::

    </scenario>


Creating your own SIPp scenarios is not a big deal. If you want to see
other examples, use the -sd parameter on the command line to display
embedded scenarios.


Structure of server (UAS like) XML scenarios
````````````````````````````````````````````

A server scenario is a scenario that starts with a "recv" command. The
syntax and the list of available commands is the same as for "client"
scenarios.

But you are more likely to use [last_*] keywords in those server side
scenarios. For example, a UAS example will look like:

::

      <recv request="INVITE">
      </recv>
    
      <send>
        <![CDATA[
    
          SIP/2.0 180 Ringing
          [last_Via:]
          [last_From:]
          [last_To:];tag=[call_number]
          [last_Call-ID:]
          [last_CSeq:]
          Contact: <sip:[local_ip]:[local_port];transport=[transport]>
          Content-Length: 0
    
        ]]>
      </send>


The answering message, 180 Ringing in this case, is built with the
content of headers received in the INVITE message.


Actions
```````

In a "recv" or "recvCmd" command, you have the possibility to execute
an action. Several actions are available:


+ Regular expressions (ereg)
+ Log something in aa log file (log)
+ Execute an external (system), internal (int_cmd) or
  pcap_play_audio/pcap_play_video command (exec)
+ Manipulate double precision variables using arithmetic
+ Assign string values to a variable
+ Compare double precision variables
+ Jump to a particular scenario index
+ Store the current time into variables
+ Lookup a key in an indexed injection file
+ Verify Authorization credentials
+ Change a Call's Network Destination



Regular expressions
+++++++++++++++++++

Using regular expressions in SIPp allows to


+ Extract content of a SIP message or a SIP header and store it for
  future usage (called re-injection)
+ Check that a part of a SIP message or of an header is matching an
  expected expression


Regular expressions used in SIPp are defined per ` Posix Extended
standard (POSIX 1003.2)`_. If you want to learn how to write regular
expressions, I will recommend this ` regexp tutorial`_.

Here is the syntax of the regexp action:



regexp action syntax
````````````````````
Keyword Default Description regexp None Contains the regexp to use for
matching the received message or header. MANDATORY. search_in msg can
have four values: "msg" (try to match against the entire message);
"hdr" (try to match against a specific SIP header); "body" (try to
match against the SIP message body); or "var" (try to match against a
SIPp string variable). header None Header to try to match against.
Only used when the search_in tag is set to hdr. MANDATORY IF search_in
is equal to hdr. variable None Variable to try to match against. Only
used when the search_in tag is set to var. MANDATORY IF search_in is
equal to var. case_indep false To look for a header ignoring case .
Only used when the search_in tag is set to hdr. occurence 1 To find
the nth occurence of a header. Only used when the search_in tag is set
to hdr. start_line false To look only at start of line. Only used when
the search_in tag is set to hdr. check_it false if set to true, the
call is marked as failed if the regexp doesn't match. Can not be
combined with check_it_inverse. check_it_inverse false Inverse of
check_it. iff set to true, the call is marked as failed if the regexp
does match. Can not be combined with check_it. assign_to None contain
the variable id (integer) or a list of variable id which will be used
to store the result(s) of the matching process between the regexp and
the message. Those variables can be re-used at a later time either by
using '[$n]' in the scenario to inject the value of the variable in
the messages or by using the content of the variables for conditional
branching. The first variable in the variable list of assign_to
contains the entire regular expression matching. The following
variables contain the sub-expressions matching. Example:

::

    <ereg regexp="o=([[:alnum:]]*) ([[:alnum:]]*) ([[:alnum:]]*)"
                search_in="msg"
                check_it=i"true"
                assign_to="3,4,5,8"/>

If the SIP message contains the line

::

    o=user1 53655765 2353687637 IN IP4 127.0.0.1

variable 3 contains "o=user1 53655765 2353687637", variable 4 contains
"user1", variable 5 contains "53655765" and variable 8 contains
"2353687637".
Note that you can have several regular expressions in one action.

The following example is used to:


+ First action:

    + Extract the first IPv4 address of the received SIP message
    + Check that we could actually extract this IP address (otherwise call
      will be marked as failed)
    + Assign the extracted IP address to call variables 1 and 2.

+ Second action:

    + Extract the Contact: header of the received SIP message
    + Assign the extracted Contract: header to variable 6.



::

    
    <recv response="200" start_rtd="true">
      <action>
        <ereg regexp="([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]*" search_in="msg" check_it="true" assign_to="1,2" />
        <ereg regexp=".*" search_in="hdr" header="Contact:" check_it="true" assign_to="6" />
      </action>
    </recv>



Log a message
+++++++++++++

The "log" action allows you to customize your traces. Messages are
printed in the <scenario file name>_<pid>_logs.log file. Any keyword
is expanded to reflect the value actually used.

Warning
Logs are generated only if -trace_logs option is set on the command
line.
Example:

::

       <recv request="INVITE" crlf="true" rrs="true">
         <action>
    	 <ereg regexp=".*" search_in="hdr" header="Some-New-Header:" assign_to="1" />
              <log message="From is [last_From]. Custom header is [$1]"/>
         </action>
       </recv>


You can use the alternative "warning" action to log a message to
SIPp's error log. For example:

::

    <warning message="From is [last_From]. Custom header is [$1]"/>



Execute a command
+++++++++++++++++

The "exec" action allows you to execute "internal", "external",
"play_pcap_audio" or "play_pcap_video" commands.


Internal commands
+++++++++++++++++

Internal commands (specified using int_cmd attribute) are stop_call,
stop_gracefully (similar to pressing 'q'), stop_now (similar to
ctrl+C).

Example that stops the execution of the script on receiving a 603
response:

::

       <recv response="603" optional="true">
         <action>
              <exec int_cmd="stop_now"/>
          </action>
       </recv>



External commands
+++++++++++++++++

External commands (specified using command attribute) are anything
that can be executed on local host with a shell.

Example that execute a system echo for every INVITE received:

::

       <recv request="INVITE">
         <action>
              <exec command="echo [last_From] is the from header received >> from_list.log"/>
          </action>
       </recv>



Media/RTP commands
++++++++++++++++++

RTP streaming allows you to stream audio from a PCMA, PCMU or
G729-encoded audio file (e.g. a .wav file). The "rtp_stream" action
controls this.


+ <exec rtp_stream="file.wav" /> will stream the audio contained in
  file.wav, assuming it is a PCMA-format file.
+ <exec rtp_stream="[filename],[loopcount],[payloadtype]" /> will
  stream the audio contained in [filename], repeat the stream
  [loopcount] times (the default is 1, and -1 indicates it will repeat
  forever), and will treat the audio as being of [payloadtype] (where 8
  is the default of PCMA, 0 indicates PCMU, and 18 indicates G729).
+ <exec rtp_stream="pause" /> will pause any currently active
  playback.
+ <exec rtp_stream="resume" /> will resume any currently paused
  playback.


PCAP play commands (specified using play_pcap_audio / play_pcap_video
attributes) allow you to send a pre-recorded RTP stream using the
`pcap library`_.
Choose play_pcap_audio to send the pre-recorded RTP stream using the
"m=audio" SIP/SDP line port as a base for the replay.

Choose play_pcap_video to send the pre-recorded RTP stream using the
"m=video" SIP/SDP line port as a base.

The play_pcap_audio/video command has the following format:
play_pcap_audio="[file_to_play]" with:


+ file_to_play: the pre-recorded pcap file to play


Note
The action is non-blocking. SIPp will start a light-weight thread to
play the file and the scenario with continue immediately. If needed,
you will need to add a pause to wait for the end of the pcap play.
Warning
A known bug means that starting a pcap_play_audio command will end any
pcap_play_video command, and vice versa; you cannot play both audio
and video streams at once.

Example that plays a pre-recorded RTP stream:

::

    <nop>
      <action>
        <exec play_pcap_audio="pcap/g711a.pcap"/>
      </action>
    </nop>



Variable Manipulation
+++++++++++++++++++++

You may also perform simple arithmetic (add, subtract, multiply,
divide) on floating point values. The "assign_to" attribute contains
the first operand, and is also the destination of the resulting value.
The second operand is either an immediate value or stored in a
variable, represented by the "value" and "variable" attributes,
respectively.

SIPp supports call variables that take on double-precision floating
values. The actions that modify double variables all write to the
variable referenced by the assign_to parameter. These variables can be
assigned using one of three actions: assign, sample, or todouble. For
assign, the double precision value is stored in the "value" parameter.
The sample action assigns values based on statistical distributions,
and uses the same parameters as a statistically distributed pauses.
Finally, the todouble command converts the variable referenced by the
"variable" attribute to a double before assigning it.

For example, to assign the value 1.0 to $1 and sample from the normal
distribution into $2:

::

    <nop>
      <action>
        <assign assign_to="1" value="1" />
        <sample assign_to="2" distribution="normal" mean="0" stdev="1"/>
        <!-- Stores the first field in the injection file into string variable $3.
             You may also use regular expressions to store string variables. -->
        <assignstr assign_to="3" value="[field0]" />
        <!-- Converts the string value in $3 to a double-precision value stored in $4. -->
        <todouble assign_to="4" variable="3" />
      </action>
    </nop>


Simple arithmetic is also possible using the <add> , <subtract> ,
<multiply> , and <divide> actions, which add, subtract, multiply, and
divide the variable referenced by assign_to by the value in value .
For example, the following action modifies variable one as follows:

::

    <nop>
      <action>
        <assign assign_to="1" value="0" /> <!-- $1 == 0 -->
        <add assign_to="1" value="2" /> <!-- $1 == 2 -->
        <subtract assign_to="1" value="3" /> <!-- $1 == -1 -->
        <multiply assign_to="1" value="4" /> <!-- $1 == -4 -->
        <divide assign_to="1" value="5" /> <!-- $1 == -0.8 -->
      </action>


Rather than using fixed values, you may also retrieve the second
operand from a variable, using the <variable> parameter. For example:

::

    <nop>
      <action>
    	 <!-- Multiplies $1 by itself -->
    	 <multiply assign_to="1" variable="1" />
    	 <!-- Divides $1 by $2, Note that $2 must not be zero -->
    	 <multiply assign_to="1" variable="2" />
         </action>
       </nop>



String Variables
++++++++++++++++

You can create string variables by using the <assignstr> command,
which accepts two parameters: assign_to and value . The value may
contain any of the same substitutions that a message can contain. For
example:

::

    <nop>
         <action>
             <!-- Assign the value in field0 of the CSV file to a $1. -->
    	 <assignstr assign_to="1" value="[field0]" />
         </action>
       </nop>


A string variable and a value can be compared using the <strcmp>
action. The result is a double value, that is less than, equal to, or
greater than zero if the variable is lexographically less than, equal
to, or greater than the value. The parameters are assign_to, variable,
and value. For example:

::

    <nop>
         <action>
             <!-- Compare the value of $strvar to "Hello" and assign it to $result.. -->
    	 <strcmp assign_to="result" variable="strvar" value="Hello" />
         </action>
       </nop>



Variable Testing
++++++++++++++++

Variable testing allows you to construct loops and control structures
using call variables. THe test action takes four arguments: variable
which is the variable that to compare against value , and assign_to
which is a boolean call variable that the result of the test is stored
in. Compare may be one of the following tests: equal , not_equal ,
greater_than , less_than , greater_than_equal , or less_than_equal .

Example that sets $2 to true if $1 is less than 10:

::

    <nop>
      <action>
        <test assign_to="2" variable="1" compare="less_than" value="10" />
      </action>
    </nop>



lookup
++++++

The lookup action is used for indexed injection files (see indexed
injection files). The lookup action takes a file and key as input and
produces an integer line number as output. For example the following
action extracts the username from an authorization header and uses it
to find the corresponding line in users.csv.

::

    <recv request="REGISTER">
      <action>
        <ereg regexp="Digest .*username=\"([^\"]*)\"" search_in="hdr" header="Authorization:" assign_to="junk,username" />
        <lookup assign_to="line" file="users.csv" key="[$username]" />
      </action>
    </nop>



Updating In-Memory Injection files
++++++++++++++++++++++++++++++++++

Injection files, particularly when an index is defined can serve as an
in-memory data store for your SIPp scenario. The <insert> and
<replace> actions provide a method of programmatically updating SIPp's
in-memory version of an injection file (there is presently no way to
update the disk-based version). The insert action takes two
parameters: file and value, and the replace action takes an additional
line value. For example, to inserting a new line can be accomplished
as follows:

::

    <nop display="Insert User">
            <action>
                    <insert file="usersdb.conf" value="[$user];[$calltype]" />
            </action>
    </nop>


Replacing a line is similar, but a line number must be specified. You
will probably want to use the lookup action to obtain the line number
for use with replace as follows:

::

    <nop display="Update User">
            <action>
    		<lookup assign_to="index" file="usersdb.conf" key="[$user]" />
    		<!-- Note: This assumes that the lookup always succeeds. -->
                    <replace file="usersdb.conf" line="[$index]" value="[$user];[$calltype]" />
            </action>
    </nop>



Jumping to an Index
+++++++++++++++++++

You can jump to an arbitrary scenario index using the <jump> action.
This can be used to create rudimentary subroutines. The caller can
save their index using the [msg_index] substitution, and the callee
can jump back to the same place using this action. If there is a
special label named "_unexp.main" in the scenario, SIPp will jump to
that label whenever an unexpected message is received and store the
previous address in the variable named "_unexp.retaddr".

Example that jumps to index 5:

::

    <nop>
      <action>
        <jump value="5" />
      </action>
    </nop>


Example that jumps to the index contained in the variable named
_unexp.retaddr:

::

    <nop>
      <action>
        <jump variable="_unexp.retaddr" />
      </action>
    </nop>



gettimeofday
++++++++++++

The gettimeofday action allows you to get the current time in seconds
and microseconds since the epoch. For example:

::

    <nop>
      <action>
        <gettimeofday assign_to="seconds,microseconds" />
      </action>
    </nop>



setdest
+++++++

The setdest action allows you to change the remote end point for a
call. The parameters are the transport, host, and port to connect the
call to. There are certain limitations baed on SIPp's design: you can
not change the transport for a call; and if you are using TCP then
multi-socket support must be selected (i.e. -t tn must be specified).
Also, be aware that frequently using setdest may reduce SIPp's
capacity as name resolution is a blocking operation (thus potentially
causing SIPp to stall while looking up host names). This example
connects to the value specified in the [next_url] keyword.

::

      <nop>
         <action>
            <assignstr assign_to="url" value="[next_url]" />
            <ereg regexp="sip:.*@([0-9A-Za-z\.]+):([0-9]+);transport=([A-Z]+)"  search_in="var" check_it="true" assign_to="dummy,host,port,transport" variable="url" />
            <setdest host="[$host]" port="[$port]" protocol="[$transport]" />
         </action>
      </nop>
      


Warning
If you are using setdest with IPv6, you must not use square brackets
around the address. These have a special meaning to SIPp, and it will
try to interpret your IPv6 address as a variable.
Since the port is specified separately, square brackets are never
necessary.


verifyauth
++++++++++

The verifyauth action checks the Authorization header in an incoming
message against a provided username and password. The result of the
check is stored in a boolean variable. This allows you to simulate a
server which requires authorization. Currently only simple MD5 digest
authentication is supported. Before using the verifyauth action, you
must send a challenge. For example:

::

      <recv request="REGISTER" />
      <send><![CDATA[
    
          SIP/2.0 401 Authorization Required
          [last_Via:]
          [last_From:]
          [last_To:];tag=[pid]SIPpTag01[call_number]
          [last_Call-ID:]
          [last_CSeq:]
          Contact: <sip:[local_ip]:[local_port];transport=[transport]>
          WWW-Authenticate: Digest realm="test.example.com", nonce="47ebe028cda119c35d4877b383027d28da013815"
          Content-Length: [len]
    
        ]]>
      </send>


After receiving the second request, you can extract the username
provided and compare it against a list of user names and passwords
provided as an injection file, and take the appropriate action based
on the result:

::

    <recv request="REGISTER" />
            <action>
                    <ereg regexp="Digest .*username=\"([^\"]*)\"" search_in="hdr" header="Authorization:" assign_to="junk,username" />
                    <lookup assign_to="line" file="users.conf" key="[$username]" />
                    <verifyauth assign_to="authvalid" username="[field0 line=\"[$line]\"]" password="[field3 line=\"[$line]\"]" />
            </action>
      </recv>
    
      <nop hide="true" test="authvalid" next="goodauth" />
      <nop hide="true" next="badauth" />



Variables
`````````

For complex scenarios, you will need to store bits of information that
can be used across messages or even calls. Like other programming
languages, SIPp's XML scenario definition allows you to use variables
for this purpose. A variable in SIPp is referenced by an alphanumeric
name. In past versions of SIPp, variables names were numeric only;
thus in this document and the embedded scenarios, you are likely to
see lots of variables of the form "1", "2", etc.; although when
creating new scenarios you are encouraged to assign meaningful names
to your variables.

Aside from a name, SIPp's variables are also loosely typed. The type
of a variable is not explicitly declared, but is instead inferred from
the action that set it. There are four types of variables: string,
regular expression matches, doubles, and booleans. All mathematical
operations take place on doubles. The <test> and <verifyauth> actions
create boolean values. String variables and regular expression matches
are similar. When a string's value is called for, a regular expression
match can be substituted. The primary difference is related to the
test attribute (see Conditional Branching). If a string has been
defined, a test is evaluated to true. However, for a regular
expression variable, the regular expression that set it must match for
the test to evaluated to true. Values can be converted to strings
using the <assignstr> action. Values can be converted to doubles using
the <todouble> action.

Variables also have a scope, which is one of global to all calls, per-
user, or the default per-call. A global variable can be used, for
example to store scenario configuration parameters or to keep a global
counter. A user-variable when combined with the -users option allows
you to keep per-user state across calls (e.g., if this user has
already registered). Finally, the default per-call variables are
useful for copying values from one SIP message to the next or
controlling branching. Variables can be declared globally or per-user
using the following syntax:

::

    <Global variables="foo,bar" />
    <User variables="baz,quux" />


Local variables need not be declared. To prevent programming errors,
SIPp performs very rudimentary checks to ensure that each variable is
used more than once in the scenario (this helps prevent some typos
from turning into hard to debug errors). Unfortunately, this can cause
some complication with regular expression matching. The regular
expression action must assign the entire matched expression to a
variable. If you are only interested in checking the validity of the
expression (i.e. the check_it attribute is set) or in capturing a sub-
expression, you must still assign the entire expression to a variable.
As this variable is likely only referenced once, you must inform SIPp
that you are knowingly using this variable once with a Reference
clause. For example:

::

    <recv request="INVITE">
      <action>
        <ereg regexp="<sip:([^;@]*)" search_in="hdr" header="To:" assign_to="dummy,uri" />
      </action>
    </recv>
    <Reference variables="dummy" />



Injecting values from an external CSV during calls
``````````````````````````````````````````````````

You can use "-inf file_name" as a command line parameter to input
values into the scenarios. The first line of the file should say
whether the data is to be read in sequence (SEQUENTIAL), random order
(RANDOM), or in a user based manner (USER). Each line corresponds to
one call and has one or more ';' delimited data fields and they can be
referred as [field0], [field1], ... in the xml scenario file. Example:

::

    SEQUENTIAL
    #This line will be ignored
    Sarah;sipphone32
    Bob;sipphone12
    #This line too
    Fred;sipphone94


Will be read in sequence (first call will use first line, second call
second line). At any place where the keyword "[field0]" appears in the
scenario file, it will be replaced by either "Sarah", "Bob" or "Fred"
depending on the call. At any place where the keyword "[field1]"
appears in the scenario file, it will be replaced by either
"sipphone32" or "sipphone12" or "sipphone94" depending on the call. At
the end of the file, SIPp will re-start from the beginning. The file
is not limited in size.

You can override the default line selection strategy with the optional
line argument. For example:

::

    [field0 line=1]


Selects the second line in the file (the first line is line zero. The
line parameters support keywords in the argument, so in conjunction
with a lookup action it is possible to select values based on a key.

The CSV file can contain comment lines. A comment line is a line that
starts with a "#".

As a picture says more than 1000 words, here is one:



Think of the possibilities of this feature. They are huge.

It is possible to use more than one injection file, and is necessary
when you want to select different types of data in different ways. For
example, when running a user-based benchmark, you may have a
caller.csv with "USER" as the first line and a callee.csv with
"RANDOM" as the first line. To specify which CSV file is used, add the
file= parameter to the keyword. For example:

::

    
    INVITE sip:[field0 file="callee.csv"] SIP/2.0
    From: sipp user <[field0 file="caller.csv"]>;tag=[pid]SIPpTag00[call_number]
    To: sut user <[field0 file="callee.csv"]>
    ...


Will select the destination user from callee.csv and the sending user
from caller.csv. If no file parameter is specified, then the first
input file on the command line is used by default.


PRINTF Injection files
++++++++++++++++++++++

An extension of the standard injection file is a "PRINTF" injection
file. Often, an input file will has a repetitive nature such as:

::

    
    		USERS
    		user000;password000
    		user001;password001
    		...
    		user999;password999
    		


SIPp must maintain this structure in memory, which can reduce
performance for very large injection files. To eliminate this problem,
SIPp can automatically generate such a structured file based on one or
more template lines. For example:

::

    
    		USERS,PRINTF=999
    		user%03d;password%03d
    		


Has the same logical meaning as the original example, yet SIPp only
needs to store one entry in memory. Each time a line is used; SIPp
will replace %d with the requested line number (starting from zero).
Standard printf format decimal specifiers can be used. When more than
one template line is available, SIPp cycles through them. This
example:

::

    
    		USERS,PRINTF=4
    		user%03d;password%03d;Foo
    		user%03d;password%03d;Bar
    		


Is equivalent to the following injection file:

::

    
    		USERS
    		user000;password000;Foo
    		user001;password001;Bar
    		user002;password002;Foo
    		user003;password003;Bar
    		


The following parameters are used to control the behavior of printf
injection files:



Printf Injection File Parameters
````````````````````````````````
Parameter Description Example PRINTF How many virtual lines exist in
this file. PRINTF=10, creates 10 virtual lines PRINTFMULTIPLE Multiple
the virtual line number by this value before generating the
substitutions used. PRINTF=10,PRINTFMULTIPLE=2 creates 10 virtual
lines numbered 0,2,4,...,18. PRINTFOFFSET Add this value to the
virtual line number before generating the substitutions used (applied
after PRINTFMULTIPLE). PRINTF=10,PRINTFOFFSET=100 creates 10 virtual
lines numbered 100-109. PRINTF=10,PRINTFMULTIPLE=2,PRINTFOFFSET=10
creates 10 users numbered 10,12,14,...28.


Indexing Injection files
++++++++++++++++++++++++

The -infindex option allows you to generate an index of an injection
file. The arguments to -infindex are the injection file to index and
the field number that should be indexed. For example if you have an
injection file that contains user names and passwords (as the
following):

::

    
    		USERS
    		alice,pass_A
    		bob,pass_B
    		carol,pass_C
    		


You may want to extract the password for a given user in the file. To
do this efficiently, SIPp must build an index for the first field (0).
Thus you would pass the argument -infindex users.csv 0 (assuming the
file is named users.csv). SIPp will create an index that contains the
logical entries {"alice" => 0, "bob" => 1, "carol" => 2}. To extract a
particular password, you can use the lookup action to store the line
number into a variable (say $line) and then use the keyword[field1
line="[$line]"].


Conditional branching
`````````````````````


Conditional branching in scenarios
++++++++++++++++++++++++++++++++++

It is possible to execute a scenario in a non-linear way. You can jump
from one part of the scenario to another for example when a message is
received or if a call variable is set.

You define a label (in the xml) as <label id="n"/> Where n is a number
between 1 and 19 (we can easily have more if needed). The label
commands go anywhere in the main scenario between other commands. To
any action command (send, receive, pause, etc.) you add a next="n"
parameter, where n matches the id of a label. When it has done the
command it continues the scenario from that label. This part is useful
with optional receives like 403 messages, because it allows you to go
to a different bit of script to reply to it and then rejoin at the BYE
(or wherever or not).

Alternatively, if you add a test="m" parameter to the next, it goes to
the label only if variable [$m] is set. This allows you to look for
some string in a received packet and alter the flow either on that or
a later part of the script. The evaluation of a test varies based on
the type of call variable. For regular expressions, at least one match
must have been found; for boolean variables the value must be true;
and for all others a value must have been set (currently this only
applies to doubles). For more complicated tests, see the <test>
action.

Warning
If you add special cases at the end, dont forget to put a label at the
real end and jump to it at the end of the normal flow.
Example:

The following example corresponds to the embedded 'branchc' (client
side) scenario. It has to run against the embedded 'branchs' (server
side) scenario.




Randomness in conditional branching
+++++++++++++++++++++++++++++++++++

To have SIPp behave somewhat more like a "normal" SIP client being
used by a human, it is possible to use "statistical branching".
Wherever you can have a conditional branch on a variable being set
(test="4"), you can also branch based on a statistical decision using
the attribute "chance" (e.g. chance="0.90"). Chance can have a value
between 0 (never) and 1 (always). "test" and "chance" can be combined,
i.e. only branching when the test succeeds and the chance is good.

With this, you can have a variable reaction in a given scenario (e.g..
answer the call or reject with busy), or run around in a loop (e.g.
registrations) and break out of it after some random number of
iterations.


SIP authentication
``````````````````

SIPp supports SIP authentication. Two authentication algorithm are
supported: Digest/MD5 ("algorithm="MD5"") and Digest/AKA
("algorithm="AKAv1-MD5"", as specified by 3GPP for IMS).

Enabling authentication is simple. When receiving a 401 (Unauthorized)
or a 407 (Proxy Authentication Required), you must add auth="true" in
the <recv> command to take the challenge into account. Then, the
authorization header can be re-injected in the next message by using
[authentication] keyword.

Computing the authorization header is done through the usage of the
"[authentication]" keyword. Depending on the algorithm ("MD5" or
"AKAv1-MD5"), different parameters must be passed next to the
authentication keyword:


+ Digest/MD5 (example: [authentication username=joe password=schmo])

    + username : username: if no username is specified, the username is
      taken from the '-au' (authentication username) or '-s' (service)
      command line parameter
    + password : password: if no password is specified, the password is
      taken from the '-ap' (authentication password) command line parameter

+ Digest/AKA: (example: [authentication username=HappyFeet
  aka_OP=0xCDC202D5123E20F62B6D676AC72CB318
  aka_K=0x465B5CE8B199B49FAA5F0A2EE238A6BC aka_AMF=0xB9B9])

    + username : username: if no username is specified, the username is
      taken from the '-au' (authentication username) or '-s' (service)
      command line parameter
    + aka_K : Permanent secret key. If no aka_K is provided, the
      "password" attributed is used as aka_K.
    + aka_OP : OPerator variant key
    + aka_AMF : Authentication Management Field (indicates the algorithm
      and key in use)



In case you want to use authentication with a different
username/password or aka_K for each call, you can do this:


+ Make a CSV like this:

::

    SEQUENTIAL
    User0001;[authentication username=joe password=schmo]
    User0002;[authentication username=john password=smith]
    User0003;[authentication username=betty password=boop]


+ And an XML like this (the [field1] will be substituted with the full
  auth string, which is the processed as a new keyword):

::

    <send retrans="500">
        <![CDATA[
    
          REGISTER sip:[remote_ip] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port]
          To: <sip:[field0]@sip.com:[remote_port]>
          From: <sip:[field0]@[remote_ip]:[remote_port]>
          Contact: <sip:[field0]@[local_ip]:[local_port]>;transport=[transport]
          [field1]
          Expires: 300
          Call-ID: [call_id]
          CSeq: 2 REGISTER
          Content-Length: 0
    
        ]]>
      </send>




Example:

::

      <recv response="407" auth="true">
      </recv>
    
      <send>
        <![CDATA[
    
          ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port]
          From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
          To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
          Call-ID: [call_id]
          CSeq: 1 ACK
          Contact: sip:sipp@[local_ip]:[local_port]
          Max-Forwards: 70
          Subject: Performance Test
          Content-Length: 0
    
        ]]>
      </send>
    
      <send retrans="500">
        <![CDATA[
    
          INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port]
          From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
          To: sut <sip:[service]@[remote_ip]:[remote_port]>
          Call-ID: [call_id]
          CSeq: 2 INVITE
          Contact: sip:sipp@[local_ip]:[local_port]
          [authentication username=foouser]
          Max-Forwards: 70
          Subject: Performance Test
          Content-Type: application/sdp
          Content-Length: [len]
    
          v=0
          o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
          s=-
          t=0 0
          c=IN IP[media_ip_type] [media_ip]
          m=audio [media_port] RTP/AVP 0
          a=rtpmap:0 PCMU/8000
    
        ]]>
      </send>
    



Initialization Stanza
`````````````````````

Some complex scenarios require setting appropriate global variables at
SIPp startup. The initialization stanza allows you do do just that. To
create an initialization stanza, simply surround a series of <nop> and
<label> commands with <init> and </init>. These <nop>s are executed
once at SIPp startup. The variables within the init stanza, except for
globals, are not shared with calls. For example, this init stanza sets
$THINKTIME to 1 if it is not already set (e.g., by the -set command
line parameter).

::

    
    <init>
    	<!-- By Default THINKTIME is true. -->
    	<nop>
    		<action>
    			<strcmp assign_to="empty" variable="THINKTIME" value="" />
    			<test assign_to="empty" compare="equal" variable="empty" value="0" />
    		</action>
    	</nop>
    	<nop condexec="empty">
    		<action>
    			<assignstr assign_to="THINKTIME" value="1" />
    		</action>
    	</nop>
    </init>



