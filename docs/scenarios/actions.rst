Actions
=======

In a `recv` or `recvCmd` command, you have the possibility to execute
an action. Several actions are available:


+ `Regular expressions`_ (ereg)
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

================  ======= ===========
Keyword           Default Description
================  ======= ===========
regexp            None    Contains the regexp to use for
                          matching the received message or header. MANDATORY.
search_in         msg     can have four values: "msg" (try to match against the entire message),
                          "hdr" (try to match against a specific SIP header), "body" (try to
                          match against the SIP message body), or "var" (try to match against a
                          SIPp string variable).
header            None    Header to try to match against.
                          Only used when the search_in tag is set to hdr. MANDATORY IF search_in
                          is equal to hdr.
variable          None    Variable to try to match against. Only
                          used when the search_in tag is set to var. MANDATORY IF search_in is
                          equal to var.
case_indep        false   To look for a header ignoring case .
                          Only used when the search_in tag is set to hdr.
occurrence         1      To find the nth occurrence of a header. Only used when the search_in tag is set
                          to hdr.
start_line        false   To look only at start of line. Only used when
                          the search_in tag is set to hdr.
check_it          false   if set to true, the
                          call is marked as failed if the regexp doesn't match. Can not be
                          combined with check_it_inverse.
check_it_inverse  false   Inverse of
                          check_it. iff set to true, the call is marked as failed if the regexp
                          does match. Can not be combined with check_it.
assign_to         None    contain
                          the variable id (integer) or a list of variable id which will be used
                          to store the result(s) of the matching process between the regexp and
                          the message. Those variables can be re-used at a later time either by
                          using '[$n]' in the scenario to inject the value of the variable in
                          the messages or by using the content of the variables for conditional
                          branching. The first variable in the variable list of assign_to
                          contains the entire regular expression matching. The following
                          variables contain the sub-expressions matching.
================  ======= ===========

Example for assign_to
---------------------
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

.. warning::
  Logs are generated only if -trace_logs option is set on the command line.

Example::

    <recv request="INVITE" crlf="true" rrs="true">
      <action>
        <ereg regexp=".*" search_in="hdr" header="Some-New-Header:" assign_to="1" />
        <log message="From is [last_From]. Custom header is [$1]"/>
      </action>
    </recv>


You can use the alternative "warning" action to log a message to
SIPp's error log. For example::

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
response::

    <recv response="603" optional="true">
      <action>
        <exec int_cmd="stop_now"/>
      </action>
    </recv>



External commands
+++++++++++++++++

External commands (specified using command attribute) are anything
that can be executed on local host with a shell.

Example that execute a system echo for every INVITE received::

    <recv request="INVITE">
      <action>
        <exec command="echo [last_From] is the from header received >> from_list.log"/>
      </action>
    </recv>



Media/RTP commands
++++++++++++++++++

RTP streaming allows you to stream audio from a PCMA, PCMU, G722,
iLBC or G729-encoded audio file (e.g. a .wav file). The "rtp_stream"
action controls this.


+ <exec rtp_stream="file.wav" /> will stream the audio contained in
  file.wav, assuming it is a PCMA-format file.
+ <exec rtp_stream="[filename],[loopcount],[payloadtype],[payloadparam]" /> will
  stream the audio contained in [filename], repeat the stream [loopcount] times
  (the default value is 1, and -1 indicates it will repeat forever), treat the
  audio as being of [payloadtype] (where 8 is the default of PCMA, 0 indicates
  PCMU, 9 indicates G722, 18 indicates G729), and payload param as
  [payloadparam] (eg: "PCMU/8000", "PCMA/8000", "G722/8000", "G729/8000",
  "H264/90000", "iLBC/8000").
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

The audio file should be the raw samples, example files are included
for PCMA, G722 and iLBC (mode=30).

===== ========== =========== =========== ================================
Codec Payload id Packet size Packet time FFMpeg arguments
===== ========== =========== =========== ================================
PCMU  0          160 bytes   20 ms       -f ulaw -ar 8k -ac 1
PCMA  8          160 bytes   20 ms       -f alaw -ar 8k -ac 1
G722  9          160 bytes   20 ms       -f g722 -ar 16k -ac 1
G729  18         20 bytes    20 ms       *not supported by ffmpeg*
iLBC  98         50 bytes    30 ms       -f ilbc -ar 8k -ac 1 -b:a 13.33k
===== ========== =========== =========== ================================

.. note::
  FFmpeg adds a header to iLBC files denoting the mode that is used, either 20
  or 30 ms per packet. This header needs to be stripped from the file.
.. note::
  The action is non-blocking. SIPp will start a light-weight thread to
  play the file and the scenario with continue immediately. If needed,
  you will need to add a pause to wait for the end of the pcap play.
.. warning::
  A known bug means that starting a pcap_play_audio command will end any
  pcap_play_video command, and vice versa; you cannot play both audio
  and video streams at once.

Example that plays a pre-recorded RTP stream::

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

For example, to assign the value 1.0 to ``$1`` and sample from the
normal distribution into ``$2``::

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
For example, the following action modifies variable one as follows::

    <nop>
      <action>
        <assign assign_to="1" value="0" /> <!-- $1 == 0 -->
        <add assign_to="1" value="2" /> <!-- $1 == 2 -->
        <subtract assign_to="1" value="3" /> <!-- $1 == -1 -->
        <multiply assign_to="1" value="4" /> <!-- $1 == -4 -->
        <divide assign_to="1" value="5" /> <!-- $1 == -0.8 -->
      </action>
    </nop>


Rather than using fixed values, you may also retrieve the second
operand from a variable, using the <variable> parameter. For example::

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
example::

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
and value. For example::

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

Example that sets ``$2`` to true if ``$1`` is less than 10::

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
    </recv>



Updating In-Memory Injection files
++++++++++++++++++++++++++++++++++

Injection files, particularly when an index is defined can serve as an
in-memory data store for your SIPp scenario. The <insert> and
<replace> actions provide a method of programmatically updating SIPp's
in-memory version of an injection file (there is presently no way to
update the disk-based version). The insert action takes two
parameters: file and value, and the replace action takes an additional
line value. For example, to inserting a new line can be accomplished
as follows::

    <nop display="Insert User">
      <action>
        <insert file="usersdb.conf" value="[$user];[$calltype]" />
      </action>
    </nop>


Replacing a line is similar, but a line number must be specified. You
will probably want to use the lookup action to obtain the line number
for use with replace as follows::

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

Example that jumps to index 5::

    <nop>
      <action>
        <jump value="5" />
      </action>
    </nop>


Example that jumps to the index contained in the variable named
_unexp.retaddr::

    <nop>
      <action>
        <jump variable="_unexp.retaddr" />
      </action>
    </nop>



gettimeofday
++++++++++++

The gettimeofday action allows you to get the current time in seconds
and microseconds since the epoch. For example::

    <nop>
      <action>
        <gettimeofday assign_to="seconds,microseconds" />
      </action>
    </nop>



urlencode / urldecode
+++++++++++++++++++++

The urlencode and urldecode actions will replace the content of the
variable specified in variable with the coded version.

For example, if the content of ``variable_to_be_encoded`` is
``this: is a string``, then content of ``variable_to_be_encoded`` will then
become ``this%3A%20is%20a%20string``::

    <nop>
      <action>
        <urlencode variable="variable_to_be_encoded" />
      </action>
    </nop>



setdest
+++++++

The setdest action allows you to change the remote end point for a
call. The parameters are the transport, host, and port to connect the
call to. There are certain limitations based on SIPp's design: you can
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


.. warning::
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
server which requires authorization. Currently MD5 and SHA-256 digest
authentications are supported. Before using the verifyauth action, you
must send a challenge. For example::

    <recv request="REGISTER" />
    <send>
      <![CDATA[

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
on the result::

    <recv request="REGISTER">
      <action>
        <ereg regexp="Digest .*username=\"([^\"]*)\"" search_in="hdr" header="Authorization:" assign_to="junk,username" />
        <lookup assign_to="line" file="users.conf" key="[$username]" />
        <verifyauth assign_to="authvalid" username="[field0 line=\"[$line]\"]" password="[field3 line=\"[$line]\"]" />
      </action>
    </recv>

    <nop hide="true" test="authvalid" next="goodauth" />
    <nop hide="true" next="badauth" />

.. _PCAP library: https://www.tcpdump.org/manpages/pcap.3pcap.html
