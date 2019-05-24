Integrated scenarios
====================

Integrated scenarios? Yes, there are scenarios that are embedded in
SIPp executable. While you can create your own custom SIP scenarios
(see how to create your own XML scenarios), a few basic (yet useful)
scenarios are available in SIPp executable.


UAC
```

Scenario file: :download:`uac.xml <uac.xml>`

::

    SIPp UAC            Remote
        |(1) INVITE         |
        |------------------>|
        |(2) 100 (optional) |
        |<------------------|
        |(3) 180 (optional) |
        |<------------------|
        |(4) 200            |
        |<------------------|
        |(5) ACK            |
        |------------------>|
        |                   |
        |(6) PAUSE          |
        |                   |
        |(7) BYE            |
        |------------------>|
        |(8) 200            |
        |<------------------|



UAC with media
``````````````

Scenario file: :download:`uac_pcap.xml <uac_pcap.xml>`

::

    SIPp UAC            Remote
        |(1) INVITE         |
        |------------------>|
        |(2) 100 (optional) |
        |<------------------|
        |(3) 180 (optional) |
        |<------------------|
        |(4) 200            |
        |<------------------|
        |(5) ACK            |
        |------------------>|
        |                   |
        |(6) RTP send (8s)  |
        |==================>|
        |                   |
        |(7) RFC2833 DIGIT 1|
        |==================>|
        |                   |
        |(8) BYE            |
        |------------------>|
        |(9) 200            |
        |<------------------|



UAS
```

Scenario file: :download:`uas.xml <uas.xml>`

::

    Remote              SIPp UAS
        |(1) INVITE         |
        |------------------>|
        |(2) 180            |
        |<------------------|
        |(3) 200            |
        |<------------------|
        |(4) ACK            |
        |------------------>|
        |                   |
        |(5) PAUSE          |
        |                   |
        |(6) BYE            |
        |------------------>|
        |(7) 200            |
        |<------------------|



regexp
``````

Scenario file: :download:`regexp.xml <regexp.xml>`

This scenario, which behaves as an UAC is explained in greater details
in this section.

::

    SIPp regexp         Remote
        |(1) INVITE         |
        |------------------>|
        |(2) 100 (optional) |
        |<------------------|
        |(3) 180 (optional) |
        |<------------------|
        |(4) 200            |
        |<------------------|
        |(5) ACK            |
        |------------------>|
        |                   |
        |(6) PAUSE          |
        |                   |
        |(7) BYE            |
        |------------------>|
        |(8) 200            |
        |<------------------|



branch
``````

Scenario files: :download:`branchc.xml <branchc.xml>` and
:download:`branchs.xml <branchs.xml>`

Those scenarios, which work against each other (branchc for client
side and branchs for server side) are explained in greater details in
this section.

::

    REGISTER ---------->
         200 <----------
         200 <----------
      INVITE ---------->
         100 <----------
         180 <----------
         403 <----------
         200 <----------
         ACK ---------->
             [  5000 ms]
         BYE ---------->
         200 <----------



UAC Out-of-call Messages
````````````````````````

Scenario file: :download:`ooc_default.xml <ooc_default.xml>`

When a SIPp UAC receives an out-of-call request, it instantiates an
out-of-call scenario. By default this scenario simply replies with a
200 OK response. This scenario can be overridden by passing the -oocsf
or -oocsn command line options.

::

    SIPp UAC            Remote
        |(1) .*             |
        |<------------------|
        |(2) 200            |
        |------------------>|



3PCC
````

3PCC stands for 3rd Party Call Control. 3PCC is described in
:RFC:`3725`. While this feature was first developed to allow 3PCC like
scenarios, it can also be used for every case where you would need one
SIPp to talk to several remotes.

In order to keep SIPp simple (remember, it's a test tool!), one SIPp
instance can only talk to one remote. Which is an issue in 3PCC call
flows, like call flow I (SIPp being a controller)::

    A              Controller               B
    |(1) INVITE no SDP  |                   |
    |<------------------|                   |
    |(2) 200 offer1     |                   |
    |------------------>|                   |
    |                   |(3) INVITE offer1  |
    |                   |------------------>|
    |                   |(4) 200 OK answer1 |
    |                   |<------------------|
    |                   |(5) ACK            |
    |                   |------------------>|
    |(6) ACK answer1    |                   |
    |<------------------|                   |
    |(7) RTP            |                   |
    |.......................................|


Scenario file: :download:`3pcc-A.xml <3pcc-A.xml>`

Scenario file: :download:`3pcc-B.xml <3pcc-B.xml>`

Scenario file: :download:`3pcc-C-A.xml <3pcc-C-A.xml>`

Scenario file: :download:`3pcc-C-B.xml <3pcc-C-B.xml>`

The 3PCC feature in SIPp allows to have two SIPp instances launched
and synchronised together. If we take the example of call flow I, one
SIPp instance will take care of the dialog with remote A (this
instance is called 3PCC-C-A for 3PCC-Controller-A-Side) and another
SIPp instance will take care of the dialog with remote B (this
instance is called 3PCC-C-B for 3PCC-Controller-B-Side).

The 3PCC call flow I will, in reality, look like this (Controller has
been divided in two SIPp instances)::

    A             Controller A         Controller B            B
    |(1) INVITE no SDP  |                  |                   |
    |<------------------|                  |                   |
    |(2) 200 offer1     |                  |                   |
    |------------------>|                  |                   |
    |                sendCmd  (offer1)     |                   |
    |                   |----------------->|                   |
    |                   |               recvCmd                |
    |                   |                  |(3) INVITE offer1  |
    |                   |                  |------------------>|
    |                   |                  |(4) 200 OK answer1 |
    |                   |                  |<------------------|
    |                   |               sendCmd                |
    |                   |     (answer1)    |                   |
    |                   |<-----------------|                   |
    |                 recvCmd              |(5) ACK            |
    |                   |                  |------------------>|
    |(6) ACK answer1    |                  |                   |
    |<------------------|                  |                   |
    |(7) RTP            |                  |                   |
    |..........................................................|


As you can see, we need to pass information between both sides of the
controller. SDP "offer1" is provided by A in message (2) and needs to
be sent to B side in message (3). This mechanism is implemented in the
scenarios through the <sendCmd> command. This::

    <sendCmd>
      <![CDATA[
        Call-ID: [call_id]
        [$1]

       ]]>
    </sendCmd>


Will send a "command" to the twin SIPp instance. Note that including
the Call-ID is mandatory in order to correlate the commands to actual
calls. In the same manner, this::

    <recvCmd>
      <action>
         <ereg regexp="Content-Type:.*"
               search_in="msg"
               assign_to="2"/>
      </action>
    </recvCmd>


Will receive a "command" from the twin SIPp instance. Using the
regular expression mechanism, the content is retrieved and stored in a
call variable ($2 in this case), ready to be reinjected::

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
        [$2]

      ]]>
    </send>


In other words, sendCmd and recvCmd can be seen as synchronization
points between two SIPp instances, with the ability to pass parameters
between each other.

Another scenario that has been reported to be do-able with the 3PCC
feature is the following:


+ A calls B. B answers. B and A converse
+ B calls C. C answers. C and B converse
+ B "REFER"s A to C and asks to replace A-B call with B-C call.
+ A accepts. A and C talk. B drops out of the calls.
