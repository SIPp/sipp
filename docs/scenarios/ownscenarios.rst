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
that can be used for all of the message commands (i.e., **<send>** ,
**<recv>** , **<nop>** , **<pause>** , **<sendCmd>**  and **<recvCmd>** ).



List of attributes common to all commands
`````````````````````````````````````````
.. flat-table::
    :header-rows:  1
    :stub-columns: 0
    :widths:       1 5 5

    * - Attribute(s)
      - Description
      - Example
    * - ``start_rtd``
      - Starts one of the " Response Time Duration" timer. (see statistics section).
      - ::

          <send start_rtd="invite">

        the timer named "invite" will start when the message is sent.
    * - ``rtd``
      - Stops one of the 5 " Response Time Duration"
      - ::

          <send rtd="2">

        the timer number 2 will stop when the message is sent.
    * - ``repeat_rtd``
      - Used with a rtd attribute, it allows the
        corresponding " Response Time Duration" timer to be counted more
        than once per call (useful for loop call flows).
      - ::

          <send rtd="1"repeat_rtd="true">

        the timer number 1 value will be printed but the timer won't stop.
    * - ``crlf``
      - Displays an empty line after the arrow for the
        message in main SIPp screen.
      - ::

          <send crlf="true">

    * - ``next``

      - You can put a "next"
        in any command element to go to another part of the script when
        you are done with sending the message. For optional receives, the next
        is only taken if that message was received. See conditional branching
        section for more info.

      - Example to jump to label "12" after sending an ACK:

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

    * - ``test``
      - You can put a "test" next to a "next" attribute to indicate that
        you only want to branch to the label specified with "next" if the
        variable specified in "test" is set (through regexp for example). See
        conditional branching section for more info.

      - Example to jump to label
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

    * - ``chance``
      - In combination with "test", probability to actually branch to
        another part of the scenario. Chance can have a value between 0
        (never) and 1 (always). See conditional branching section for more
        info.

      - ::

          <recv response="403" optional="true" next="5" test="3" chance="0.90">
          </recv>

        90% chance to go to label "5" if variable "3" is set.

    * - ``condexec``
      - Executes an element only if the variable in the condexec attribute is
        set. This attribute allows you to write complex XML scenarios with
        fewer next attributes and labels.

      - ::

          <nop condexec="executethis">

    * - ``condexec_inverse``
      - If condexec is set, condexec_inverse inverts the
        condition in condexec. This allows you to execute an element only when
        a variable is **not** set.

      - ::

          <nop condexec="skipthis"condexec_inverse="true">

    * - counter
      - Increments the counter given as
        parameter when the message is sent. The counters are saved in the
        statistic file.

      - ::

          <send counter="MsgA">

        Increments counter "MsgA" when the message is sent.
        Each command also has its own unique attributes, listed here:


List of commands with their attributes
``````````````````````````````````````
.. flat-table::
    :header-rows:  1
    :stub-columns: 0
    :widths:       1 1 5 5

    * - Command
      - Attribute(s)
      - Description
      - Example
    * - **<send>**
      - retrans
      - Used for UDP transport only: it specifies the T1 timer value, as described in SIP
        :RFC:`3261`, section 17.1.1.2.
      - ::

          <send retrans="500">

        will initiate T1 timer to 500 milliseconds (:RFC:`3261` default).
    * -
      - ``lost``
      - Emulate packet lost. The value is specified as a percentage.
      - ::

          <send lost="10">

        10% of the message sent are actually not sent :).
    * -
      - ``start_txn``
      - Records the branch ID of this sent message so that responses
        can be properly matched (without this element the transaction
        matching is done based on the CSeq method, which is imprecise).
      - ::

          <send start_txn="invite">

        Stores the branch ID of this message in the transaction named "invite".
    * -
      - ``ack_txn``
      - Indicates that the ACK being sent corresponds to the
        transaction started by a start_txn attribute. Every INVITE with a
        start_txn tag must have a matching ACK with an ack_txn attribute.
      - ::

          <send ack_txn="invite">

        References the branch ID of the transaction named "invite".
    * - **<recv>**
      - response
      - Indicates what SIP message code is expected.
      - ::

          <recv response="200">

        SIPp will expect a SIP message with code "200".
    * -
      - ``request``
      - Indicates what SIP message request is expected.
      - ::

          <recv request="ACK">

        SIPp will expect an "ACK" SIP message.
    * -
      - ``optional``
      - Indicates if the message to receive is optional. In case of an
        optional message and if the message is actually received, it is not
        seen as a unexpected message. When an unexpected message is received,
        Sipp looks if this message matches an optional message defined in the
        previous step of the scenario.
        If optional is set to "global", Sipp will look every previous steps of
        the scenario.
      - ::

          <recv response="100" optional="true">

        The 100 SIP message can be received without being considered as "unexpected".
    * -
      - ``ignoresdp``
      - Ignore SDP from received message, when set to true. It will allow you
        to reject newly negotiated streams while keeping the old media flowing.
      - ::

          <recv request="INVITE" ignoresdp="true">
    * -
      - ``rrs``
      - R ecord R oute S et. if this attribute is set to "true", then the
        "Record-Route:" header of the message received is stored and can be
        recalled using the ``[routes]`` keyword.
      - ::

          <recv response="100" rrs="true">
    * -
      - ``auth``
      - Authentication. if this attribute is set to "true", then the
        "Proxy-Authenticate:" header of the message received is stored and is
        used to build the [authentication] keyword.
      - ::

          <recv response="407" auth="true">
    * -
      - ``lost``
      - Emulate packet lost. The value is specified as a
        percentage.
      - ::

          <recv lost="10">

        10% of the message received are thrown away.
    * -
      - ``timeout``
      - Specify a timeout while waiting for a message. If the
        message is not received, the call is aborted, unless an ontimeout
        label is defined.
      - ::

          <recv timeout="100000">
    * -
      - ``ontimeout``
      - Specify a label to jump to if the timeout popped before the message to be received.
      - Example to jump to label "5" when not receiving a 100 message after
        100 seconds:

        ::

          <recv response="100" timeout="100000" ontimeout="5">
          </recv>

    * -
      - ``action``
      - Specify an action when receiving the message. See Actions
        section for possible actions.
      - Example of a "regular expression" action:

        ::

          <recv response="200">
          <action>
            <ereg regexp="([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]*"
              search_in="msg"
              check_it="true"
              assign_to="1,2"/>
            </action>
          </recv>

    * -
      - ``regexp_match``
      - Boolean. Indicates if 'request' ('response' is not
        available) is given as a regular expression. If so, the recv command
        will match against the regular expression. This allows to catch
        several cases in the same receive command.
      - Example of a recv command that matches MESSAGE or PUBLISH or SUBSCRIBE requests:

        ::

          <recv request="MESSAGE|PUBLISH|SUBSCRIBE" crlf="true" regexp_match="true">
          </recv>

    * -
      - ``response_txn``
      - Indicates that this is a response to a transaction that
        was previously started. To match, the branch ID of the first via
        header must match the stored transaction ID.
      - ::

          <recv response="200" response_txn="invite" />

        Matches only responses to the message sent with start_txn="invite"
        attribute.
    * - ``<pause>``
      - milliseconds
      - Specify the pause delay, in milliseconds. When this delay is not set, the value of
        the -d command line parameter is used.
      - ::

          <pause milliseconds="5000"/>

        pause the scenario for 5 seconds.
    * -
      - ``variable``
      - Indicates which call variable to use to determine the length of the pause.
      - ::

          <pause variable="1" />

        pauses for the number of milliseconds specified by
        call variable 1.
    * -
      - ``distribution``
      - Indicates which statistical distribution
        to use to determine the length of the pause. Without GSL, you may use
        uniform or fixed. With GSL, normal, exponential, gamma, lambda,
        lognormal, negbin, (negative binomial), pareto, and weibull are
        available. Depending on the distribution you select, you must also
        supply distribution specific parameters.
      - The following examples show the various types of distributed pauses:

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

          .. figure:: dist_normal.gif

        + <pause distribution="lognormal" mean="12.28" stdev="1" /> creates a
          distribution's whose natural logarithm has a mean of 12.28 and a
          standard deviation of 1. The mean and standard deviation are specified
          as double values (in milliseconds). The distribution will look like:

          .. figure:: dist_lognormal.gif

        + <pause distribution="exponential" mean="900000"/> creates an
          exponentially distributed pause with a mean of 15 minutes. The
          distribution will look like:

          .. figure:: dist_exponential.gif

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

    * -
      - ``sanity_check``
      - By default, statistically distributed pauses are sanity
        checked to ensure that their 99th percentile values are less than
        INT_MAX. Setting sanity_check to false disables this behavior.
      - ::

          <pause distribution="lognormal" mean="10" stdev="10" sanity_check="false"/>

        disables sanity checking of the lognormal distribution.
    * - **<nop>**
      - action
      - The nop command doesn't do anything at SIP level. It is only there to
        specify an action to execute. See Actions section for possible
        actions.
      - Execute the play_pcap_audio/video action:

        ::

          <nop>
            <action>
              <exec play_pcap_audio="pcap/g711a.pcap"/>
            </action>
          </nop>

    * - **<sendCmd>**
      - ``<![CDATA[]]>``
      - Content to be sent to the twin 3PCC SIPp
        instance. The Call-ID must be included in the CDATA. In 3pcc extended
        mode, the From must be included to.
      - ::

          <sendCmd>
            <![CDATA[
              Call-ID: [call_id]
              [$1]

            ]]>
          </sendCmd>

    * -
      - ``dest``
      - 3pcc extended mode only: the twin sipp instance which the command
        will be sent to
      - ::

          <sendCmd dest="s1">

        the command will be sent to the "s1" twin instance
    * - **<recvCmd>**
      - ``action``
      - Specify an action when receiving the command. See Actions section
        for possible actions.
      - Example of a "regular expression" to retrieve what has been send
        by a sendCmd command:

        ::

          <recvCmd>
            <action>
              <ereg regexp="Content-Type:.*"
                    search_in="msg"
                    assign_to="2"/>
            </action>
          </recvCmd>

    * -
      - ``src``
      - 3pcc extended mode only: indicate the twin sipp instance which the
        command is expected to be received from
      - ::

          <recvCmd src = "s1">

        the command will be expected to be received from the "s1" twin instance
    * - **<label>**
      - ``id``
      - A label is used when you want to branch to specific parts
        in your scenarios. The "id" attribute is an integer where the maximum
        value is 19. See conditional branching section for more info.
      - Example: set label number 13:

        ::

          <label id="13"/>

    * - **<Response Time Repartition>**
      - ``value``
      - Specify the intervals, in milliseconds, used to distribute
        the values of response times.
      - ::

          <ResponseTimeRepartition value="10, 20, 30"/>

        response time values are distributed between 0 and 10ms,
        10 and 20ms, 20 and 30ms, 30 and beyond.
    * - **<Call Length Repartition>**
      - ``value``
      - Specify the intervals, in milliseconds, used to distribute
        the values of the call length measures.
      - ::

          <CallLengthRepartition value="10, 20, 30"/>

        call length values are distributed between 0 and 10ms, 10 and
        20ms, 20 and 30ms, 30 and beyond.
    * - **<Global>**
      - ``variables``
      - Specify the name of globally scoped variables.
      - ::

          <Global variables="foo,bar"/>

    * - **<User>**
      - ``variables``
      - Specify the name of user-scoped variables.
      - ::

          <User variables="foo,bar"/>

    * - **<Reference>**
      - ``variables``
      - Suppresses warnings about unused variables.
      - ::

          <Reference variables="dummy"/>


There are not so many commands: send, recv, sendCmd, recvCmd, pause,
ResponseTimeRepartition, CallLengthRepartition, Global, User, and
Reference. To make things even clearer, nothing is better than an
example...


Structure of client (UAC like) XML scenarios
````````````````````````````````````````````

A client scenario is a scenario that starts with a "send" command. So
let's start::

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

Now, let's send the ACK::

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


And finish the call by sending a BYE and expecting the 200 OK::

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

    <recv response="200" />


And this is the end of the scenario::

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
scenarios. For example, a UAS example will look like::

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



.. _Negative Binomial on Wikipedia: https://en.wikipedia.org/wiki/Negative_binomial_distribution
.. _Weibull on Wikipedia: https://en.wikipedia.org/wiki/Weibull_distribution
.. _Pareto on Wikipedia: https://en.wikipedia.org/wiki/Pareto_distribution
.. _Gamma on Wikipedia: https://en.wikipedia.org/wiki/Gamma_distribution
