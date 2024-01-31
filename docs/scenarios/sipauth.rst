SIP authentication
``````````````````

SIPp supports SIP authentication. Two authentication algorithm are
supported: Digest/MD5 ("algorithm="MD5""),
Digest/SHA-256 ("algorithm="SHA-256"") and Digest/AKA
("algorithm="AKAv1-MD5"", as specified by 3GPP for IMS).

Enabling authentication is simple. When receiving a 401 (Unauthorized)
or a 407 (Proxy Authentication Required), you must add auth="true" in
the <recv> command to take the challenge into account. Then, the
authorization header can be re-injected in the next message by using
[authentication] keyword.

Computing the authorization header is done through the usage of the
"[authentication]" keyword. Depending on the algorithm ("MD5", "AKAv1-MD5" or
"SHA-256"), different parameters must be passed next to the
authentication keyword:


+ Digest/MD5 and Digest/SHA-256 (example: [authentication username=joe password=schmo])

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


+ Make a CSV like this::

    SEQUENTIAL
    User0001;[authentication username=joe password=schmo]
    User0002;[authentication username=john password=smith]
    User0003;[authentication username=betty password=boop]


+ And an XML like this (the [field1] will be substituted with the full
  auth string, which is the processed as a new keyword)::

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



Example::

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
