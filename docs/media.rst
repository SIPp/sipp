Handling media with SIPp
========================

SIPp is originally a signalling plane traffic generator. There is a
limited support of media plane (RTP).


RTP echo
````````

The "RTP echo" feature allows SIPp to listen to one or two local IP
address and port (specified using -mi and -min_rtp_port command line
parameters) for RTP media. Everything that is received on this
address/port is echoed back to the sender.

RTP/UDP packets coming on this port + 2 are also echoed to their
sender (used for sound and video echo).


RTP streaming
`````````````

SIPp can play a PCMA, PCMU, G722, iLBC or G729-encoded audio file over
RTP.

More details on how to do this can be found in the action reference
section.


RTP check functionality
```````````````````````

SIPp has support for for bidirectional RTP or bidirectional SRTP
checking. This is not detailed in the RST docs, but in a separate PDF,
unfortunately. See:
:download:`rtpcheck_xml_syntax_reference.pdf <rtpcheck_xml_syntax_reference.pdf>`


PCAP Play
`````````

The PCAP play feature makes use of the `PCAP library`_ to replay pre-
recorded RTP streams towards a destination. RTP streams can be
recorded by tools like Wireshark or ``tcpdump``. This allows you to:


+ Play any RTP stream (voice, video, voice+video, out of band
  DTMFs/:RFC:`2833`, T38 fax, ...)
+ Use any codec as the codec is not handled by SIPp
+ Emulate precisely the behavior of any SIP equipment as the pcap play
  will try to replay the RTP stream as it was recorded (limited to the
  performances of the system).
+ Reproduce exactly what has been captured using an IP sniffer like
  Wireshark.


A good example is the UAC with media (uac_pcap) embedded scenario.

SIPp comes with a G711 alaw pre-recorded pcap file and out of band
(:RFC:`2833`) DTMFs in the pcap/ directory.

.. warning::
    The PCAP play feature uses pthread_setschedparam calls from pthread
    library. Depending on the system settings, you might need to be root
    to allow this. Please check "man 3 pthread_setschedparam" man page for
    details


More details on the possible PCAP play actions can be found in the
action reference section.

.. _PCAP library: https://www.tcpdump.org/manpages/pcap.3pcap.html
