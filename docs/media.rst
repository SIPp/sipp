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

SIPp has support for bidirectional RTP or bidirectional SRTP
checking. This is not detailed in the RST docs, but in a separate PDF,
unfortunately. See:
:download:`rtpcheck_xml_syntax_reference.pdf <rtpcheck_xml_syntax_reference.pdf>`

The Rust port adds an RTT probe as pattern 7: every 0xAA-filled packet
carries a magic byte, a 64-bit per-call tag and a microsecond send stamp, which
an echoing peer (a UAS ``rtp_echo`` or an SBC media loop) returns
verbatim. The sender times the round trip and reports duplicates,
reordering and loss, even when a B2BUA rewrites the SSRC, sequence number
and timestamp. It needs a payload of at least 13 bytes and an echoing
peer. ``-trace_rtp_rtt`` writes one row per call to ``-rtp_rtt_file``,
and a run summary is printed at exit. ``-rtp_rtt_interval`` (default
250 ms, 0 off) adds a row per call per window, with ``window_ms`` on
every row (0 is the call total). Each row also carries an RFC 3550-style
RTT jitter: the smoothed difference of successive round trips, not
one-way interarrival jitter, and zero until two samples arrive. p95 is
nearest-rank over up to 64 window samples or the call's last 256; the run
summary keeps the first 100,000 samples.
``-trace_probe_tags`` (``-probe_tags_file``) writes, on the echoing
side, one row per call with the probe tag it received, the echoed packet
count and the call's Call-ID, so the sender's ``tag -> call`` column
pairs the two legs without a capture. The C++ SIPp does not have this
yet.


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
(:RFC:`2833`) DTMFs in the pcap/ directory. The play_dtmf action
generates such DTMFs for any digits, without a pcap file.

.. warning::
    The PCAP play feature sends the packets from a raw socket, which
    needs root or the CAP_NET_RAW capability, e.g. with
    ``setcap cap_net_raw+ep sipp``.


More details on the possible PCAP play actions can be found in the
action reference section.

.. _PCAP library: https://www.tcpdump.org/manpages/pcap.3pcap.html
