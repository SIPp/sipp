RTCP/SRTCP media quality analysis
=================================

``tools/sipp_rtcp_qos.py`` decodes RTCP sender/receiver reports and emits
JSON media-quality measurements. It is designed as a companion for SIPp media
tests, so analysis can evolve without adding work to SIPp's packet scheduler.

Plain RTCP
----------

Decode one compound RTCP datagram::

    python3 tools/sipp_rtcp_qos.py --hex 81c90007...

Or listen for RTCP datagrams on UDP::

    python3 tools/sipp_rtcp_qos.py --listen 127.0.0.1:9001 --clock-rate 8000

For each SR/RR report block the output includes:

* interval packet-loss percentage from ``fraction lost``
* cumulative packet loss
* RTP interarrival jitter converted to milliseconds
* RTT when LSR/DLSR data is available
* an R-factor and listening-quality MOS estimate

The MOS calculation is deliberately labelled as an estimate. It uses a
G.711-style E-model approximation and is useful for test thresholds and trend
comparison; it is not a codec-aware replacement for a full ITU-T G.107 model.

SRTCP
-----

AES-CM SRTCP packets can be authenticated and decrypted when the SDP SDES
``inline:`` master material is known::

    python3 tools/sipp_rtcp_qos.py \
      --listen 127.0.0.1:9001 \
      --srtcp-inline '<base64-master-key-and-salt>'

SRTCP support currently covers the SDES suites used by SIPp's AES-CM SRTP
paths: 128-bit AES-CM with HMAC-SHA1 80-bit or 32-bit authentication tags.
Use ``--srtcp-tag-bytes 4`` for the 32-bit tag variant; the default is 10.

SRTCP AES support uses the optional Python ``cryptography`` package. Plain
RTCP parsing and QoS/MOS calculations require only the Python standard
library.

Security notes
--------------

The SDES inline value contains key material. Avoid putting it in shell history,
logs, CI output or process listings on shared systems. Prefer a protected
wrapper or ephemeral test environment when analyzing encrypted media.

The parser rejects malformed packet lengths, unsupported RTCP versions and
SRTCP packets with failed authentication before attempting to decrypt them.
