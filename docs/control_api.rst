Control API and Web UI
======================

``tools/sipp_control.py`` exposes SIPp's existing UDP remote-control socket as
a small local HTTP API and browser dashboard.  It does not replace the native
control socket and does not run in SIPp's call-processing path.

Start SIPp normally, optionally with statistics enabled::

   sipp 192.0.2.10 -sf uac.xml -trace_stat -fd 1s

Start the control service next to it::

   python3 tools/sipp_control.py \
       --sipp-host 127.0.0.1 \
       --sipp-port 8888 \
       --stat-file uac_1234.csv

Open ``http://127.0.0.1:9880/`` to use the dashboard.

HTTP API
--------

``GET /api/v1/status`` returns the configured SIPp target, the last control
action and the latest complete statistics row. ``GET /healthz`` is a simple
liveness endpoint.

``POST /api/v1/control`` accepts a JSON object.  Supported actions are
allow-listed rather than forwarding arbitrary strings to SIPp::

   {"action": "pause"}
   {"action": "rate", "value": 500}
   {"action": "users", "value": 1000}
   {"action": "limit", "value": 10000}
   {"action": "quit"}

The remaining rate step actions are ``rate-up``, ``rate-down``,
``rate-up-10x`` and ``rate-down-10x``.  ``quit-now`` maps to SIPp's immediate
quit hotkey.

Security
--------

The HTTP server binds to ``127.0.0.1`` by default and has no authentication.
Do not bind it to an untrusted interface without a firewall or authenticated
reverse proxy.  The API intentionally has no raw-command endpoint.

Tests
-----

The command validator and statistics reader have standard-library unit tests::

   python3 -m unittest tests/test_sipp_control.py
