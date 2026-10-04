Control API and Web UI
======================

``tools/sipp_control.py`` exposes SIPp's UDP remote-control socket (see
:doc:`controlling`) as a small HTTP API and browser dashboard.  It does not
replace the native control socket and does not run in SIPp's call-processing
path.

Exposure
--------

SIPp's own UDP control socket is the real exposure: it listens on all
interfaces unless ``-ci`` is given, and anyone who can send it a datagram can
pause, re-rate or stop the run.  Bind it to loopback and give it a fixed port::

   sipp 192.0.2.10 -sf uac.xml -ci 127.0.0.1 -cp 8888 -trace_stat -fd 1s

Without ``-cp``, SIPp takes the first free port from 8888 upwards, so the port
to pass to the companion may differ.

Start the control service next to it::

   python3 tools/sipp_control.py --sipp-port 8888 --stat-dir . --scenario uac

Open ``http://127.0.0.1:9880/`` to use the dashboard.

The HTTP server binds to ``127.0.0.1`` by default and has no authentication in
that mode.  It only answers requests whose ``Host`` header is
``127.0.0.1``, ``localhost`` or ``[::1]`` with its port (and rejects a
``POST`` whose ``Origin`` is another site), which stops DNS-rebinding and
cross-site requests from a browser.  Responses carry
``X-Frame-Options: DENY`` and a ``Content-Security-Policy`` that only allows
the dashboard's own inline script and style.

A non-loopback ``--listen`` is refused unless ``--allow-remote`` is given and a
token is set in the ``SIPP_CONTROL_TOKEN`` environment variable.  API requests
must then send ``Authorization: Bearer <token>`` (the dashboard has a field for
it).  The listen address is accepted as a ``Host`` name; add others, such as a
DNS name, with ``--allow-host``.  The token is sent in clear text, so use this
only on a trusted network or behind a TLS reverse proxy.  There is
deliberately no raw-command endpoint.

Statistics
----------

With ``-trace_stat``, SIPp writes ``<scenario>_<pid>_.csv`` in its working
directory (or the file given by ``-stf``), where ``<scenario>`` is the
``-sf`` file name without ``.xml`` or the ``-sn`` name.  Give the file with
``--stat-file``, or let the companion pick the newest
``<scenario>_<pid>_.csv`` in a directory with ``--stat-dir`` and
``--scenario``.  The file is read with the parser of ``tools/sipp_report.py``.

The status shows a short list of numeric columns (rates, call counts,
failures, retransmissions, watchdogs, ``ResponseTime1(C)`` and
``CallLength(C)`` in seconds).  ``TargetRate`` is the rate SIPp is aiming for,
or the number of users when it runs with ``-users``; it is the way to see
whether a rate or users command took effect.  SIPp writes a row every ``-fd``
period, so set ``--stale-after`` (default 10 seconds) above it.  The values are
marked stale when the file stops changing or when the SIPp process named by
the pid in the file name has exited.

HTTP API
--------

``GET /api/v1/status`` returns the configured target, the last command sent,
the number of pause toggles sent and the statistics described above.
``GET /healthz`` is a liveness endpoint.

``POST /api/v1/control`` accepts a JSON object.  Supported actions are
allow-listed rather than forwarding arbitrary strings to SIPp:

==================  =============================  ==========================================
Action              Sent to SIPp                   Effect
==================  =============================  ==========================================
``pause``           ``p``                          Toggle pause; the companion cannot see the
                                                   resulting state
``step-up``         ``+``                          Rate + 1 × rate_scale (users with ``-users``)
``step-down``       ``-``                          Rate − 1 × rate_scale (users with ``-users``)
``step-up-10``      ``*``                          Rate + 10 × rate_scale (users with ``-users``)
``step-down-10``    ``/``                          Rate − 10 × rate_scale (users with ``-users``)
``rate``            ``set rate N``                 Rate-based runs only
``rate-scale``      ``set rate-scale N``           Step size of the four keys above
``users``           ``set users N``                ``-users`` runs only
``limit``           ``set limit N``                Rate-based runs only
``quit``            ``q``                          Graceful quit
``quit-now``        ``Q``                          Immediate quit
==================  =============================  ==========================================

For example::

   {"action": "rate", "value": 500}
   {"action": "rate-scale", "value": 10}

Values must be finite and non-negative; ``users`` and ``limit`` must be
integers and ``rate-scale`` greater than zero.

A ``quit`` repeated within two seconds is refused, because SIPp treats a
second ``q`` as an immediate quit.  With ``--mode rate`` or ``--mode users``
the companion also refuses the commands SIPp would ignore in that mode.

The control socket is fire-and-forget: SIPp sends no reply, and it ignores an
invalid command with only a warning on its own screen.  A ``200`` answer
therefore means the datagram was sent, not that SIPp applied it, and
``last_sent`` in the status is an echo of what was sent.  If nothing listens
on a loopback target the companion usually sees the ICMP port-unreachable
and answers ``502``.  Check ``TargetRate`` and the other statistics for the
actual effect.

Tests
-----

The tests run without SIPp, with a real HTTP server and UDP socket on
loopback::

   python3 -m unittest tests/test_sipp_control.py
