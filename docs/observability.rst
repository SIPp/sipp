Observability exporters
=======================

SIPp can write periodic statistics with ``-trace_stat``.  The helper tools
in ``tools/`` turn the latest complete statistics row into live monitoring
signals without changing SIPp's call-processing path.  They read the row with
the same parser as ``tools/sipp_report.py`` (see :doc:`ci_reports`).

Prometheus and JSON
-------------------

Start SIPp with a periodic statistics report, for example::

   sipp 192.0.2.10 -sf uac.xml -trace_stat -fd 1s

SIPp writes the statistics to ``<scenario>_<pid>_.csv``, here
``uac_1234_.csv``.  Point the exporter at that file::

   python3 tools/sipp_metrics.py --stat-file uac_1234_.csv --serve

or let it find the newest ``<scenario>_<pid>_.csv`` in a directory.  The
``_counts.csv``, ``_error_codes.csv`` and ``_rtt.csv`` files and ``-inf``
input files are not used, and a file must start with the ``StartTime``
column.  The directory is searched again on every scrape, so a restarted
SIPp (with a new pid) is picked up; ``--scenario`` limits the search to one
scenario name::

   python3 tools/sipp_metrics.py --stat-dir /var/tmp/sipp --scenario uac --serve

The HTTP server listens on ``127.0.0.1:9876`` and provides:

* ``/metrics`` - Prometheus text exposition format.
* ``/v1/metrics`` - the same snapshot as JSON.
* ``/healthz`` - HTTP 200 while the statistics file can be read and its last
  row is recent, otherwise 503.

Metrics
-------

Column names are normalised to the ``sipp_`` metric namespace:

* ``(C)`` columns are cumulative since SIPp started and are exported as
  counters, such as ``sipp_successfulcall_total``.  Use ``rate()`` or
  ``increase()`` on them; a SIPp restart is a counter reset.
* The ``(C)`` running averages ``CallRate``, ``ResponseTime<n>``,
  ``CallLength`` and their ``StDev`` columns are gauges, such as
  ``sipp_responsetime1_seconds``.
* ``(P)`` columns hold the value of the last ``-fd`` period only and are
  gauges with a ``_period`` suffix, such as ``sipp_successfulcall_period``.
  A scrape sees one period out of each scrape interval, so periods are lost
  unless the scrape interval equals ``-fd``; prefer the ``(C)`` counters.
* Columns without a suffix, such as ``CurrentCall``, are gauges.
* ``ElapsedTime``, ``ResponseTime`` and ``CallLength`` values, written by SIPp
  as ``HH:MM:SS`` or ``HH:MM:SS:UUUUUU``, are exported in seconds with a
  ``_seconds`` suffix.
* Repartition ranges are named ``_lt_<n>`` and ``_ge_<n>``, such as
  ``sipp_responsetimerepartition1_lt_10_total``.

Text columns, such as ``StartTime``, are not exported.

Stale statistics
----------------

``sipp_stat_row_timestamp_seconds`` is the ``CurrentTime`` of the last row
and ``sipp_stat_row_age_seconds`` its age.  When the last row is older than
``--stale-after`` seconds (default 120, twice SIPp's default ``-fd``), for
example after SIPp has exited, ``sipp_exporter_up`` is 0, the statistics
series are left out and ``/healthz`` returns 503.  Set ``--stale-after``
above the ``-fd`` period, or to 0 to always serve the last row.

OpenTelemetry OTLP/HTTP
-----------------------

``sipp_otlp.py`` sends the same snapshot as OTLP/HTTP JSON; the counters are
cumulative monotonic sums starting at ``StartTime`` and every point carries
the ``CurrentTime`` of its row::

   python3 tools/sipp_otlp.py \
       --stat-file uac_1234_.csv \
       --endpoint http://otel-collector:4318/v1/metrics \
       --service-name sipp-loadtest

It takes the same ``--stat-dir``, ``--scenario`` and ``--stale-after``
options.  A row is pushed once; a stale row is not pushed.  A missing file or
a failed push is reported and retried at the next ``--interval``.  Use
``--once`` in CI or scripts that want one export and a meaningful exit
status.  The exporter uses only the Python standard library.

HTTP headers, such as credentials, are read from the
``OTEL_EXPORTER_OTLP_HEADERS`` environment variable (``name=value`` pairs
separated by commas, percent-encoded), then from ``--header-file FILE``
(one ``NAME=VALUE`` per line, ``#`` starts a comment), then from repeated
``--header NAME=VALUE`` options; a later source overrides an earlier one.

Security
--------

The Prometheus listener defaults to ``127.0.0.1``.  Binding it to another
interface with ``--listen`` exposes test statistics without authentication;
use a firewall or reverse proxy when remote scraping is required.  Values given
with ``--header`` are visible in the process list and shell history; pass
secrets with ``--header-file`` or ``OTEL_EXPORTER_OTLP_HEADERS`` instead.

Tests
-----

The reader, exporters and HTTP endpoints have dependency-free unit tests::

   python3 -m unittest tests/test_sipp_metrics.py
