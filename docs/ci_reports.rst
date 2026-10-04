CI thresholds and reports
=========================

``tools/sipp_report.py`` turns the final row of a ``-trace_stat`` CSV file into
CI assertions.  A failed assertion exits with status 1, as does a column that
is not in the file; invalid input exits with status 2.

SIPp names the file ``<scenario>_<pid>_.csv`` (with the trailing underscore)
and writes its last row when it exits, so run the tool after SIPp has ended.
Assert on the cumulative ``(C)`` columns: the ``(P)`` columns are those of the
last reporting period only (see :doc:`statistics`).  Elapsed times, response
times and call lengths are written as ``HH:MM:SS`` or ``HH:MM:SS:UUUUUU``; the
tool reads them as seconds, so ``ResponseTime1(C)<=0.05`` is 50 ms.

Thresholds
----------

Threshold expressions use an exact statistics column name followed by one of
``<``, ``<=``, ``>``, ``>=``, ``==`` or ``!=`` and a numeric target::

   python3 tools/sipp_report.py uac_1234_.csv \
       --threshold 'SuccessfulCall(C)>=10000' \
       --threshold 'FailedCall(C)==0' \
       --threshold 'CallRate(C)>=500'

Thresholds may also be stored in JSON::

   {
     "SuccessfulCall(C)": ">=10000",
     "FailedCall(C)": "==0"
   }

and loaded with ``--threshold-file thresholds.json``.  Give a list to put
several bounds on one column, such as ``"CallRate(C)": [">=100", "<=500"]``.

Reports
-------

Use ``--json-out report.json`` for a machine-readable summary and
``--junit-out report.xml`` for JUnit-compatible test results.  Most CI systems
can publish the JUnit file without a SIPp-specific plugin.

Example GitHub Actions step::

   - name: Assert SIP load test
     run: |
       python3 tools/sipp_report.py artifacts/uac_stats.csv \
         --threshold-file ci/sipp-thresholds.json \
         --junit-out artifacts/sipp-junit.xml \
         --json-out artifacts/sipp-summary.json

Tests
-----

The threshold parser and report renderers use only the standard library::

   python3 -m unittest tests/test_sipp_report.py
