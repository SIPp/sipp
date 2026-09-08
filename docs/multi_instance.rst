Multi-instance launcher
=======================

The multi-instance launcher is a standalone Python 3 helper for starting and
supervising multiple coordinated SIPp processes.

Run it with a CSV configuration file:

.. code-block:: bash

   python3 sipp-multi.py multi.csv --base-port 5060

The base port defaults to 5060.  Use ``--sipp`` when the SIPp binary is not
next to the helper and is not available on ``PATH``:

.. code-block:: bash

   python3 sipp-multi.py multi.csv --sipp ./build/sipp

When installed with SIPp, ``sipp-multi.py`` is placed in the same ``bin``
directory as the ``sipp`` executable.  If ``--sipp`` is omitted, the helper
first looks for that sibling executable (or ``sipp.exe`` on Windows) and then
searches ``PATH``.  The CSV file cannot select or replace the executable.

CSV format
----------

The format is:

.. code-block:: text

   role,count,args
   uas,2,"-sn uas -p {instance_port} -nostdin"
   uac,2,"-sn uac 127.0.0.1:{instance_port} -m 100 -nostdin"

Blank lines and lines whose first non-whitespace character is ``#`` are
ignored.  The header is optional and case-insensitive.  A configuration may
launch at most 256 child processes.

The ``args`` field uses POSIX shell-style quoting and is tokenized exactly
once with Python's ``shlex`` parser.  Placeholder expansion happens after
tokenization, so placeholder values containing spaces or quote characters
remain a single argument and are never re-parsed as shell syntax.  The helper
always uses ``subprocess`` with an argument vector; it never invokes a shell.

Placeholders
------------

The following placeholders are supported:

* ``{role}``: the role column value.
* ``{instance}``: zero-based instance number within that role.  If a role
  appears in multiple rows, numbering continues across those rows.
* ``{base_port}``: the base port passed with ``--base-port``.
* ``{instance_port}``: ``base_port + instance``.  Use this to pair UAC and
  UAS rows by instance number.
* ``{port}``: a globally increasing port number for every generated child.

The helper validates that every generated port remains between 1 and 65535.

Process supervision
-------------------

All children are started directly with ``subprocess.Popen`` and inherit the
helper's current working directory and standard input, output, and error
streams.  Relative paths in child arguments are therefore resolved from the
directory where the helper is run.

The helper waits for all children and returns the first non-zero child status
in launch order.  A child terminated by a POSIX signal is reported using the
usual ``128 + signal`` convention.  If a child cannot be started, children
that were already started are terminated and reaped before the helper exits
with failure.

On POSIX systems, when the helper receives ``SIGINT``, ``SIGTERM``, or
``SIGHUP``, it sends a graceful termination request to active children, waits
up to approximately one second, sends ``SIGKILL`` to any child that remains,
reaps all children, and exits with ``128 + signal``.

On native Windows, Python's ``Popen.terminate()`` uses ``TerminateProcess``, so
child termination is immediate rather than graceful; the one-second grace
period cannot be used by children to flush state before exiting.  The helper
uses only the Python standard library.

All children share the same terminal.  For coordinated non-interactive tests,
pass ``-nostdin`` in each row and redirect the helper output when desired:

.. code-block:: bash

   python3 sipp-multi.py multi.csv >multi.log 2>&1

Avoid SIPp's ``-bg`` option when the helper is expected to supervise a child
for the complete lifetime of a test; a process that backgrounds itself leaves
the helper's direct supervision.
