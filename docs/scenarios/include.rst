Including other files
=====================

A block of commands that several scenarios share, such as a
registration, can live in a file of its own. ``<xi:include>`` puts the
content of that file where it stands:

::

    <scenario name="call" xmlns:xi="http://www.w3.org/2001/XInclude">
      <xi:include href="register.xml"/>
      <send>
        ...
      </send>
    </scenario>

If the included file is a ``<scenario>``, its commands are included;
the included scenario's own attributes, such as its name, are ignored.
A file can also hold a single command as its root element, such as one
``<send>``. A relative ``href`` is relative to the directory of the
file that has the ``<xi:include>``. Included files can include others,
up to 16 levels deep.

The prefix must be ``xi``; SIPp does not need the ``xmlns:xi``
declaration, but XML editors may.
