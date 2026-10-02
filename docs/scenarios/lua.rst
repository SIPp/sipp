Lua scripts
===========

A scenario can call functions written in Lua, to do what SIPp has no
action for: a look-up in a table, a file or a database, a string
transformation, a decision that depends on the calls before. The
function reads and writes the variables of the call, and so changes what
the scenario sends or where it goes on.

The idea, and the first example, are from pull request #577 by Nathan
Franzmeier.


Enabling Lua
------------

SIPp must be built with Lua (5.3 or 5.4). It is when CMake finds Lua
with pkg-config; ``-DUSE_LUA=1`` makes it an error if it does not, and
``-DUSE_LUA=0`` leaves Lua out. ``sipp -v`` shows ``-LUA`` in the
version when it is built in.

The Lua file is given with ``-lua_file``. SIPp runs it once at start,
before the first call: it defines the functions the scenario calls, and
can set up what they need, such as reading a file.


Calling a function
------------------

The ``lua`` attribute of ``exec`` holds the name of a global function,
and its arguments, separated by spaces. Keywords are replaced first, and
every argument is a string. For example, with ``[$called]`` holding
1002, ``<exec lua="translate [$called]"/>`` calls ``translate("1002")``.
An argument can not hold a space; a function that takes a number of
words can use ``...`` in Lua.

Lua keeps its state between calls: a global, or a ``local`` of the file,
is the same for every call of the scenario.


The sipp table
--------------

The functions of the ``sipp`` table work on the call that runs the Lua
function:

``sipp.get(name)``
  The value of the variable *name*, with no ``$``: a string, a number
  for a variable set by a calculation, a boolean for a variable set by a
  test; nil if it has no value yet.

``sipp.set(name, value)``
  Sets the variable to *value*, a string, a number or a boolean. A
  number shows as ``42.000000`` in a keyword, like the numbers of other
  actions: ``string.format("%d", n)`` gives the string ``42``. A boolean
  is what the ``test`` of a ``<nop>`` looks at, see the second example.

``sipp.log(message)``
  Writes to the log file of ``-trace_logs``, as the ``log`` action does.
  ``print`` would write over SIPp's screen.

The variable must be one the scenario uses somewhere, in an action or a
keyword: SIPp makes the variables of a scenario when it reads it, and a
name it does not know is an error. In a scenario with a ``lua`` action a
variable may be used just once: SIPp does not give the "referenced 1
times" error, as Lua may be the one that sets it.


Errors and speed
----------------

A Lua error, a function that does not exist and a variable that does not
exist end SIPp, with the message, as an ``error`` action does.

The function runs in SIPp's main thread, in the middle of the call: no
other call, message or timer is handled until it returns. A function
that waits for a database, or runs a program, holds up all the calls for
that long. Keep them short, or keep the answers in a Lua table.


Example: translate a number
---------------------------

A UAS that answers with a translated number in a header. The table could
as well be read from a file at start. The function is in translate.lua::

    -- a table; it could as well be read from a file, or asked from a database
    local translations = {
      ["1001"] = "sip:sales@example.com",
      ["1002"] = "sip:support@example.com",
    }

    function translate(called)
      sipp.set("target", translations[called] or "sip:operator@example.com")
    end

The scenario is run with ``sipp -sf uas_translate.xml -lua_file
translate.lua``. Its INVITE action reads the number of the To header
into ``called``, and the answer uses the ``target`` that Lua set::

    <recv request="INVITE">
      <action>
        <ereg regexp="sip:([^@]*)@" search_in="hdr" header="To:" assign_to="_,called"/>
        <exec lua="translate [$called]"/>
      </action>
    </recv>

    <send>
      <![CDATA[

        SIP/2.0 200 OK
        [last_Via:]
        [last_From:]
        [last_To:];tag=[pid]SIPpTag01[call_number]
        [last_Call-ID:]
        [last_CSeq:]
        X-Translated-Called: [$target]
        Contact: <sip:[local_ip]:[local_port];transport=[transport]>
        Content-Length: 0

      ]]>
    </send>


Example: reject some callers
----------------------------

Lua reads a list at start, and tells for each call if the caller is on
it. A boolean variable that is true makes a ``<nop test=...>`` jump.
screen.lua, with a file blocked.txt of one number per line::

    -- one number per line
    local blocked = {}
    for number in io.lines("blocked.txt") do
      blocked[number] = true
    end

    function screen(caller)
      sipp.set("blocked", blocked[caller] or false)
    end

The scenario, with the ordinary answer to the INVITE (a 200 OK, then
the ACK, BYE and its answer) left out::

    <recv request="INVITE">
      <action>
        <ereg regexp="sip:([^@]*)@" search_in="hdr" header="From:" assign_to="_,caller"/>
        <exec lua="screen [$caller]"/>
      </action>
    </recv>

    <nop test="blocked" next="reject"/>

    ... the answer of a caller that is not on the list ...

    <label id="reject"/>

    <send>
      <![CDATA[

        SIP/2.0 403 Forbidden
        [last_Via:]
        [last_From:]
        [last_To:];tag=[pid]SIPpTag01[call_number]
        [last_Call-ID:]
        [last_CSeq:]
        Content-Length: 0

      ]]>
    </send>

    <recv request="ACK" optional="true"/>


Example: use the backends in turn
---------------------------------

The state of Lua is the same for every call, so a counter can share the
calls out. ``<exec lua="next_backend"/>`` sets ``backend``, which a
keyword, such as a Route header, uses::

    local backends = { "10.0.0.1", "10.0.0.2", "10.0.0.3" }
    local n = 0

    function next_backend()
      n = n + 1
      sipp.set("backend", backends[(n - 1) % #backends + 1])
    end

The first three calls get 10.0.0.1, 10.0.0.2 and 10.0.0.3, the fourth
10.0.0.1 again.


Example: clean up a number
--------------------------

Lua's string functions do what SIPp's regular expressions are clumsy
at: here, only the digits are kept, and a ten digit number gets the
country code 1. ``<exec lua="normalize (555)123-4567"/>`` sets ``e164``
to ``+15551234567``::

    function normalize(number)
      local digits = number:gsub("%D", "")
      if #digits == 10 then
        digits = "1" .. digits
      end
      sipp.set("e164", "+" .. digits)
    end


Example: ask a program
----------------------

A function can run a program, such as ``curl`` for a REST service, and
use what it prints. ``<exec lua="run printf hello"/>`` sets ``answer``
to ``hello``; for a service it would be ``<exec lua="run curl -s
http://host/lookup?number=[$called]"/>``. Mind the speed: all the calls
wait for the program::

    function run(...)
      local out = io.popen(table.concat({...}, " "))
      sipp.set("answer", out:read("*l"))
      out:close()
    end

Lua has no timeout for ``io.popen``; give the program its own, such as
``curl --max-time 1``.


Example: a calculation
----------------------

A number set by Lua is a number to the actions of SIPp, as the result of
an ``<add>`` is. ``<exec lua="add 2 40"/>`` sets ``sum`` to 42, which a
``<test>`` can compare::

    function add(a, b)
      sipp.set("sum", tonumber(a) + tonumber(b))
    end
