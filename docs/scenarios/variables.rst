Variables
`````````

For complex scenarios, you will need to store bits of information that
can be used across messages or even calls. Like other programming
languages, SIPp's XML scenario definition allows you to use variables
for this purpose. A variable in SIPp is referenced by an alphanumeric
name. In past versions of SIPp, variables names were numeric only;
thus in this document and the embedded scenarios, you are likely to
see lots of variables of the form "1", "2", etc.; although when
creating new scenarios you are encouraged to assign meaningful names
to your variables.

Aside from a name, SIPp's variables are also loosely typed. The type
of a variable is not explicitly declared, but is instead inferred from
the action that set it. There are four types of variables: string,
regular expression matches, doubles, and booleans. All mathematical
operations take place on doubles. The **<test>** and **<verifyauth>** actions
create boolean values. String variables and regular expression matches
are similar. When a string's value is called for, a regular expression
match can be substituted. The primary difference is related to the
test attribute (see :ref:`cond-branching`). If a string has been
defined, a test is evaluated to true. However, for a regular
expression variable, the regular expression that set it must match for
the test to evaluated to true. Values can be converted to strings
using the **<assignstr>** action. Values can be converted to doubles using
the **<todouble>** action.

Variables also have a scope, which is one of global to all calls, per-
user, or the default per-call. A global variable can be used, for
example to store scenario configuration parameters or to keep a global
counter. A user-variable when combined with the -users option allows
you to keep per-user state across calls (e.g., if this user has
already registered). Finally, the default per-call variables are
useful for copying values from one SIP message to the next or
controlling branching. Variables can be declared globally or per-user
using the following syntax:

::

    <Global variables="foo,bar" />
    <User variables="baz,quux" />


Local variables need not be declared. To prevent programming errors,
SIPp performs very rudimentary checks to ensure that each variable is
used more than once in the scenario (this helps prevent some typos
from turning into hard to debug errors). Unfortunately, this can cause
some complication with regular expression matching. The regular
expression action must assign the entire matched expression to a
variable. If you are only interested in checking the validity of the
expression (i.e. the check_it attribute is set) or in capturing a sub-
expression, you must still assign the entire expression to a variable.
As this variable is likely only referenced once, you must inform SIPp
that you are knowingly using this variable once with a Reference
clause. For example:

::

    <recv request="INVITE">
      <action>
        <ereg regexp="<sip:([^;@]*)" search_in="hdr" header="To:" assign_to="dummy,uri" />
      </action>
    </recv>
    <Reference variables="dummy" />



