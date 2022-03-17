Initialization Stanza
=====================

Some complex scenarios require setting appropriate global variables at
SIPp startup. The initialization stanza allows you do do just that. To
create an initialization stanza, simply surround a series of <nop> and
<label> commands with <init> and </init>. These <nop>s are executed
once at SIPp startup. The variables within the init stanza, except for
globals, are not shared with calls. For example, this init stanza sets
$THINKTIME to 1 if it is not already set (e.g., by the -set command
line parameter).

::

    <init>
      <!-- By Default THINKTIME is true. -->
      <nop>
        <action>
          <strcmp assign_to="empty" variable="THINKTIME" value="" />
          <test assign_to="empty" compare="equal" variable="empty" value="0" />
        </action>
      </nop>
      <nop condexec="empty">
        <action>
          <assignstr assign_to="THINKTIME" value="1" />
        </action>
      </nop>
    </init>
