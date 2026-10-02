/* musl's src/regex/regerror.c (1.2.5), without its locale translation:
 * the messages are glibc's, as SIPp prints them. */
#include <string.h>
#include <stdio.h>
#include "regex.h"

static const char messages[][40] = {
	"Success",
	"No match",
	"Invalid regular expression",
	"Invalid collation character",
	"Invalid character class name",
	"Trailing backslash",
	"Invalid back reference",
	"Unmatched [, [^, [:, [., or [=",
	"Unmatched ( or \\(",
	"Unmatched \\{",
	"Invalid content of \\{\\}",
	"Invalid range end",
	"Memory exhausted",
	"Invalid preceding regular expression",
};

size_t regerror(int e, const regex_t *restrict preg, char *restrict buf, size_t size)
{
	const char *s = e >= 0 && e < (int)(sizeof messages / sizeof *messages) ? messages[e] : "Unknown error";
	(void)preg;
	return 1 + snprintf(buf, size, "%s", s);
}
