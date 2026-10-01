/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Authors : Benjamin GAUTHIER - 24 Mar 2004
 *            Joseph BANINO
 *            Olivier JACQUES
 *            Richard GAYRAUD
 *            From Hewlett Packard Company.
 */

#ifndef __SIPP_SIP_PARSER_H__
#define __SIPP_SIP_PARSER_H__

#include <optional>
#include <string>
#include <string_view>

#define MAX_HEADER_LEN 2049

/* These return views into the message they read */
std::string_view get_call_id(const char *msg);
/* The tag of the To header; none when it has no tag parameter */
std::optional<std::string_view> get_peer_tag(const char *msg);

unsigned long int get_cseq_value(const char* msg);
unsigned long get_reply_code(const char* msg);

/* A header as get_header() returns it: a view into the message when the
 * message has it as it is returned, else a text of its own */
class header_value
{
public:
    header_value() = default;
    explicit header_value(std::string_view in_message) : text(in_message) {}
    explicit header_value(std::string &&built) : made(std::move(built)), is_made(true) {}

    /* Valid while this and the message are */
    std::string_view view() const
    {
        return is_made ? std::string_view(made) : text;
    }
    bool empty() const
    {
        return view().empty();
    }

private:
    std::string_view text;
    std::string made;
    bool is_made = false;
};

/* The value of the headers of name, "Via:" or another with its colon,
 * joined with ", " */
header_value get_header_content(const char *message, std::string_view name);
/* The same with the name before it unless content */
header_value get_header(const char *message, std::string_view name, bool content);
/* The number at the start of value, as strtol() reads it */
long header_number(std::string_view value);
std::string_view get_first_line(const char *message);

#endif /* __SIPP_SIP_PARSER_H__ */
