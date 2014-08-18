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

#define MAX_HEADER_LEN 2049

char *get_call_id(const char *msg);
char *get_peer_tag(const char *msg);

int get_method(char *msg);
unsigned long int get_cseq_value(char *msg);
unsigned long get_reply_code(char *msg);

char *get_header_content(const char * message, const char * name);
char *get_header(const char * message, const char * name, bool content);
char *get_first_line(const char * message);

#endif /* __SIPP_SIP_PARSER_H__ */
