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
 *  Copyright (C) 2003 - The Authors
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 */

#ifdef __cplusplus
extern "C" {
#endif

int xp_unescape(const char *source, char *dest);
int xp_set_xml_buffer_from_string(const char *str);
int xp_set_xml_buffer_from_file(const char *filename);
char* xp_open_element(int index);
void xp_close_element(void);
char* xp_get_value(const char *name);
char* xp_get_cdata(void);
int xp_get_content_length(const char *P_buffer);

#ifdef __cplusplus
}
#endif
