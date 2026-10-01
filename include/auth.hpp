/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
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
 */

#ifndef __SIPP_AUTH_H__
#define __SIPP_AUTH_H__

#include <string>
#include <string_view>

/* The credentials answering the challenge auth in result, true; or why
 * there are none in result, false. */
bool createAuthHeader(std::string_view user, std::string_view password, const char *method, std::string_view uri,
                      std::string_view msgbody, std::string_view auth, const char *aka_OP, const char *aka_AMF,
                      const char *aka_K, unsigned int nonce_count, std::string &result);
int verifyAuthHeader(std::string_view user, std::string_view password, std::string_view method, std::string_view auth,
                     std::string_view msgbody);
/* The value of parameter name in header, in it: "" if it has none */
std::string_view getAuthParameter(std::string_view name, std::string_view header);
/* Of the challenges in auth (headers joined by ", "), the first that
 * createAuthHeader() can answer, in auth; all of them if none. */
std::string_view selectAuthChallenge(std::string_view auth);

#endif /* __SIPP_AUTH_H__ */
