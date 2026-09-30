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
 */

#ifndef SIPP_DNS_HPP
#define SIPP_DNS_HPP

#include <string>
#include <vector>

/* DNS NAPTR (RFC 3403) and SRV (RFC 2782) records, to locate SIP servers
 * (RFC 3263). */

struct naptr_record
{
    unsigned short order;
    unsigned short preference;
    std::string flags;
    std::string service;
    std::string replacement; /* "." if there is none */
};

struct srv_record
{
    unsigned short priority;
    unsigned short weight;
    unsigned short port;
    std::string target; /* "." if the service is not available */
};

/* Append the NAPTR or SRV records of the answer section of the DNS
 * message msg, len bytes long, to records. They return false if the
 * message is malformed. */
bool naptr_parse(const unsigned char *msg, int len,
                 std::vector<naptr_record> &records);
bool srv_parse(const unsigned char *msg, int len,
               std::vector<srv_record> &records);

/* Keeps the records that lead to SRV records (flags "s") for service,
 * such as "SIP+D2U", in the order to try them: by order, then by
 * preference. */
void naptr_select(std::vector<naptr_record> &records, const char *service);

/* Puts records in the order to try them (RFC 2782): by priority, and in
 * a weighted random order within a priority. random(n) returns a
 * number from 0 to n, both included. */
void srv_order(std::vector<srv_record> &records,
               unsigned (*random)(unsigned n));

/* The SRV records of name, in the order to try them; none if the lookup
 * fails or has no answer. */
std::vector<srv_record> srv_lookup(const char *name);

/* The SRV records to try for host over one SIP transport (RFC 3263):
 * those of the first NAPTR record of host for service that has some or,
 * if host has no NAPTR record for service, those of prefix + host.
 * name gets the SRV name, and naptr whether a NAPTR record gave it. */
std::vector<srv_record> sip_srv_lookup(const char *host, const char *service,
                                       const char *prefix, std::string &name,
                                       bool &naptr);

#endif // SIPP_DNS_HPP
