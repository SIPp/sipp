/**
 * @file dnsparser.h DNS message parser definitions.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

#ifndef DNSPARSER_H__
#define DNSPARSER_H__

#include <string>
#include <list>

#include "dnsrrecords.h"

class DnsParser
{
public:
  DnsParser(unsigned char* buf,
            int length);
  ~DnsParser();

  bool parse();

  std::list<DnsQuestion*>& questions() { return _questions; }
  std::list<DnsRRecord*>& answers() { return _answers; }
  std::list<DnsRRecord*>& authorities() { return _authorities; }
  std::list<DnsRRecord*>& additional() { return _additional; }

  static std::string display_records(const std::list<DnsRRecord*>& records);

private:
  int parse_header(unsigned char* hptr);
  int parse_domain_name(unsigned char* nptr, std::string& name);
  int parse_character_string(unsigned char* sptr, std::string& cstring);
  int parse_question(unsigned char* qptr, DnsQuestion*& question);
  int parse_rr(unsigned char* rptr, DnsRRecord*& record);
  int read_int16(unsigned char* p);
  int read_int32(unsigned char* p);
  int label_length(unsigned char* lptr);
  int label_offset(unsigned char* lptr);
  std::string display_message();

  unsigned char* _data;
  unsigned char* _data_end;
  int _length;

  int _qd_count;
  int _an_count;
  int _ns_count;
  int _ar_count;

  std::list<DnsQuestion*> _questions;
  std::list<DnsRRecord*> _answers;
  std::list<DnsRRecord*> _authorities;
  std::list<DnsRRecord*> _additional;

  // Constants defining sizes and offsets in message header.
  static const int HDR_SIZE                = 12;
  static const int QDCOUNT_OFFSET          = 4;
  static const int ANCOUNT_OFFSET          = 6;
  static const int NSCOUNT_OFFSET          = 8;
  static const int ARCOUNT_OFFSET          = 10;

  // Constants defining sizes and offsets in question.
  static const int Q_FIXED_SIZE            = 4;
  static const int QTYPE_OFFSET            = 0;
  static const int QCLASS_OFFSET           = 2;

  // Constants defining sizes and offsets in common RR header.
  static const int RR_HDR_FIXED_SIZE       = 10;
  static const int RRTYPE_OFFSET           = 0;
  static const int RRCLASS_OFFSET          = 2;
  static const int TTL_OFFSET              = 4;
  static const int RDLENGTH_OFFSET         = 8;

  // Constants defining sizes and offsets in NAPTR record.
  static const int NAPTR_FIXED_SIZE        = 4;
  static const int NAPTR_ORDER_OFFSET      = 0;
  static const int NAPTR_PREFERENCE_OFFSET = 2;
  static const int NAPTR_FLAGS_OFFSET      = 4;

  // Constants defining sizes and offsets in SRV record.
  static const int SRV_FIXED_SIZE          = 6;
  static const int SRV_PRIORITY_OFFSET     = 0;
  static const int SRV_WEIGHT_OFFSET       = 2;
  static const int SRV_PORT_OFFSET         = 4;
  static const int SRV_TARGET_OFFSET       = 6;

};

#endif
