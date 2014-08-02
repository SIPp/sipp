/**
 * @file dnsparser.cpp DNS message parser implementation
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

#include <sstream>
#include <iomanip>
#include <exception>

#include <memory.h>
#include <ctype.h>

#include <ares.h>

#include "dnsparser.h"

DnsParser::DnsParser(unsigned char* buf,
                     int length) :
  _data(buf),
  _data_end(buf + length - 1),
  _length(length),
  _questions(),
  _answers(),
  _authorities(),
  _additional()
{
}

DnsParser::~DnsParser()
{
  while (!_questions.empty())
  {
    delete _questions.front();
    _questions.pop_front();
  }
  while (!_answers.empty())
  {
    delete _answers.front();
    _answers.pop_front();
  }
  while (!_authorities.empty())
  {
    delete _authorities.front();
    _authorities.pop_front();
  }
  while (!_additional.empty())
  {
    delete _additional.front();
    _additional.pop_front();
  }
}

bool DnsParser::parse()
{
  bool rc = true;
  unsigned char* rptr = _data;

  // LOG_DEBUG("Parsing DNS message\n%s", display_message().c_str());

  try
  {
    // Parse the header.
    // LOG_DEBUG("Parsing header at offset 0x%x", rptr - _data);
    rptr += parse_header(rptr);
    // LOG_DEBUG("%d questions, %d answers, %d authorities, %d additional records",
    //          _qd_count, _an_count, _ns_count, _ar_count);

    // Parse the question(s).
    for (int ii = 0; ii < _qd_count; ++ii)
    {
      // LOG_DEBUG("Parsing question %d at offset 0x%x", ii+1, rptr - _data);
      DnsQuestion* question;
      rptr += parse_question(rptr, question);
      _questions.push_back(question);
    }

    // Parse the answer(s)
    for (int ii = 0; ii < _an_count; ++ii)
    {
      // LOG_DEBUG("Parsing answer %d at offset 0x%x", ii+1, rptr - _data);
      DnsRRecord* rr;
      rptr += parse_rr(rptr, rr);
      _answers.push_back(rr);
    }

    // Parse the NS records.
    for (int ii = 0; ii < _ns_count; ++ii)
    {
      // LOG_DEBUG("Parsing NS record %d at offset 0x%x", ii+1, rptr - _data);
      DnsRRecord* rr;
      rptr += parse_rr(rptr, rr);
      _authorities.push_back(rr);
    }

    // Parse the additional records.
    for (int ii = 0; ii < _ar_count; ++ii)
    {
      // LOG_DEBUG("Parsing additional record %d at offset 0x%x", ii+1, rptr - _data);
      DnsRRecord* rr;
      rptr += parse_rr(rptr, rr);
      _additional.push_back(rr);
    }
  }
  catch (std::exception e)
  {
    // LOG_ERROR("Failed to parse DNS message - %s", e.what());
    rc = false;
  }

  // LOG_DEBUG("Answer records\n%s", display_records(_answers).c_str());
  // LOG_DEBUG("Authority records\n%s", display_records(_authorities).c_str());
  // LOG_DEBUG("Additional records\n%s", display_records(_additional).c_str());

  return rc;
}

int DnsParser::parse_header(unsigned char* hptr)
{
  if (hptr + HDR_SIZE > _data_end)
  {
    throw std::exception();
  }
  _qd_count = read_int16(hptr + QDCOUNT_OFFSET);
  _an_count = read_int16(hptr + ANCOUNT_OFFSET);
  _ns_count = read_int16(hptr + NSCOUNT_OFFSET);
  _ar_count = read_int16(hptr + ARCOUNT_OFFSET);

  return HDR_SIZE;
}

int DnsParser::parse_domain_name(unsigned char *nptr, std::string& name)
{
  int compressed_length = 0;
  unsigned char* lptr = nptr;

  if (*lptr == 0)
  {
    // Already at the root domain, so just return a single dot.
    name = ".";
    return 1;
  }

  name = "";

  do
  {
    if (lptr > _data_end)
    {
      throw std::exception();
    }
    int length;
    int offset;
    if ((length = label_length(lptr)) != -1)
    {
      // Length field, so append the label.
      if (lptr + length + 1 > _data_end)
      {
        throw std::exception();
      }
      name.append((const char *)(lptr + 1), length);
      lptr += length + 1;
      if (*lptr != 0)
      {
        name.append(".");
      }
    }
    else if ((offset = label_offset(lptr)) != -1)
    {
      // Offset field.
      if (offset > (lptr - _data))
      {
        // Forward references are not allowed.
        throw std::exception();
      }
      if (compressed_length == 0)
      {
        // This is the first pointer followed, so calculate the length of
        // the compressed name.
        compressed_length = lptr - nptr + 2;
      }
      lptr = _data + offset;
    }
    else
    {
      // LOG_DEBUG("Unexpected label length/offset field %x at offset %x", *lptr, lptr - _data);
      throw std::exception();
    }
  }
  while (*lptr != 0);

  if (compressed_length == 0)
  {
    // We didn't follow any pointers, so fill in the compressed length.
    compressed_length = lptr - nptr + 1;
  }

  // LOG_DEBUG("Parsed domain name = %s, encoded length = %d", name.c_str(), compressed_length);

  return compressed_length;
}

int DnsParser::parse_character_string(unsigned char* sptr, std::string& cstring)
{
  if (sptr + *sptr > _data_end)
  {
    throw std::exception();
  }
  cstring.assign((const char*)(sptr + 1), *sptr);

  return *sptr + 1;
}

int DnsParser::parse_question(unsigned char* qptr, DnsQuestion*& question)
{
  std::string qname;
  int nlength = parse_domain_name(qptr, qname);
  int qtype = read_int16(qptr + nlength + QTYPE_OFFSET);
  int qclass = read_int16(qptr + nlength + QCLASS_OFFSET);
  question = new DnsQuestion(qname, qtype, qclass);

  return nlength + Q_FIXED_SIZE;
}

int DnsParser::parse_rr(unsigned char* rptr, DnsRRecord*& rr)
{
  // Parse the common RR fields.
  std::string rrname;
  int nlength = parse_domain_name(rptr, rrname);
  if (rptr + RR_HDR_FIXED_SIZE > _data_end)
  {
    throw std::exception();
  }
  int rrtype = read_int16(rptr + nlength + RRTYPE_OFFSET);
  int rrclass = read_int16(rptr + nlength + RRCLASS_OFFSET);
  int ttl = read_int32(rptr + nlength + TTL_OFFSET);
  int rdlength = read_int16(rptr + nlength + RDLENGTH_OFFSET);
  unsigned char* rdata = rptr + nlength + RR_HDR_FIXED_SIZE;

  // Check the length of the variable part of the record doesn't overflow
  // the buffer.
  if (rdata + rdlength - 1 > _data_end)
  {
    throw std::exception();
  }

  /* LOG_DEBUG("Resource Record NAME=%s TYPE=%s CLASS=%s TTL=%d RDLENGTH=%d",
            rrname.c_str(),
            DnsRRecord::rrtype_to_string(rrtype).c_str(),
            DnsRRecord::rrclass_to_string(rrclass).c_str(),
            ttl, rdlength); */

  // Process the variant parts of the record.
  if ((rrclass == ns_c_in) && (rrtype == ns_t_a))
  {
    // LOG_DEBUG("Parse A record RDATA");
    if (rdlength < (int)sizeof(struct in_addr))
    {
      throw std::exception();
    }
    struct in_addr address;
    memcpy((char*)&address, rdata, sizeof(struct in_addr));
    rr = (DnsRRecord*)new DnsARecord(rrname, ttl, address);
  }
  else if ((rrclass == ns_c_in) && (rrtype == ns_t_aaaa))
  {
    // LOG_DEBUG("Parse AAAA record RDATA");
    if (rdlength < (int)sizeof(struct in6_addr))
    {
      throw std::exception();
    }
    struct in6_addr address;
    memcpy((char*)&address, rdata, sizeof(struct in6_addr));
    rr = (DnsRRecord*)new DnsAAAARecord(rrname, ttl, address);
  }
  else if ((rrclass == ns_c_in) && (rrtype == ns_t_srv))
  {
    // LOG_DEBUG("Parse SRV record RDATA");
    if (rdlength < SRV_FIXED_SIZE)
    {
      throw std::exception();
    }
    int priority = read_int16(rdata + SRV_PRIORITY_OFFSET);
    int weight = read_int16(rdata + SRV_WEIGHT_OFFSET);
    int port = read_int16(rdata + SRV_PORT_OFFSET);
    std::string target;
    int target_len = parse_domain_name(rdata + SRV_TARGET_OFFSET, target);
    if (rdlength < SRV_TARGET_OFFSET + target_len)
    {
      throw std::exception();
    }
    rr = (DnsRRecord*)new DnsSrvRecord(rrname, ttl, priority, weight, port, target);
  }
  else if ((rrclass == ns_c_in) && (rrtype == ns_t_naptr))
  {
    // LOG_DEBUG("Parse NAPTR record RDATA");
    if (rdlength < NAPTR_FIXED_SIZE)
    {
      throw std::exception();
    }
    int order = read_int16(rdata + NAPTR_ORDER_OFFSET);
    int preference = read_int16(rdata + NAPTR_PREFERENCE_OFFSET);
    int offset = NAPTR_FLAGS_OFFSET;
    std::string flags;
    offset += parse_character_string(rdata + offset, flags);
    std::string services;
    offset += parse_character_string(rdata + offset, services);
    std::string regexp;
    offset += parse_character_string(rdata + offset, regexp);
    std::string replacement;
    offset += parse_domain_name(rdata + offset, replacement);
    if (rdlength < offset)
    {
      throw std::exception();
    }
    rr = (DnsRRecord*)new DnsNaptrRecord(rrname, ttl, order, preference, flags, services, regexp, replacement);
  }
  else
  {
    rr = new DnsRRecord(rrname, rrtype, rrclass, ttl);
  }

  return nlength + RR_HDR_FIXED_SIZE + rdlength;
}

int DnsParser::read_int16(unsigned char* p)
{
  return (((int)(*p)) << 8) + ((int)(*(p+1)));
}

int DnsParser::read_int32(unsigned char* p)
{
  return (((int)(*p)) << 24) + (((int)(*(p+1))) << 16) + (((int)(*(p+2))) << 8) + ((int)(*(p+3)));
}

int DnsParser::label_length(unsigned char* lptr)
{
  return ((*lptr & 0xc0) == 0) ? *lptr & 0x3f : -1;
}

int DnsParser::label_offset(unsigned char* lptr)
{
  return ((*lptr & 0xc0) == 0xc0) ? ((*lptr & 0x3f) << 8) + *(lptr+1) : -1;
}

std::string DnsParser::display_message()
{
  std::ostringstream oss;
  for (int ii = 0; ii < _length; ii += 32)
  {
    oss << std::setw(6) << std::setfill('0') << std::hex << ii;
    oss << ": ";
    for (int jj = 0; jj < 32; ++jj)
    {
      int index = ii + jj;
      if (index < _length)
      {
        oss << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)_data[index];
      }
      else
      {
        oss << "  ";
      }
      if ((jj % 4) == 3)
      {
        oss << " ";
      }
    }
    oss << "   ";
    for (int jj = 0; jj < 32; ++jj)
    {
      int index = ii + jj;
      if (index < _length)
      {
        oss << (char)(isprint(_data[index]) ? _data[index] : '.');
      }
      else
      {
        oss << " ";
      }
      if ((jj % 4) == 3)
      {
        oss << " ";
      }
    }
    oss << std::endl;
  }
  return oss.str();
}

std::string DnsParser::display_records(const std::list<DnsRRecord*>& records)
{
  std::ostringstream oss;
  for (std::list<DnsRRecord*>::const_iterator i = records.begin();
       i != records.end();
       ++i)
  {
    const DnsRRecord* rr = *i;
    oss << rr->to_string() << std::endl;
  }
  return oss.str();
}

