/**
 * @file dnscachedresolver.h Definitions for the DNS caching resolver.
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

#ifndef DNSCACHEDRESOLVER_H__
#define DNSCACHEDRESOLVER_H__

#include <string.h>
#include <pthread.h>
#include <time.h>

#include <map>
#include <list>
#include <vector>
#include <memory>

#include <arpa/nameser.h>
#include <ares.h>

#include "dnsrrecords.h"

class DnsResult
{
public:
  DnsResult(const std::string& domain, int dnstype, const std::vector<DnsRRecord*>& records, int ttl);
  DnsResult(const std::string& domain, int dnstype, int ttl);
  ~DnsResult();

  const std::string& domain() const { return _domain; }
  int dnstype() const { return _dnstype; }
  std::vector<DnsRRecord*>& records() { return _records; }
  int ttl() const { return _ttl; }

private:
  std::string _domain;
  int _dnstype;
  std::vector<DnsRRecord*> _records;
  int _ttl;
};

class DnsCachedResolver
{
public:
  DnsCachedResolver(const std::string& dns_server);
  ~DnsCachedResolver();

  /// Queries a single DNS record.
  DnsResult dns_query(const std::string& domain,
                      int dnstype);

  /// Queries multiple DNS records in parallel.
  void dns_query(const std::vector<std::string>& domains,
                 int dnstype,
                 std::vector<DnsResult>& results);

  /// Adds or updates an entry in the cache.
  void add_to_cache(const std::string& domain,
                    int dnstype,
                    std::vector<DnsRRecord*>& records);

  /// Display the current status of the cache.
  std::string display_cache();

  /// Clear the cache
  void clear();

private:

  struct DnsChannel
  {
    ares_channel channel;
    DnsCachedResolver* resolver;
    int pending_queries;
  };

  class DnsTsx
  {
  public:
    DnsTsx(DnsChannel* channel, const std::string& domain, int dnstype);
    ~DnsTsx();;
    void execute();
    static void ares_callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen);
    void ares_callback(int status, int timeouts, unsigned char* abuf, int alen);

  private:
    DnsChannel* _channel;
    std::string _domain;
    int _dnstype;
  };

  struct DnsCacheEntry
  {
    pthread_mutex_t lock;
    bool pending_query;
    std::string domain;
    int dnstype;
    int expires;
    std::vector<DnsRRecord*> records;
  };

  class DnsCacheKeyCompare
  {
  public:
    bool operator()(const std::pair<int, std::string> lhs, const std::pair<int, std::string> rhs)
    {
      if (lhs.first > rhs.first)
      {
        return true;
      }
      else if (lhs.first < rhs.first)
      {
        return false;
      }
      else
      {
        // DNSTYPE is identical, so do case insensitive string compare.
        return strcasecmp(lhs.second.c_str(), rhs.second.c_str()) > 0;
      }
    }
  };

  typedef std::shared_ptr<DnsCacheEntry> DnsCacheEntryPtr;
  typedef std::pair<int, std::string> DnsCacheKey;
  typedef std::multimap<int, DnsCacheKey> DnsCacheExpiryList;
  typedef std::map<DnsCacheKey,
                   DnsCacheEntryPtr,
                   DnsCacheKeyCompare> DnsCache;

  void dns_response(const std::string& domain,
                    int dnstype,
                    int status,
                    unsigned char* abuf,
                    int alen);

  bool caching_enabled(int rrtype);

  DnsCacheEntryPtr get_cache_entry(const std::string& domain, int dnstype);
  DnsCacheEntryPtr create_cache_entry(const std::string& domain, int dnstype);
  void add_to_expiry_list(DnsCacheEntryPtr ce);
  void expire_cache();
  void add_record_to_cache(DnsCacheEntryPtr ce, DnsRRecord* rr);
  void clear_cache_entry(DnsCacheEntryPtr ce);

  DnsChannel* get_dns_channel();
  void wait_for_replies(DnsChannel* channel);
  static void destroy_dns_channel(DnsChannel* channel);

  struct in_addr _dns_server;

  // The thread-local store - used for storing DnsChannels.
  pthread_key_t _thread_local;

  /// The cache itself is held in a map indexed on RRTYPE and RRNAME, and a
  /// multimap indexed on expiry time.
  pthread_mutex_t _cache_lock;
  DnsCache _cache;

  // Expiry is done efficiently by storing pointers to cache entries in a
  // multimap indexed on expiry time.
  DnsCacheExpiryList _cache_expiry_list;

  /// The default negative cache period is set to 5 minutes.
  /// @TODO - may make sense for this to be configured, or even different for
  /// each record type.
  static const int DEFAULT_NEGATIVE_CACHE_TTL = 300;
};

#endif
