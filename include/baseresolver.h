/**
 * @file baseresolver.h  Declaration of base class for DNS resolution.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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

#ifndef BASERESOLVER_H__
#define BASERESOLVER_H__

#include <list>
#include <map>
#include <vector>
//#include <boost/regex.hpp>

//#include "log.h"
#include "dnscachedresolver.h"
#include "ttlcache.h"
//#include "utils.h"
//#include "sas.h"

struct IP46Address
{
  int af;
  union
  {
    struct in_addr ipv4;
    struct in6_addr ipv6;
  } addr;

  int compare(const IP46Address& rhs) const
  {
    if (af != rhs.af)
    {
      return af - rhs.af;
    }
    else if (af == AF_INET)
    {
      return addr.ipv4.s_addr - rhs.addr.ipv4.s_addr;
    }
    else if (af == AF_INET6)
    {
      return memcmp((const char*)&addr.ipv6, (const char*)&rhs.addr.ipv6, sizeof(in6_addr));
    }
    else
    {
      return false;
    }
  }
};


struct AddrInfo
{
    IP46Address address;
    int port;
    int transport;
    sockaddr_storage sipp_ss;

    bool operator<(const AddrInfo& rhs) const {
        int addr_cmp = address.compare(rhs.address);

        if (addr_cmp < 0) {
            return true;
        } else if (addr_cmp > 0) {
            return false;
        } else {
            return (port < rhs.port) || ((port == rhs.port) && (transport < rhs.transport));
        }
    }

    bool operator==(const AddrInfo& rhs) const {
        return (address.compare(rhs.address) == 0) &&
        (port == rhs.port) &&
        (transport == rhs.transport);
    }

    sockaddr_storage* to_sockaddr_storage() {
        memset(&sipp_ss, 0, sizeof(sipp_ss));
        if (address.af == AF_INET) {
            sockaddr_in inet4;
            inet4.sin_family = AF_INET;
            inet4.sin_port = (unsigned short)port;
            inet4.sin_addr = address.addr.ipv4;
            memcpy(&sipp_ss, &inet4, sizeof(inet4));
        }
        return &sipp_ss;
    }
};

/// The BaseResolver class provides common infrastructure for doing DNS
/// resolution, but does not implement a full resolver for any particular
/// protocol.  Specific protocol resolvers are expected to inherit from
/// this class and implement their specific resolution logic using this
/// infrastructure.
class BaseResolver
{
public:
  BaseResolver();
  virtual ~BaseResolver();

  void blacklist(const AddrInfo& ai, int ttl);

  /// Utility function to parse a target name to see if it is a valid IPv4 or IPv6 address.
  bool parse_ip_target(const std::string& target, IP46Address& address);

  void create_naptr_cache(std::map<std::string, int> naptr_services);
  void create_srv_cache();
  void create_blacklist();
  void destroy_naptr_cache();
  void destroy_srv_cache();
  void destroy_blacklist();

  /// Does an SRV record resolution for the specified SRV name, selecting
  // appropriate targets.
  void srv_resolve(const std::string& srv_name,
                   int af,
                   int transport,
                   int retries,
                   std::vector<AddrInfo>& targets,
                   int& ttl);

  /// Does an A/AAAA record resolution for the specified name, selecting
  /// appropriate targets.
  void a_resolve(const std::string& name,
                 int af,
                 int port,
                 int transport,
                 int retries,
                 std::vector<AddrInfo>& targets,
                 int& ttl);
protected:
  /// Converts a DNS A or AAAA record to an IP46Address structure.
  IP46Address to_ip46(const DnsRRecord* rr);

  /// Holds the results of applying NAPTR replacement on a target domain name.
  struct NAPTRReplacement
  {
    std::string replacement;
    std::string flags;
    int transport;
  };

  /// Factory class to handle populating and evicting entries from the
  /// NAPTR cache.
  class NAPTRCacheFactory : public CacheFactory<std::string, NAPTRReplacement*>
  {
  public:
    NAPTRCacheFactory(const std::map<std::string, int>& services,
                      int default_ttl,
                      DnsCachedResolver* dns_client);
    ~NAPTRCacheFactory();

    NAPTRReplacement* get(std::string key, int& ttl);
    void evict(std::string key, NAPTRReplacement* value);

  private:
    static bool compare_naptr_order_preference(DnsNaptrRecord* r1,
                                               DnsNaptrRecord* r2);
/*    bool parse_regex_replace(const std::string& regex_replace,
                             boost::regex& regex,
                             std::string& replace); */

    std::map<std::string, int> _services;
    int _default_ttl;
    DnsCachedResolver* _dns_client;
  };
  NAPTRCacheFactory* _naptr_factory;

  /// The NAPTR cache holds a cache of the results of performing a NAPTR
  /// lookup on a particular target.
  typedef TTLCache<std::string, NAPTRReplacement*> NAPTRCache;
  NAPTRCache* _naptr_cache;

  /// The SRVPriorityList holds the result of an SRV lookup sorted into
  /// priority groups.
  struct SRV
  {
    std::string target;
    int port;
    int priority;
    int weight;
  };
  typedef std::map<int, std::vector<SRV> > SRVPriorityList;

  /// Factory class to handle populating and evicting entries from the SRV
  /// cache.
  class SRVCacheFactory : public CacheFactory<std::string, SRVPriorityList*>
  {
  public:
    SRVCacheFactory(int default_ttl, DnsCachedResolver* dns_client);
    ~SRVCacheFactory();

    SRVPriorityList* get(std::string key, int&ttl);
    void evict(std::string key, SRVPriorityList* value);

  private:
    static bool compare_srv_priority(DnsRRecord* r1, DnsRRecord* r2);

    int _default_ttl;
    DnsCachedResolver* _dns_client;
  };
  SRVCacheFactory* _srv_factory;

  /// The SRV cache holds a cache of SRVPriorityLists indexed on the SRV domain
  /// name (that is, a domain of the form _<service>._<transport>.<target>).
  typedef TTLCache<std::string, SRVPriorityList*> SRVCache;
  SRVCache* _srv_cache;

  /// The SRVWeightedSelector class is a temporary class used to implemented
  /// selection of SRV records at a single priority level according to the
  /// weighting of each record.
  class SRVWeightedSelector
  {
  public:
    /// Constructor.
    SRVWeightedSelector(const std::vector<SRV>& srvs);

    /// Destructor.
    ~SRVWeightedSelector();

    /// Renders the current state of the tree as a string.
    std::string to_string() const;

    /// Selects an entry and sets its weight to zero.
    int select();

    /// Returns the current total weight of the items in the selector.
    int total_weight();

  private:
    std::vector<int> _tree;
  };

  /// The global blacklist holds a list of transport/IP address/port
  /// combinations which have been blacklisted because the destination is
  /// unresponsive (either TCP connection attempts are failing or a UDP
  /// destination is unreachable).
  typedef TTLCache<AddrInfo, bool> BlacklistCache;
  BlacklistCache* _blacklist;

  /// Stores a pointer to the DNS client this resolver should use.
  DnsCachedResolver* _dns_client;

  static const int DEFAULT_TTL = 300;

};

#endif
