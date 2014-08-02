/**
 * @file baseresolver.cpp  Implementation of base class for DNS resolution.
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

#include <time.h>

#include <algorithm>
#include <sstream>
#include <iomanip>

//#include "log.h"
//#include "utils.h"
#include "baseresolver.h"
//#include "sas.h"
//#include "sasevent.h"

BaseResolver::BaseResolver(DnsCachedResolver* dns_client) :
  _srv_factory(),
  _srv_cache(),
  _blacklist(),
  _dns_client(dns_client)
{
}

BaseResolver::~BaseResolver()
{
}

/// Creates the cache for storing SRV results and selectors.
void BaseResolver::create_srv_cache()
{
  // Create the factory and cache for SRV.
  //LOG_DEBUG("Create SRV cache");
  _srv_factory = new SRVCacheFactory(DEFAULT_TTL, _dns_client);
  _srv_cache = new SRVCache(_srv_factory);
}

/// Creates the blacklist of address/port/transport triplets.
void BaseResolver::create_blacklist()
{
  // Create the blacklist (no factory required).
  //LOG_DEBUG("Create black list");
  _blacklist = new BlacklistCache(NULL);
}

void BaseResolver::destroy_srv_cache()
{
    //LOG_DEBUG("Destroy SRV cache");
  delete _srv_cache;
  delete _srv_factory;
}

void BaseResolver::destroy_blacklist()
{
    //LOG_DEBUG("Destroy blacklist");
  delete _blacklist;
}

/// This algorithm selects a number of targets (IP address/port/transport
/// tuples) following the SRV selection algorithm in RFC2782, with a couple
/// of modifications.
/// -  Where SRV records resolve to multiple A/AAAA records, the SRVs at each
///    priority level are round-robined in the selected order, with IP
///    addresses chosen at random.  SRV at the next priority level are only
///    used when all A/AAAA records at higher riority levels have been used.
///    (This behaviour isn't specified in RFC2782, but is a corollary of the
///    requirements that
///    -  retries should initially be to different SRVs
///    -  servers at lower priority levels should not be used if servers from
///       a higher priority level are contactable.
/// -  Targets are checked against a blacklist.  Blacklisted targets are only
///    used if there are insufficient un-blacklisted targets.
///
void BaseResolver::srv_resolve(const std::string& srv_name,
                               int af,
                               int transport,
                               int retries,
                               std::vector<AddrInfo>& targets,
                               int& ttl)
{
  // Accumulate blacklisted targets in case they are needed.
  std::vector<AddrInfo> blacklisted_targets;

  // Clear the list of targets just in case.
  targets.clear();

  // Find/load the relevant SRV priority list from the cache.  This increments
  // a reference, so the list cannot be updated until we have finished with
  // it.
  SRVPriorityList* srv_list = _srv_cache->get(srv_name, ttl);

  std::string targetlist_str;
  std::string blacklist_str;
  std::string added_from_blacklist_str;

  if (srv_list != NULL)
  {
      //LOG_VERBOSE("SRV list found, %d priority levels", srv_list->size());

    // Select the SRV records in priority/weighted order.
    for (SRVPriorityList::const_iterator i = srv_list->begin();
         i != srv_list->end();
         ++i)
    {
        //LOG_VERBOSE("Processing %d SRVs with priority %d", i->second.size(), i->first);

      std::vector<const SRV*> srvs;
      srvs.reserve(i->second.size());

      // Build a cumulative weighted tree for this priority level.
      SRVWeightedSelector selector(i->second);

      // Select entries while there are any with non-zero weights.
      while (selector.total_weight() > 0)
      {
        int ii = selector.select();
        /*LOG_DEBUG("Selected SRV %s:%d, weight = %d",
                  i->second[ii].target.c_str(),
                  i->second[ii].port,
                  i->second[ii].weight);*/
        srvs.push_back(&i->second[ii]);
      }

      // Do A/AAAA record look-ups for the selected SRV targets.
      std::vector<std::string> a_targets;
      std::vector<DnsResult> a_results;

      for (size_t ii = 0; ii < srvs.size(); ++ii)
      {
        a_targets.push_back(srvs[ii]->target);
      }
      //LOG_VERBOSE("Do A record look-ups for %ld SRVs", a_targets.size());
      _dns_client->dns_query(a_targets,
                             (af == AF_INET) ? ns_t_a : ns_t_aaaa,
                             a_results);

      // Now form temporary lists for each SRV target containing the active
      // and blacklisted addresses, in randomized order.
      std::vector<std::vector<IP46Address> > active_addr(srvs.size());
      std::vector<std::vector<IP46Address> > blacklist_addr(srvs.size());

      for (size_t ii = 0; ii < srvs.size(); ++ii)
      {
        DnsResult& a_result = a_results[ii];
        /*LOG_DEBUG("SRV %s:%d returned %ld IP addresses",
                  srvs[ii]->target.c_str(),
                  srvs[ii]->port,
                  a_result.records().size());*/
        std::vector<IP46Address>& active = active_addr[ii];
        std::vector<IP46Address>& blacklist = blacklist_addr[ii];
        active.reserve(a_result.records().size());
        blacklist.reserve(a_result.records().size());

        for (size_t jj = 0; jj < a_result.records().size(); ++jj)
        {
          AddrInfo ai;
          ai.transport = transport;
          ai.port = srvs[ii]->port;
          ai.address = to_ip46(a_result.records()[jj]);

          if (_blacklist->ttl(ai) == 0)
          {
            // Address isn't blacklisted, so copy across to the active list.
            active.push_back(ai.address);
          }
          else
          {
            // Address is blacklisted, so copy to blacklisted list.
            blacklist.push_back(ai.address);
          }
        }

        // Take the smallest ttl returned so far.
        ttl = std::min(ttl, a_result.ttl());

        // Randomize the order of both vectors.
        std::random_shuffle(active.begin(), active.end());
        std::random_shuffle(blacklist.begin(), blacklist.end());
      }

      // Finally select the appropriate number of targets by looping through
      // the SRV records taking one address each time until either we have
      // enough for the number of retries allowed, or we have no more addresses.
      bool more = true;
      while ((targets.size() < (size_t)retries) &&
             (more))
      {
        more = false;
        AddrInfo ai;
        ai.transport = transport;

        for (size_t ii = 0;
             (ii < srvs.size()) && (targets.size() < (size_t)retries);
             ++ii)
        {
          ai.port = srvs[ii]->port;

          if (!active_addr[ii].empty())
          {
            ai.address = active_addr[ii].back();
            active_addr[ii].pop_back();
            targets.push_back(ai);
            char buf[100];
            std::string target = inet_ntop(ai.address.af,
                                           &ai.address.addr,
                                           buf, sizeof(buf));
            std::string tg = "Address - \"" + target + "\". Port - \"" + std::to_string(ai.port) + "\"";
            targetlist_str = targetlist_str + tg;

            //LOG_VERBOSE("Added a server, now have %ld of %d", targets.size(), retries);
          }

          if (!blacklist_addr[ii].empty())
          {
            ai.address = blacklist_addr[ii].back();
            blacklist_addr[ii].pop_back();
            blacklisted_targets.push_back(ai);
            char buf[100];
            std::string blacklistee = inet_ntop(ai.address.af,
                                                &ai.address.addr,
                                                buf, sizeof(buf));
            std::string bl = "[" + blacklistee + ":" + std::to_string(ai.port) + "]";
            blacklist_str = blacklist_str + bl;
          }

          more = more || ((!active_addr[ii].empty()) || (!blacklist_addr[ii].empty()));
        }

      }

      if (targets.size() >= (size_t)retries)
      {
        // We have enough targets so don't move to the next priority level.
        break;
      }
    }

    // If we've gone through the whole set of SRVs and haven't found enough
    // unblacklisted targets, add blacklisted targets.
    if (targets.size() < (size_t)retries)
    {
      size_t to_copy = (size_t)retries - targets.size();

      if (to_copy > blacklisted_targets.size())
      {
        to_copy = blacklisted_targets.size();
      }

      //LOG_VERBOSE("Adding %ld servers from blacklist", to_copy);

      for (size_t ii = 0; ii < to_copy; ++ii)
      {
        targets.push_back(blacklisted_targets[ii]);
        char buf[100];
        std::string blacklistee = inet_ntop(blacklisted_targets[ii].address.af,
                                            &blacklisted_targets[ii].address.addr,
                                            buf, sizeof(buf));
        std::string bl = "[" + blacklistee + ":" + std::to_string(blacklisted_targets[ii].port) + "]";
        added_from_blacklist_str = added_from_blacklist_str + bl;
      }
    }
  }

  _srv_cache->dec_ref(srv_name);
}

/// Does A/AAAA record queries for the specified hostname.
void BaseResolver::a_resolve(const std::string& hostname,
                             int af,
                             int port,
                             int transport,
                             int retries,
                             std::vector<AddrInfo>& targets,
                             int& ttl)
{
  // Clear the list of targets just in case.
  targets.clear();

  // Accumulate blacklisted targets in case they are needed.
  std::vector<AddrInfo> blacklisted_targets;

  // Do A/AAAA lookup.
  DnsResult result = _dns_client->dns_query(hostname, (af == AF_INET) ? ns_t_a : ns_t_aaaa);
  ttl = result.ttl();

  // Randomize the records in the result.
//  LOG_DEBUG("Found %ld A/AAAA records, randomizing", result.records().size());
  std::random_shuffle(result.records().begin(), result.records().end());

  // Loop through the records in the result picking non-blacklisted targets.
  AddrInfo ai;
  ai.transport = transport;
  ai.port = port;
  std::string targetlist_str;
  std::string blacklist_str;
  std::string added_from_blacklist_str;

  for (std::vector<DnsRRecord*>::const_iterator i = result.records().begin();
       i != result.records().end();
       ++i)
  {
    ai.address = to_ip46(*i);
    if (_blacklist->ttl(ai) == 0)
    {
      // Address isn't blacklisted, so copy across to the target list.
      targets.push_back(ai);
      targetlist_str = targetlist_str + (*i)->to_string() + ";";
      //LOG_DEBUG("Added a server, now have %ld of %d", targets.size(), retries);
    }
    else
    {
      // Address is blacklisted, so copy to blacklisted list.
      blacklisted_targets.push_back(ai);
      blacklist_str = blacklist_str + (*i)->to_string() + ";";
    }

    if (targets.size() >= (size_t)retries)
    {
      // We have enough targets so stop looking at records.
      //LOG_DEBUG("Have enough targets");

      break;
    }
  }

  // If we've gone through the whole set of A/AAAA record and haven't found
  // enough unblacklisted targets, add blacklisted targets.
  if (targets.size() < (size_t)retries)
  {
    size_t to_copy = (size_t)retries - targets.size();
    if (to_copy > blacklisted_targets.size())
    {
      to_copy = blacklisted_targets.size();
    }

    //LOG_DEBUG("Adding %ld servers from blacklist", to_copy);

    for (size_t ii = 0; ii < to_copy; ++ii)
    {
      targets.push_back(blacklisted_targets[ii]);
      char buf[100];
      std::string blacklistee = inet_ntop(blacklisted_targets[ii].address.af,
                                          &blacklisted_targets[ii].address.addr,
                                          buf, sizeof(buf));
      std::string bl = "[" + blacklistee + ":" + std::to_string(blacklisted_targets[ii].port) + "]";
      added_from_blacklist_str = added_from_blacklist_str + bl;
    }
  }

}

/// Converts a DNS A or AAAA record to an IP46Address structure.
IP46Address BaseResolver::to_ip46(const DnsRRecord* rr)
{
  IP46Address addr;
  if (rr->rrtype() == ns_t_a)
  {
    // A record.
    DnsARecord* ar = (DnsARecord*)rr;
    addr.af = AF_INET;
    addr.addr.ipv4 = ar->address();
  }
  else
  {
    // AAAA record.
    DnsAAAARecord* ar = (DnsAAAARecord*)rr;
    addr.af = AF_INET6;
    addr.addr.ipv6 = ar->address();
  }

  return addr;
}

/// Adds an address, port, transport tuple to the blacklist.
void BaseResolver::blacklist(const AddrInfo& ai, int ttl)
{
  char buf[100];
  //LOG_DEBUG("Add %s:%d transport %d to blacklist for %d seconds",
//            inet_ntop(ai.address.af, &ai.address.addr, buf, sizeof(buf)),
  //          ai.port, ai.transport, ttl);
  _blacklist->add(ai, true, ttl);
}

 // trim from start
  static inline std::string& ltrim(std::string &s)
  {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                    std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
  }

  // trim from end
  static inline std::string& rtrim(std::string &s)
  {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
  }

  // trim from both ends
  static inline std::string& trim(std::string &s)
  {
    return ltrim(rtrim(s));
  }

/// Parses a target as if it was an IPv4 or IPv6 address and returns the
/// status of the parse.
bool BaseResolver::parse_ip_target(const std::string& target, IP46Address& address)
{
  // Assume the parse fails.
  //LOG_DEBUG("Attempt to parse %s as IP address", target.c_str());
  bool rc = false;

  // Strip start and end white-space.
  std::string ip_target = target;
  trim(ip_target);

  if (inet_pton(AF_INET6, ip_target.c_str(), &address.addr.ipv6) == 1)
  {
    // Parsed the address as a valid IPv6 address.
    address.af = AF_INET6;
    rc = true;
  }
  else if (inet_pton(AF_INET, ip_target.c_str(), &address.addr.ipv4) == 1)
  {
    // Parsed the address as a valid IPv4 address.
    address.af = AF_INET;
    rc = true;
  }

  return rc;
}

BaseResolver::SRVCacheFactory::SRVCacheFactory(int default_ttl,
                                               DnsCachedResolver* dns_client) :
  _default_ttl(default_ttl),
  _dns_client(dns_client)
{
}

BaseResolver::SRVCacheFactory::~SRVCacheFactory()
{
}

BaseResolver::SRVPriorityList* BaseResolver::SRVCacheFactory::get(std::string key, int& ttl)
{
  //LOG_DEBUG("SRV cache factory called for %s", key.c_str());
  SRVPriorityList* srv_list = NULL;

  DnsResult result = _dns_client->dns_query(key, ns_t_srv);

  if (!result.records().empty())
  {
    // We have a result.
    //LOG_DEBUG("SRV query returned %d records", result.records().size());
    srv_list = new SRVPriorityList;
    ttl = result.ttl();

    // Sort the records on priority.
    std::sort(result.records().begin(), result.records().end(), compare_srv_priority);

    // Now rearrange the results in to an SRV priority list (a map of vectors
    // for each priority level).
    for (std::vector<DnsRRecord*>::const_iterator i = result.records().begin();
         i != result.records().end();
         ++i)
    {
      DnsSrvRecord* srv_record = (DnsSrvRecord*)(*i);

      // Get the appropriate priority list of SRVs.
      std::vector<SRV>& plist = (*srv_list)[srv_record->priority()];

      // Add a new entry for this SRV.
      plist.push_back(SRV());
      SRV& srv = plist.back();
      srv.target = srv_record->target();
      srv.port = srv_record->port();
      srv.priority = srv_record->priority();
      srv.weight = srv_record->weight();

      // Adjust the weight.  Any items which have weight 0 are increase to
      // weight of one, and non-zero weights are multiplied by 100.  This gives
      // the right behaviour as per RFC2782 - when all weights are zero we
      // round-robin (but still have the ability to blacklist) and when there
      // are non-zero weights the zero weighted items have a small (but not
      // specified in RFC2782) chance of selection.
      srv.weight = (srv.weight == 0) ? 1 : srv.weight * 100;
    }
  }
  else
  {
    // No results from SRV query, so return no entry with the default TTL
    ttl = _default_ttl;
  }

  return srv_list;
}

void BaseResolver::SRVCacheFactory::evict(std::string key, SRVPriorityList* value)
{
  //LOG_DEBUG("Evict SRV cache %s", key.c_str());
  delete value;
}

bool BaseResolver::SRVCacheFactory::compare_srv_priority(DnsRRecord* r1,
                                                         DnsRRecord* r2)
{
  return (((DnsSrvRecord*)r1)->priority() < ((DnsSrvRecord*)r2)->priority());
}


BaseResolver::SRVWeightedSelector::SRVWeightedSelector(const std::vector<SRV>& srvs) :
  _tree(srvs.size())
{
  // Copy the weights to the tree.
  for (size_t ii = 0; ii < srvs.size(); ++ii)
  {
    _tree[ii] = srvs[ii].weight;
  }

  // Work backwards up the tree accumulating the weights.
  for (size_t ii = _tree.size() - 1; ii >= 1; --ii)
  {
    _tree[(ii - 1)/2] += _tree[ii];
  }
}

BaseResolver::SRVWeightedSelector::~SRVWeightedSelector()
{
}

std::string BaseResolver::SRVWeightedSelector::to_string() const
{
  std::ostringstream oss;
  for (size_t ii = 0; ii < _tree.size(); ++ii)
  {
    oss << _tree[ii];
    if (ii != _tree.size()-1)
    {
      oss << ", ";
    }
  }
  return oss.str();
}

int BaseResolver::SRVWeightedSelector::select()
{
  // Search the tree to find the item with the smallest cumulative weight that
  // is greater than a random number between zero and the total weight of the
  // tree.
  int s = rand() % _tree[0];
  size_t ii = 0;

  while (true)
  {
    // Find the left and right children using the usual tree => array mappings.
    size_t l = 2*ii + 1;
    size_t r = 2*ii + 2;

    if ((l < _tree.size()) && (s < _tree[l]))
    {
      // Selection is somewhere in left subtree.
      ii = l;
    }
    else if ((r < _tree.size()) && (s >= _tree[ii] - _tree[r]))
    {
      // Selection is somewhere in right subtree.
      s -= (_tree[ii] - _tree[r]);
      ii = r;
    }
    else
    {
      // Found the selection.
      break;
    }
  }

  // Calculate the weight of the selected entry by subtracting the weight of
  // its left and right subtrees.
  int weight = _tree[ii] -
               (((2*ii + 1) < _tree.size()) ? _tree[2*ii + 1] : 0) -
               (((2*ii + 2) < _tree.size()) ? _tree[2*ii + 2] : 0);

  // Update the tree to set the weight of the selection to zero so it isn't
  // selected again.
  _tree[ii] -= weight;
  int p = ii;
  while (p > 0)
  {
    p = (p - 1)/2;
    _tree[p] -= weight;
  }

  return ii;
}

int BaseResolver::SRVWeightedSelector::total_weight()
{
  return _tree[0];
}
