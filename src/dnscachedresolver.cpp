/**
 * @file dnscachedresolver.cpp Implements a DNS caching resolver using C-ARES
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include <sstream>
#include <iomanip>

#include "dnsparser.h"
#include "dnscachedresolver.h"

DnsResult::DnsResult(const std::string& domain,
                     int dnstype,
                     const std::vector<DnsRRecord*>& records,
                     int ttl) :
  _domain(domain),
  _dnstype(dnstype),
  _records(),
  _ttl(ttl)
{
  // Clone the records to the result.
  for (std::vector<DnsRRecord*>::const_iterator i = records.begin();
       i != records.end();
       ++i)
  {
    _records.push_back((*i)->clone());
  }
}

DnsResult::DnsResult(const std::string& domain,
                     int dnstype,
                     int ttl) :
  _domain(domain),
  _dnstype(dnstype),
  _records(),
  _ttl(ttl)
{
}

DnsResult::~DnsResult()
{
  while (!_records.empty())
  {
    delete _records.back();
    _records.pop_back();
  }
}

DnsCachedResolver::DnsCachedResolver(const std::string& dns_server) :
  _cache_lock(PTHREAD_MUTEX_INITIALIZER),
  _cache()
{
  //LOG_STATUS("Creating Cached Resolver using server %s", dns_server.c_str());

  // Initialize the ares library.  This might have already been done by curl
  // but it's safe to do it twice.
  ares_library_init(ARES_LIB_INIT_ALL);

  // Parse the DNS server's IP address.
  if (!inet_aton(dns_server.c_str(), &_dns_server))
  {
    //LOG_ERROR("Failed to parse '%s' as IP address - defaulting to 127.0.0.1", dns_server.c_str());
    (void)inet_aton("127.0.0.1", &_dns_server);
  }

  // We store a DNSResolver in thread-local data, so create the thread-local
  // store.
  pthread_key_create(&_thread_local, (void(*)(void*))&destroy_dns_channel);
}

DnsCachedResolver::~DnsCachedResolver()
{
  DnsChannel* channel = (DnsChannel*)pthread_getspecific(_thread_local);
  if (channel != NULL)
  {
    pthread_setspecific(_thread_local, NULL);
    destroy_dns_channel(channel);
  }

  // Clear the cache.
  clear();
}

DnsResult DnsCachedResolver::dns_query(const std::string& domain,
                                       int dnstype)
{
  DnsChannel* channel = NULL;

  pthread_mutex_lock(&_cache_lock);

  // Expire any cache entries that have passed their TTL.
  expire_cache();

  DnsCacheEntryPtr ce = get_cache_entry(domain, dnstype);

  if (ce == NULL)
  {
    // Create an empty record for this cache entry.
    //LOG_DEBUG("Create cache entry pending query");
    ce = create_cache_entry(domain, dnstype);

    // Get a DNS channel to issue any queries.
    channel = get_dns_channel();

    if (channel != NULL)
    {
      // DNS server is configured, so create a Transaction for the query and
      // execute it.  Mark the entry as pending and take the lock on it
      // before doing this to prevent any other threads sending the same
      // query.
      //LOG_DEBUG("Create and execute DNS query transaction");
      ce->pending_query = true;
      pthread_mutex_lock(&ce->lock);
      DnsTsx* tsx = new DnsTsx(channel, domain, dnstype);
      tsx->execute();

      //LOG_DEBUG("Wait for query responses");
      pthread_mutex_unlock(&_cache_lock);
      wait_for_replies(channel);
      pthread_mutex_lock(&_cache_lock);
      //LOG_DEBUG("Received all query responses");
    }
  }

  // We should now have responses for everything (unless another thread was
  // already doing a query), so get the response.
  if (ce->pending_query)
  {
    // We must release the global lock and let the other thread finish
    // the query.
    // @TODO - may need to do something with reference counting of the
    // DnsCacheEntry to make this watertight.
    pthread_mutex_unlock(&_cache_lock);
    pthread_mutex_lock(&ce->lock);
    pthread_mutex_unlock(&ce->lock);
    pthread_mutex_lock(&_cache_lock);
  }

  /*LOG_DEBUG("Pulling %d records from cache for %s %s",
            ce->records.size(),
            ce->domain.c_str(),
            DnsRRecord::rrtype_to_string(ce->dnstype).c_str());
  */
  DnsResult result(ce->domain,
                   ce->dnstype,
                   ce->records,
                   ce->expires - time(NULL));

  pthread_mutex_unlock(&_cache_lock);

  return result;
}

void DnsCachedResolver::dns_query(const std::vector<std::string>& domains,
                                  int dnstype,
                                  std::vector<DnsResult>& results)
{
  DnsChannel* channel = NULL;

  pthread_mutex_lock(&_cache_lock);

  // Expire any cache entries that have passed their TTL.
  expire_cache();

  // First see if any of the domains need to be queried.
  for (std::vector<std::string>::const_iterator i = domains.begin();
       i != domains.end();
       ++i)
  {
    //LOG_VERBOSE("Check cache for %s type %d", (*i).c_str(), dnstype);
    if (get_cache_entry(*i, dnstype) == NULL)
    {
      //LOG_DEBUG("No entry found in cache");

      // Create an empty record for this cache entry.
      //LOG_DEBUG("Create cache entry pending query");
      DnsCacheEntryPtr ce = create_cache_entry(*i, dnstype);

      if (channel == NULL)
      {
        // Get a DNS channel to issue any queries.
        channel = get_dns_channel();
      }

      if (channel != NULL)
      {
        // DNS server is configured, so create a Transaction for the query
        // and execute it.  Mark the entry as pending and take the lock on
        // it before doing this to prevent any other threads sending the
        // same query.
        //LOG_DEBUG("Create and execute DNS query transaction");
        ce->pending_query = true;
        pthread_mutex_lock(&ce->lock);
        DnsTsx* tsx = new DnsTsx(channel, *i, dnstype);
        tsx->execute();
      }
    }
  }

  if (channel != NULL)
  {
    // Issued some queries, so wait for the replies before processing the
    // request further.
    //LOG_DEBUG("Wait for query responses");
    pthread_mutex_unlock(&_cache_lock);
    wait_for_replies(channel);
    pthread_mutex_lock(&_cache_lock);
    //LOG_DEBUG("Received all query responses");
  }

  // We should now have responses for everything (unless another thread was
  // already doing a query), so loop collecting the responses.
  for (std::vector<std::string>::const_iterator i = domains.begin();
       i != domains.end();
       ++i)
  {
    DnsCacheEntryPtr ce = get_cache_entry(*i, dnstype);

    if (ce != NULL)
    {
      // Found the cache entry, so check whether it is still pending a query.
      if (ce->pending_query)
      {
        // We must release the global lock and let the other thread finish
        // the query.
        // @TODO - may need to do something with reference counting of the
        // DnsCacheEntry to make this watertight.
        pthread_mutex_unlock(&_cache_lock);
        pthread_mutex_lock(&ce->lock);
        pthread_mutex_unlock(&ce->lock);
        pthread_mutex_lock(&_cache_lock);
      }

      // Can now pull the information from the cache entry in to the results.
      /*LOG_DEBUG("Pulling %d records from cache for %s %s",
                ce->records.size(),
                ce->domain.c_str(),
                DnsRRecord::rrtype_to_string(ce->dnstype).c_str());*/

      results.push_back(DnsResult(ce->domain,
                                  ce->dnstype,
                                  ce->records,
                                  ce->expires - time(NULL)));
    }
    else
    {
      // This shouldn't happen, but if it does, return an empty result set.
      //LOG_DEBUG("Return empty result set");
      results.push_back(DnsResult(*i, dnstype, 0));
    }
  }

  pthread_mutex_unlock(&_cache_lock);
}

/// Adds or updates an entry in the cache.
void DnsCachedResolver::add_to_cache(const std::string& domain,
                                     int dnstype,
                                     std::vector<DnsRRecord*>& records)
{
  pthread_mutex_lock(&_cache_lock);

  //LOG_DEBUG("Adding cache entry %s %s",
  //          domain.c_str(), DnsRRecord::rrtype_to_string(dnstype).c_str());

  DnsCacheEntryPtr ce = get_cache_entry(domain, dnstype);

  if (ce == NULL)
  {
    // Create a new cache entry.
    //LOG_DEBUG("Create cache entry");
    ce = create_cache_entry(domain, dnstype);
  }
  else
  {
    // Clear the existing entry of records.
    clear_cache_entry(ce);
  }

  // Copy all the records across to the cache entry.
  for (size_t ii = 0; ii < records.size(); ++ii)
  {
    add_record_to_cache(ce, records[ii]);
  }

  records.clear();

  // Finally make sure the record is in the expiry list.
  add_to_expiry_list(ce);

  pthread_mutex_unlock(&_cache_lock);
}

/// Renders the current contents of the cache to a displayable string.
std::string DnsCachedResolver::display_cache()
{
  std::ostringstream oss;
  pthread_mutex_lock(&_cache_lock);
  expire_cache();
  int now = time(NULL);
  for (DnsCache::const_iterator i = _cache.begin();
       i != _cache.end();
       ++i)
  {
    DnsCacheEntryPtr ce = i->second;
    oss << "Cache entry " << ce->domain
        << " type=" << DnsRRecord::rrtype_to_string(ce->dnstype)
        << " expires=" << ce->expires-now << std::endl;

    for (std::vector<DnsRRecord*>::const_iterator j = ce->records.begin();
         j != ce->records.end();
         ++j)
    {
      oss << (*j)->to_string() << std::endl;
    }
  }
  pthread_mutex_unlock(&_cache_lock);
  return oss.str();
}

/// Clears the cache.
void DnsCachedResolver::clear()
{
  //LOG_DEBUG("Clearing %d cache entries", _cache.size());
  while (!_cache.empty())
  {
    DnsCache::iterator i = _cache.begin();
    DnsCacheEntryPtr ce = i->second;
    //LOG_DEBUG("Deleting cache entry %s %s",
    //          ce->domain.c_str(),
    //         DnsRRecord::rrtype_to_string(ce->dnstype).c_str());
    clear_cache_entry(ce);
    _cache.erase(i);
  }
}

/// Handles a DNS response from the server.
void DnsCachedResolver::dns_response(const std::string& domain,
                                     int dnstype,
                                     int status,
                                     unsigned char* abuf,
                                     int alen)
{
  pthread_mutex_lock(&_cache_lock);

  //LOG_DEBUG("Received DNS response for %s type %s",
  //          domain.c_str(), DnsRRecord::rrtype_to_string(dnstype).c_str());

  // Find the relevant node in the cache.
  DnsCacheEntryPtr ce = get_cache_entry(domain, dnstype);

  // Note that if the request failed or the response failed to parse the expiry
  // time in the cache record is left unchanged.  If it is an existing record
  // it will expire according to the current expiry value, if it is a new
  // record it will expire after DEFAULT_NEGATIVE_CACHE_TTL time.
  if (status == ARES_SUCCESS)
  {
    // Create a message parser and parse the message.
    DnsParser parser(abuf, alen);
    if (parser.parse())
    {
      // Parsing was successful, so clear out any old records, then process
      // the answers and additional data.
      clear_cache_entry(ce);

      while (!parser.answers().empty())
      {
        DnsRRecord* rr = parser.answers().front();
        parser.answers().pop_front();
        if ((rr->rrtype() == ns_t_a) ||
            (rr->rrtype() == ns_t_aaaa))
        {
          // A/AAAA record, so check that RRNAME matches the question.
          if (strcasecmp(rr->rrname().c_str(), domain.c_str()) == 0)
          {
            // RRNAME matches, so add this record to the cache entry.
            add_record_to_cache(ce, rr);
          }
          else
          {
            delete rr;
          }
        }
        else
        {
          // SRV or NAPTR record, so add it to the cache entry.
          add_record_to_cache(ce, rr);
        }
      }

      // Process any additional records returned in the response, creating
      // or updating cache entries.  First we sort the records by cache key.
      std::map<DnsCacheKey, std::list<DnsRRecord*> > sorted;
      while (!parser.additional().empty())
      {
        DnsRRecord* rr = parser.additional().front();
        parser.additional().pop_front();
        if (caching_enabled(rr->rrtype()))
        {
          // Caching is enabled for this record type, so add it to sorted
          // structure.
          sorted[std::make_pair(rr->rrtype(), rr->rrname())].push_back(rr);
        }
        else
        {
          // Caching not enabled for this record, so delete it.
          delete rr;
        }
      }

      // Now update each cache record in turn.
      for (std::map<DnsCacheKey, std::list<DnsRRecord*> >::const_iterator i = sorted.begin();
           i != sorted.end();
           ++i)
      {
        DnsCacheEntryPtr ace = get_cache_entry(i->first.second, i->first.first);
        if (ace == NULL)
        {
          // No existing cache entry, so create one.
          ace = create_cache_entry(i->first.second, i->first.first);
        }
        else
        {
          // Existing cache entry so clear out any existing records.
          clear_cache_entry(ace);
        }
        for (std::list<DnsRRecord*>::const_iterator j = i->second.begin();
             j != i->second.end();
             ++j)
        {
          add_record_to_cache(ace, *j);
        }

        // Finally make sure the record is in the expiry list.
        add_to_expiry_list(ace);
      }
    }
  }

  // If there were no records set cache a negative entry to prevent 
  // immediate retries.
  if ((ce->records.empty()) &&
      (ce->expires == 0))
  {
    // We didn't get an SOA record, so use a default negative cache timeout.
    ce->expires = DEFAULT_NEGATIVE_CACHE_TTL + time(NULL);
  }

  // Add the record to the expiry list.
  add_to_expiry_list(ce);

  // Flag that the cache entry is no longer pending a query, and release
  // the lock on the cache entry.
  ce->pending_query = false;
  pthread_mutex_unlock(&ce->lock);

  pthread_mutex_unlock(&_cache_lock);
}

/// Returns true if the specified RR type should be cached.
bool DnsCachedResolver::caching_enabled(int rrtype)
{
  return (rrtype == ns_t_a) || (rrtype == ns_t_aaaa) || (rrtype == ns_t_srv) || (rrtype == ns_t_naptr);
}

/// Finds an existing cache entry for the specified domain name and NS type.
DnsCachedResolver::DnsCacheEntryPtr DnsCachedResolver::get_cache_entry(const std::string& domain, int dnstype)
{
  DnsCache::iterator i = _cache.find(std::make_pair(dnstype, domain));

  if (i != _cache.end())
  {
    return i->second;
  }

  return NULL;
}

/// Creates a new empty cache entry for the specified domain name and NS type.
DnsCachedResolver::DnsCacheEntryPtr DnsCachedResolver::create_cache_entry(const std::string& domain, int dnstype)
{
  DnsCacheEntryPtr ce = DnsCacheEntryPtr(new DnsCacheEntry());
  pthread_mutex_init(&ce->lock, NULL);
  ce->domain = domain;
  ce->dnstype = dnstype;
  ce->expires = 0;
  ce->pending_query = false;
  _cache[std::make_pair(dnstype, domain)] = ce;

  return ce;
}

/// Adds the cache entry to the expiry list.
void DnsCachedResolver::add_to_expiry_list(DnsCacheEntryPtr ce)
{
  //LOG_DEBUG("Adding %s to cache expiry list with expiry time of %d", ce->domain.c_str(), ce->expires);
  _cache_expiry_list.insert(std::make_pair(ce->expires, std::make_pair(ce->dnstype, ce->domain)));
}

/// Scans for expired cache entries.  In most case records are created then
/// expired, but occasionally a record may be refreshed.  To avoid having
/// to move the record in the expiry list we allow a single record to be
/// reference multiple times in the expiry list, but only expire it when
/// the last reference is reached.
void DnsCachedResolver::expire_cache()
{
  int now = time(NULL);

  while ((!_cache_expiry_list.empty()) &&
         (_cache_expiry_list.begin()->first < now))
  {
    std::multimap<int, DnsCacheKey>::iterator i = _cache_expiry_list.begin();
    //LOG_DEBUG("Removing record for %s (type %d, expiry time %d) from the expiry list", i->second.second.c_str(), i->second.first, i->first);

    // Check that the record really is due for expiry and hasn't been
    // refreshed or already deleted.
    DnsCache::iterator j = _cache.find(i->second);
    if (j != _cache.end())
    {
      DnsCacheEntryPtr ce = j->second;

      if (ce->expires == i->first)
      {
        // Record really is ready to expire, so remove it from the main cache
        // map.
        //LOG_DEBUG("Expiring record for %s (type %d) from the DNS cache", ce->domain.c_str(), ce->dnstype);
        clear_cache_entry(ce);
        _cache.erase(j);
      }
    }

    _cache_expiry_list.erase(i);
  }
}

/// Clears all the records from a cache entry.
void DnsCachedResolver::clear_cache_entry(DnsCacheEntryPtr ce)
{
  while (!ce->records.empty())
  {
    delete ce->records.back();
    ce->records.pop_back();
  }
  ce->expires = 0;
}

/// Adds a DNS RR to a cache entry.
void DnsCachedResolver::add_record_to_cache(DnsCacheEntryPtr ce, DnsRRecord* rr)
{
  //LOG_DEBUG("Adding record to cache entry, TTL=%d, expiry=%ld", rr->ttl(), rr->expires());
  if ((ce->expires == 0) ||
      (ce->expires > rr->expires()))
  {
    //LOG_DEBUG("Update cache entry expiry to %ld", rr->expires());
    ce->expires = rr->expires();
  }
  ce->records.push_back(rr);
}

/// Waits for replies to outstanding DNS queries on the specified channel.
void DnsCachedResolver::wait_for_replies(DnsChannel* channel)
{
  // Wait until the expected number of results has been returned.
  while (channel->pending_queries > 0)
  {
    // Call into ares to get details of the sockets it's using.
    ares_socket_t scks[ARES_GETSOCK_MAXNUM];
    int rw_bits = ares_getsock(channel->channel, scks, ARES_GETSOCK_MAXNUM);

    // Translate these sockets into pollfd structures.
    int num_fds = 0;
    struct pollfd fds[ARES_GETSOCK_MAXNUM];
    for (int fd_idx = 0; fd_idx < ARES_GETSOCK_MAXNUM; fd_idx++)
    {
      struct pollfd* fd = &fds[fd_idx];
      fd->fd = scks[fd_idx];
      fd->events = 0;
      fd->revents = 0;
      if (ARES_GETSOCK_READABLE(rw_bits, fd_idx))
      {
        fd->events |= POLLRDNORM | POLLIN;
      }
      if (ARES_GETSOCK_WRITABLE(rw_bits, fd_idx))
      {
        fd->events |= POLLWRNORM | POLLOUT;
      }
      if (fd->events != 0)
      {
        num_fds++;
      }
    }

    // Calculate the timeout.
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    (void)ares_timeout(channel->channel, NULL, &tv);

    // Wait for events on these file descriptors.
    if (poll(fds, num_fds, tv.tv_sec * 1000 + tv.tv_usec / 1000) != 0)
    {
      // We got at least one event, so find which file descriptor(s) this was on.
      for (int fd_idx = 0; fd_idx < num_fds; fd_idx++)
      {
        struct pollfd* fd = &fds[fd_idx];
        if (fd->revents != 0)
        {
          // Call into ares to notify it of the event.  The interface requires
          // that we pass separate file descriptors for read and write events
          // or ARES_SOCKET_BAD if no event has occurred.
          ares_process_fd(channel->channel,
                          fd->revents & (POLLRDNORM | POLLIN) ? fd->fd : ARES_SOCKET_BAD,
                          fd->revents & (POLLWRNORM | POLLOUT) ? fd->fd : ARES_SOCKET_BAD);
        }
      }
    }
    else
    {
      // No events, so just call into ares with no file descriptor to let it handle timeouts.
      ares_process_fd(channel->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    }
  }
}

DnsCachedResolver::DnsChannel* DnsCachedResolver::get_dns_channel()
{
  // Get the channel from the thread-local data, or create a new one if none
  // found.
  DnsChannel* channel = (DnsChannel*)pthread_getspecific(_thread_local);
  if ((channel == NULL) &&
      (_dns_server.s_addr != 0))
  {
    channel = new DnsChannel;
    channel->pending_queries = 0;
    channel->resolver = this;
    struct ares_options options;
    options.flags = ARES_FLAG_PRIMARY | ARES_FLAG_STAYOPEN;
    options.timeout = 1000;
    options.tries = 1;
    options.ndots = 0;
    options.servers = (struct in_addr*)&_dns_server;
    options.nservers = 1;
    ares_init_options(&channel->channel,
                      &options,
                      ARES_OPT_FLAGS |
                      ARES_OPT_TIMEOUTMS |
                      ARES_OPT_TRIES |
                      ARES_OPT_NDOTS |
                      ARES_OPT_SERVERS);
    pthread_setspecific(_thread_local, channel);
  }

  return channel;
}

void DnsCachedResolver::destroy_dns_channel(DnsChannel* channel)
{
  ares_destroy(channel->channel);
  delete channel;
}

DnsCachedResolver::DnsTsx::DnsTsx(DnsChannel* channel, const std::string& domain, int dnstype) :
  _channel(channel),
  _domain(domain),
  _dnstype(dnstype)
{
}

DnsCachedResolver::DnsTsx::~DnsTsx()
{
}

void DnsCachedResolver::DnsTsx::execute()
{
  ares_query(_channel->channel,
             _domain.c_str(),
             ns_c_in,
             _dnstype,
             DnsTsx::ares_callback,
             this);
  ++_channel->pending_queries;
}

void DnsCachedResolver::DnsTsx::ares_callback(void* arg,
                                              int status,
                                              int timeouts,
                                              unsigned char* abuf,
                                              int alen)
{
  ((DnsTsx*)arg)->ares_callback(status, timeouts, abuf, alen);
}


void DnsCachedResolver::DnsTsx::ares_callback(int status, int timeouts, unsigned char* abuf, int alen)
{
  --_channel->pending_queries;
  _channel->resolver->dns_response(_domain, _dnstype, status, abuf, alen);
}

