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
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           Olivier Jacques
 *           From Hewlett Packard Company.
 *           Shriram Natarajan
 *           Peter Higginson
 *           Eric Miller
 *           Venkatesh
 *           Enrico Hartung
 *           Nasir Khan
 *           Lee Ballard
 *           Guillaume Teissier from FTR&D
 *           Wolfgang Beck
 *           Venkatesh
 *           Vlad Troyanker
 *           Charles P Wright from IBM Research
 *           Amit On from Followap
 *           Jan Andres from Freenet
 *           Ben Evans from Open Cloud
 *           Marc Van Diest from Belgacom
 *           Michael Dwyer from Cibation
 */

#include <iterator>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef PCAPPLAY
#include "send_packets.h"
#endif
#include "sipp.hpp"
#include "assert.h"

#ifdef _USE_OPENSSL
extern  SSL                 *ssl_list[];
extern  struct pollfd        pollfiles[];
extern  SSL_CTX             *sip_trp_ssl_ctx;
#endif

extern  map<string, struct sipp_socket *>     map_perip_fd;

call_map calls;
call_list running_calls;
timewheel paused_calls;

 socket_call_map_map socket_to_calls;

#ifdef PCAPPLAY
/* send_packets pthread wrapper */
void *send_wrapper(void *);
#endif

/************** Call map and management routines **************/
call_map * get_calls()
{
  return & calls;
}

static unsigned int next_number = 1;

unsigned int get_tdm_map_number(unsigned int number) {
  unsigned int nb = 0;
  unsigned int i=0;
  unsigned int interval=0;
  unsigned int random=0;
  bool found = false;

  /* Find a number in the tdm_map which is not in use */
  interval = (tdm_map_a+1) * (tdm_map_b+1) * (tdm_map_c+1);
  random = rand() % interval;
  while ((i<interval) && (!found)) {
    if (tdm_map[(random + i - 1) % interval] == false) {
      nb = (random + i - 1) % interval;
      found = true;
    } 
    i++;
  } 

  if (!found) {
    return 0;
  } else {
    return nb+1;
  } 
}

struct sipp_socket *call::associate_socket(struct sipp_socket *socket) {
  if (socket) {
    this->call_socket = socket;
    add_call_to_socket(socket, this);
  }
  return socket;
}

struct sipp_socket *call::dissociate_socket() {
  struct sipp_socket *ret = this->call_socket;

  remove_call_from_socket(this->call_socket, this);
  this->call_socket = NULL;

  return ret;
}

call * add_call(char * call_id , bool use_ipv6, int userId)
{
  return add_call(call_id, use_ipv6, userId, false /* Is not automatic. */);
}

call * add_call(char * call_id , bool use_ipv6, int userId, bool isAutomatic)
{
  call * new_call;
  unsigned int nb;

  if(!next_number) { next_number ++; }

  if (use_tdmmap) {
    nb = get_tdm_map_number(next_number);
    if (nb != 0) {
      /* Mark the entry in the list as busy */
      tdm_map[nb - 1] = true;
    } else {
      /* Can't create the new call */
      WARNING("Can't create new outgoing call: all tdm_map circuits busy");
      return NULL;
    }
  }

  new_call = new call(call_id, userId, use_ipv6, isAutomatic);

  if(!new_call) {
    ERROR("Memory Overflow");
  }

  /* All calls must exist in the map. */
  calls[std::string(call_id)] = new_call;
  /* All calls start off in the running state. */
  add_running_call(new_call);

  new_call -> number = next_number;
  new_call -> tdm_map_number = nb - 1;

  /* Vital counters update */
  if (!isAutomatic) {
    next_number++;
  } else {
    /* We do not update the call_id counter, for we create here a call */
    /* to answer to an out of call message */
  }
  open_calls++;

  /* Statistics update */
  calls_since_last_rate_change++;
  total_calls ++;

  if(open_calls > open_calls_peak) { 
    open_calls_peak = open_calls;
    open_calls_peak_time = clock_tick / 1000;
  }

  return new_call;
}

call * add_call(char * call_id , struct sipp_socket *socket) {
  call *new_call = add_call(call_id, socket->ss_ipv6, 0 /* No User. */, false /* Not Auto. */);
  new_call->associate_socket(socket);
  return new_call;
}

call * add_call(char * call_id , struct sipp_socket *socket, bool isAutomatic) {
  call *new_call = add_call(call_id, socket->ss_ipv6, 0 /* No User. */, isAutomatic);
  new_call->associate_socket(socket);
  return new_call;
}

call * add_call(int userId, bool ipv6)
{
  static char call_id[MAX_HEADER_LEN];

  char * src = call_id_string;
  int count = 0;

  if(!next_number) { next_number ++; }

  while (*src && count < MAX_HEADER_LEN-1) {
      if (*src == '%') {
          ++src;
          switch(*src++) {
          case 'u':
              count += snprintf(&call_id[count], MAX_HEADER_LEN-count-1,"%u", next_number);
              break;
          case 'p':
              count += snprintf(&call_id[count], MAX_HEADER_LEN-count-1,"%u", pid);
              break;
          case 's':
              count += snprintf(&call_id[count], MAX_HEADER_LEN-count-1,"%s", local_ip);
              break;
          default:      // treat all unknown sequences as %%
              call_id[count++] = '%';
              break;
          }
      } else {
        call_id[count++] = *src++;
      }
  }
  call_id[count] = 0;

  return add_call(call_id, ipv6, userId);
}

call * get_call(char * call_id)
{

  call * call_ptr;

  call_map::iterator call_it ;
  call_it = calls.find(call_map::key_type(call_id));
  call_ptr = (call_it != calls.end()) ? call_it->second : NULL ;

  return call_ptr;
}

void delete_call(char * call_id)
{
  call * call_ptr;
  call_map::iterator call_it ;
  call_it = calls.find(call_map::key_type(call_id));
  call_ptr = (call_it != calls.end()) ? call_it->second : NULL ;

  if(call_ptr) {
    if (use_tdmmap)
      tdm_map[call_ptr->tdm_map_number] = false;
    calls.erase(call_it);

    if (call_ptr->running) {
      remove_running_call(call_ptr);
    } else {
      paused_calls.remove_paused_call(call_ptr);
    }

    delete call_ptr;
    open_calls--;
  } else {
    if (start_calls == 0) {
      ERROR("Call not found");
    }
  }
}

void delete_calls(void)
{
  call * call_ptr;
  
  call_map::iterator call_it ;
  call_it = calls.begin();
  while (call_it != calls.end()) {
    call_ptr = (call_it != calls.end()) ? call_it->second : NULL ;
    WARNING_P1("Aborting call with Call-Id '%s'", call_ptr->id);
    call_ptr->abortCall();
    call_it = calls.begin();
  }

}

/* Routines for running calls. */

/* Get the overall list of running calls. */
call_list * get_running_calls()
{
  return & running_calls;
}

/* Put this call in the run queue. */
void add_running_call(call *call) {
  call->runit = running_calls.insert(running_calls.end(), call);
  call->running = true;
}

/* Remove this call from the run queue. */
bool remove_running_call(call *call) {
  if (!call->running) {
    return false;
    }
  running_calls.erase(call->runit);
  call->running = false;
  return true;
}

/* When should this call wake up? */
unsigned int call_wake(call *call) {
  unsigned int wake = 0;

  if (call->paused_until) {
    wake = call->paused_until;
  }

  if (call->next_retrans && (!wake || (call->next_retrans < wake))) {
    wake = call->next_retrans;
  }

  if (call->recv_timeout && (!wake || (call->recv_timeout < wake))) {
    wake = call->recv_timeout;
  }

  return wake;
}

call_list *timewheel::call2list(call *call) {
  unsigned int wake = call_wake(call);
  unsigned int wake_sigbits = wake;
  unsigned int base_sigbits = wheel_base;

  if (wake == 0) {
    return &forever_list;
  }

  wake_sigbits /= LEVEL_ONE_SLOTS;
  base_sigbits /= LEVEL_ONE_SLOTS;
  if (wake_sigbits == base_sigbits) {
    return &wheel_one[wake % LEVEL_ONE_SLOTS];
  }
  wake_sigbits /= LEVEL_TWO_SLOTS;
  base_sigbits /= LEVEL_TWO_SLOTS;
  if (wake_sigbits == base_sigbits) {
    return &wheel_two[(wake / LEVEL_ONE_SLOTS) % LEVEL_TWO_SLOTS];
  }
  assert(wake_sigbits < LEVEL_THREE_SLOTS);
  return &wheel_three[wake_sigbits];
}

int expire_paused_calls() {
  return paused_calls.expire_paused_calls();
}
int paused_calls_count() {
  return paused_calls.size();
}
void remove_paused_call(call *call) {
  assert(!call->running);
  paused_calls.remove_paused_call(call);
}

/* Iterate through our sorted set of paused calls, removing those that
 * should no longer be paused, and adding them to the run queue. */
int timewheel::expire_paused_calls() {
  int found = 0;

  while (wheel_base < clock_tick) {
    int slot1 = wheel_base % LEVEL_ONE_SLOTS;

    /* Migrate calls from slot2 when we hit 0. */
    if (slot1 == 0) {
      int slot2 = (wheel_base / LEVEL_ONE_SLOTS) % LEVEL_TWO_SLOTS;

      /* If slot2 is also zero, we must migrate calls from slot3 into slot2. */
      if (slot2 == 0) {
	int slot3 = ((wheel_base / LEVEL_ONE_SLOTS) / LEVEL_TWO_SLOTS);
	assert(slot3 < LEVEL_THREE_SLOTS);

	for (call_list::iterator l3it = wheel_three[slot3].begin();
	     l3it != wheel_three[slot3].end();
	     l3it++) {
	  /* Migrate this call to wheel two. */
	  add_paused_call(*l3it, false);
        }

	wheel_three[slot3].clear();
      }

      for (call_list::iterator l2it = wheel_two[slot2].begin();
	  l2it != wheel_two[slot2].end();
	  l2it++) {
	/* Migrate this call to wheel one. */
	add_paused_call(*l2it, false);
      }

      wheel_two[slot2].clear();
    }

    found += wheel_one[slot1].size();
    for(call_list::iterator it = wheel_one[slot1].begin();
	it != wheel_one[slot1].end(); it++) {
      add_running_call(*it);
      count--;
    }
    wheel_one[slot1].clear();

    wheel_base++;
  }

  return found;
}

void timewheel::add_paused_call(call *call, bool increment) {
  call_list *list = call2list(call);
  call->pauseit = list->insert(list->end(), call);
  if (increment) {
    count++;
  }
}

void timewheel::remove_paused_call(call *call) {
  call_list *list = call2list(call);
  list->erase(call->pauseit);
  count--;
}

timewheel::timewheel() {
  count = 0;
  wheel_base = clock_tick;
}

int timewheel::size() {
  return count;
}

/* The caller must delete this list. */
call_list *get_calls_for_socket(struct sipp_socket *socket) {
  call_list *l = new call_list;

  socket_call_map_map::iterator map_it = socket_to_calls.find(socket);

  /* No map defined for this socket. */
  if (map_it == socket_to_calls.end()) {
    return l;
  }

  call_map *socket_call_map = (call_map *) map_it->second;
  call_map::iterator call_it;

  for (call_it = socket_call_map->begin();
       call_it != socket_call_map->end();
       call_it++) {
	l->insert(l->end(), call_it->second);
  }

  return l;
}

void add_call_to_socket(struct sipp_socket *socket, call *call) {
  socket_call_map_map::iterator map_it = socket_to_calls.find(socket);
  /* No map defined for this socket. */
  if (map_it == socket_to_calls.end()) {
    socket_to_calls.insert(socket_map_pair(socket, new call_map));
    map_it = socket_to_calls.find(socket);
    assert(map_it != socket_to_calls.end());
  }

 call_map *socket_call_map = (call_map *) map_it->second;
 socket_call_map->insert(string_call_pair(call->id, call));
}

void remove_call_from_socket(struct sipp_socket *socket, call *call) {
  socket_call_map_map::iterator map_it = socket_to_calls.find(socket);
  /* We must have  a map for this socket. */
  assert(map_it != socket_to_calls.end());

  call_map *socket_call_map = (call_map *) map_it->second;
  call_map::iterator call_it = socket_call_map->find(call->id);
  /* And our call must exist in the map. */
  assert(call_it != socket_call_map->end());
  socket_call_map->erase(call_it);

  /* If we have no more calls, we can delete this entry. */
  if (socket_call_map->begin() == socket_call_map->end()) {
    delete socket_call_map;
    socket_to_calls.erase(map_it);
  }
}

#ifdef PCAPPLAY
/******* Media information management *************************/
/*
 * Look for "c=IN IP4 " pattern in the message and extract the following value
 * which should be IP address
 */
uint32_t get_remote_ip_media(char *msg)
{
    char pattern[] = "c=IN IP4 ";
    char *begin, *end;
    char ip[32];
    begin = strstr(msg, pattern);
    if (!begin) {
      /* Can't find what we're looking at -> return no address */
      return INADDR_NONE;
    }
    begin += sizeof("c=IN IP4 ") - 1;
    end = strstr(begin, "\r\n");
    if (!end)
      return INADDR_NONE;
    memset(ip, 0, 32);
    strncpy(ip, begin, end - begin);
    return inet_addr(ip);
}

/*
 * Look for "c=IN IP6 " pattern in the message and extract the following value
 * which should be IPv6 address
 */
uint8_t get_remote_ipv6_media(char *msg, struct in6_addr addr)
{
    char pattern[] = "c=IN IP6 ";
    char *begin, *end;
    char ip[128];

    memset(&addr, 0, sizeof(addr));
    memset(ip, 0, 128);

    begin = strstr(msg, pattern);
    if (!begin) {
      /* Can't find what we're looking at -> return no address */
      return 0;
    }
    begin += sizeof("c=IN IP6 ") - 1;
    end = strstr(begin, "\r\n");
    if (!end)
      return 0;
    strncpy(ip, begin, end - begin);
    if (!inet_pton(AF_INET6, ip, &addr)) {
      return 0;
    }
    return 1;
}

/*
 * Look for "m=audio " pattern in the message and extract the following value
 * which should be port number
 */
uint16_t get_remote_audio_port_media(char *msg)
{
    char pattern[] = "m=audio ";
    char *begin, *end;
    char number[6];
    begin = strstr(msg, pattern);
    if (!begin) {
      /* m=audio not found */
      return 0;
    }
    begin += sizeof("m=audio ") - 1;
    end = strstr(begin, "\r\n");
    if (!end)
      ERROR("get_remote_audio_port_media: no CRLF found");
    memset(number, 0, sizeof(number));
    strncpy(number, begin, sizeof(number) - 1);
    return atoi(number);
}

/*
 * Look for "m=video " pattern in the message and extract the following value
 * which should be port number
 */
uint16_t get_remote_video_port_media(char *msg)
{
    char pattern[] = "m=video ";
    char *begin, *end;
    char number[5];
    begin = strstr(msg, pattern);
    if (!begin) {
      /* m=video not found */
      return 0;
    }
    begin += sizeof("m=video ") - 1;
    end = strstr(begin, "\r\n");
    if (!end)
      ERROR("get_remote_video_port_media: no CRLF found");
    memset(number, 0, 5);
    strncpy(number, begin, end - begin);
    return atoi(number);
}

/*
 * IPv{4,6} compliant
 */
void call::get_remote_media_addr(char *msg) {
  uint16_t video_port, audio_port;
  if (media_ip_is_ipv6) {
  struct in6_addr ip_media;
    if (get_remote_ipv6_media(msg, ip_media)) {
      audio_port = get_remote_audio_port_media(msg);
      if (audio_port) {
        /* We have audio in the SDP: set the to_audio addr */
        (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_flowinfo = 0;
        (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_scope_id = 0;
        (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_family = AF_INET6;
        (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_port = audio_port;
        (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_addr = ip_media;
      }
      video_port = get_remote_video_port_media(msg);
      if (video_port) {
        /* We have video in the SDP: set the to_video addr */
        (_RCAST(struct sockaddr_in6 *, &(play_args_v.to)))->sin6_flowinfo = 0;
        (_RCAST(struct sockaddr_in6 *, &(play_args_v.to)))->sin6_scope_id = 0;
        (_RCAST(struct sockaddr_in6 *, &(play_args_v.to)))->sin6_family = AF_INET6;
        (_RCAST(struct sockaddr_in6 *, &(play_args_v.to)))->sin6_port = video_port;
        (_RCAST(struct sockaddr_in6 *, &(play_args_v.to)))->sin6_addr = ip_media;
      }
      hasMediaInformation = 1;
    }
  }
  else {
    uint32_t ip_media;
    ip_media = get_remote_ip_media(msg);
    if (ip_media != INADDR_NONE) {
      audio_port = get_remote_audio_port_media(msg);
      if (audio_port) {
        /* We have audio in the SDP: set the to_audio addr */
        (_RCAST(struct sockaddr_in *, &(play_args_a.to)))->sin_family = AF_INET;
        (_RCAST(struct sockaddr_in *, &(play_args_a.to)))->sin_port = audio_port;
        (_RCAST(struct sockaddr_in *, &(play_args_a.to)))->sin_addr.s_addr = ip_media;
      }
      video_port = get_remote_video_port_media(msg);
      if (video_port) {
        /* We have video in the SDP: set the to_video addr */
        (_RCAST(struct sockaddr_in *, &(play_args_v.to)))->sin_family = AF_INET;
        (_RCAST(struct sockaddr_in *, &(play_args_v.to)))->sin_port = video_port;
        (_RCAST(struct sockaddr_in *, &(play_args_v.to)))->sin_addr.s_addr = ip_media;
      }
      hasMediaInformation = 1;
    }
  }
}

#endif

/******* Very simple hash for retransmission detection  *******/

unsigned long hash(char * msg) {
  unsigned long hash = 0;
  int c;

  while (c = *msg++)
    hash = c + (hash << 6) + (hash << 16) - hash;

  return hash;
}

/******************* Call class implementation ****************/

call::call(char * p_id, int userId, bool ipv6, bool isAutomatic) : use_ipv6(ipv6)
{
  memset(this, 0, sizeof(call));
  id = strdup(p_id);
  start_time = clock_tick;
  call_established=false ;
  count_in_stats=true ;
  ack_is_pending=false ;
  last_recv_msg = NULL;
  cseq = base_cseq;
  nb_last_delay = 0;
  tdm_map_number = 0;
  
#ifdef _USE_OPENSSL
  m_ctx_ssl = NULL ;
  m_bio = NULL ;
#endif

  call_remote_socket = 0;
  
  // initialising the CallVariable with the Scenario variable
  int i;
  if (maxVariableUsed >= 0) {
	M_callVariableTable = new CCallVariable *[maxVariableUsed + 1];
  }
  for(i=0; i<=maxVariableUsed; i++)
    {
      if (variableUsed[i]) {
        M_callVariableTable[i] = new CCallVariable();
        if (M_callVariableTable[i] == NULL) {
          ERROR ("call variable allocation failed");
        }
      } else {
        M_callVariableTable[i] = NULL;
      }
    }

  // If not updated by a message we use the start time 
  // information to compute rtd information
  for (i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    start_time_rtd[i] = getmicroseconds();
    rtd_done[i] = false;
  }

  // by default, last action result is NO_ERROR
  last_action_result = call::E_AR_NO_ERROR;

  this->userId = userId;

  /* For automatic answer calls to an out of call request, we must not */
  /* increment the input files line numbers to not disturb */
  /* the input files read mechanism (otherwise some lines risk */
  /* to be systematically skipped */
  if (!isAutomatic) {
    m_lineNumber = new file_line_map();
    for (file_map::iterator file_it = inFiles.begin();
	file_it != inFiles.end();
	file_it++) {
      (*m_lineNumber)[file_it->first] = file_it->second->nextLine(userId);
    }
  }

#ifdef PCAPPLAY
  memset(&(play_args_a.to), 0, sizeof(struct sockaddr_storage));
  memset(&(play_args_v.to), 0, sizeof(struct sockaddr_storage));
  memset(&(play_args_a.from), 0, sizeof(struct sockaddr_storage));
  memset(&(play_args_v.from), 0, sizeof(struct sockaddr_storage));
  hasMediaInformation = 0;
  media_thread = 0;
#endif

  peer_tag = NULL;
  recv_timeout = 0;
  send_timeout = 0;
}

call::~call()
{
  deleted += 1;

  if(comp_state) { comp_free(&comp_state); }

  if(count_in_stats) {
    CStat::instance()->computeStat(CStat::E_ADD_CALL_DURATION, 
                                   clock_tick - start_time);
  }

  sipp_close_socket(dissociate_socket());
  if (call_remote_socket) {
    sipp_close_socket(call_remote_socket);
  }

  /* Deletion of the call variable */
  for(int i=0; i<=maxVariableUsed; i++) {
    if(M_callVariableTable[i] != NULL) {
      delete M_callVariableTable[i] ;
      M_callVariableTable[i] = NULL;
    }
  }
  if(M_callVariableTable) { delete M_callVariableTable; }
  delete m_lineNumber;
  if (userId) {
    freeUsers.push_front(userId);
  }

  if(id) { free(id); }
  if(last_recv_msg) { free(last_recv_msg); }
  if(last_send_msg) { free(last_send_msg); }
  if(peer_tag) { free(peer_tag); }

  if(dialog_route_set) {
       free(dialog_route_set);
  }

  if(next_req_url) {
       free(next_req_url);
  }


#ifdef _USE_OPENSSL
  if(dialog_authentication) {
       free(dialog_authentication);
  }
#endif
  call_established= false ;
}

void call::connect_socket_if_needed()
{
  bool existing;

  if(call_socket) return;
  if(!multisocket) return;

  if(transport == T_UDP) {
    struct sockaddr_storage saddr;

    if(toolMode != MODE_CLIENT)
      return;

    char peripaddr[256];
    if (!peripsocket) {
      if ((associate_socket(new_sipp_call_socket(use_ipv6, transport, &existing))) == NULL) {
	ERROR_NO("Unable to get a UDP socket");
      }
    } else {
      char *tmp = peripaddr;
      getFieldFromInputFile(ip_file, peripfield, tmp);
      map<string, struct sipp_socket *>::iterator i;
      i = map_perip_fd.find(peripaddr);
      if (i == map_perip_fd.end()) {
	// Socket does not exist
	if ((associate_socket(new_sipp_call_socket(use_ipv6, transport, &existing))) == NULL) {
	  ERROR_NO("Unable to get a UDP socket");
	} else {
	  /* Ensure that it stays persistent, because it is recorded in the map. */
	  call_socket->ss_count++;
	  map_perip_fd[peripaddr] = call_socket;
	}
      } else {
	// Socket exists already
	associate_socket(i->second);
	existing = true;
	i->second->ss_count++;
      }
    }
    if (existing) {
	return;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_storage));

    memcpy(&saddr,
	   local_addr_storage->ai_addr,
           SOCK_ADDR_SIZE(
             _RCAST(struct sockaddr_storage *,local_addr_storage->ai_addr)));

    if (use_ipv6) {
      saddr.ss_family       = AF_INET6;
    } else {
      saddr.ss_family       = AF_INET;
    }
    
    if (peripsocket) {
      struct addrinfo * h ;
      struct addrinfo   hints;
      memset((char*)&hints, 0, sizeof(hints));
      hints.ai_flags  = AI_PASSIVE;
      hints.ai_family = PF_UNSPEC;
      getaddrinfo(peripaddr,
                  NULL,
                  &hints,
                  &h); 
      memcpy(&saddr,
             h->ai_addr,
             SOCK_ADDR_SIZE(
                _RCAST(struct sockaddr_storage *,h->ai_addr)));

      if (use_ipv6) {
       (_RCAST(struct sockaddr_in6 *, &saddr))->sin6_port = htons(local_port);
      } else {
       (_RCAST(struct sockaddr_in *, &saddr))->sin_port = htons(local_port);
      }
    }

    if (sipp_bind_socket(call_socket, &saddr, &call_port)) {
      ERROR_NO("Unable to bind UDP socket");
    }
  } else { /* TCP or TLS. */
    struct sockaddr_storage *L_dest = &remote_sockaddr;

    if ((associate_socket(new_sipp_call_socket(use_ipv6, transport, &existing))) == NULL) {
      ERROR_NO("Unable to get a TCP socket");
    }

    if (existing) {
      return;
    }
    
    sipp_customize_socket(call_socket);

    if (use_remote_sending_addr) {
      L_dest = &remote_sending_sockaddr;
    }

    if (sipp_connect_socket(call_socket, L_dest)) {
      if (reset_number > 0) {
        if(errno == EINVAL){
          /* This occurs sometime on HPUX but is not a true INVAL */
          WARNING("Unable to connect a TCP socket, remote peer error");
        } else {
          WARNING("Unable to connect a TCP socket");
        }
        start_calls = 1;
      } else {
	if(errno == EINVAL){
	  /* This occurs sometime on HPUX but is not a true INVAL */
	  ERROR("Unable to connect a TCP socket, remote peer error");
	} else {
	  ERROR_NO("Unable to connect a TCP socket");
	}
      }
    }
  }
}

bool lost(int index)
{
  static int inited = 0;
  double percent = global_lost;

  if(!lose_packets) return false;

  if (scenario[index]->lost >= 0) {
    percent = scenario[index]->lost;
  }

  if (percent == 0) {
    return false;
  }

  if(!inited) {
    srand((unsigned int) time(NULL));
    inited = 1;
  }

  return (((double)rand() / (double)RAND_MAX) < (percent / 100.0));
}

int call::send_raw(char * msg, int index) 
{
  struct sipp_socket *sock;
  int rc;
 
  if (useShortMessagef == 1) {
      struct timeval currentTime;
      GET_TIME (&currentTime);
      char* cs=get_header_content(msg,"CSeq:");
      TRACE_SHORTMSG((s, "%s\tS\t%s\tCSeq:%s\t%s\n",
             CStat::instance()->formatTime(&currentTime),id, cs, get_first_line(msg)));
  }  
 
  if((index!=-1) && (lost(index))) {
    TRACE_MSG((s, "%s message voluntary lost (while sending).", TRANSPORT_TO_STRING(transport)));
    
    if(comp_state) { comp_free(&comp_state); }
    scenario[index] -> nb_lost++;
    return 0;
  }
  
  sock = call_socket;

  if ((use_remote_sending_addr) && (toolMode == MODE_SERVER)) {
    if (!call_remote_socket) {
      struct sockaddr_storage *L_dest = &remote_sending_sockaddr;

      if((call_remote_socket= new_sipp_socket(use_ipv6, transport)) == NULL) {
	ERROR_NO("Unable to get a socket for rsa option");
      }

      sipp_customize_socket(call_remote_socket);

      if(transport != T_UDP) {
	if (sipp_connect_socket(call_remote_socket, L_dest)) {
	  if(errno == EINVAL){
	    /* This occurs sometime on HPUX but is not a true INVAL */
	    ERROR_P1("Unable to connect a %s socket for rsa option, remote peer error", TRANSPORT_TO_STRING(transport));
	  } else {
	    ERROR_NO("Unable to connect a socket for rsa option");
	  }
	}
      }
    }
    sock=call_remote_socket ;
  }

  rc = write_socket(sock, msg, strlen(msg), WS_BUFFER);
  if(rc == -1 && errno == EWOULDBLOCK) {
    return -1;
  }

  if(rc < 0) {
    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    CStat::instance()->computeStat(CStat::E_FAILED_CANNOT_SEND_MSG);
    delete_call(id);
  }

  return rc; /* OK */
}

/* This method is used to send messages that are not */
/* part of the XML scenario                          */
void call::sendBuffer(char * msg)
{
  /* call send_raw but with a special scenario index */
  if (send_raw(msg, -1) < 0) {
    ERROR_NO("Error sending raw message");
  }
}


char * call::compute_cseq(char * src)
{
  static char cseq[MAX_HEADER_LEN];

    /* If we find a CSeq in incoming msg */
  char * last_header = get_last_header("CSeq:");
    if(last_header) {
      int i;
      /* Extract the integer value of the last CSeq */
      last_header = strstr(last_header, ":");
      last_header++;
      while(isspace(*last_header)) last_header++;
      sscanf(last_header,"%d", &i);
      /* Add 1 to the last CSeq value */
      sprintf(cseq, "%s%d",  "CSeq: ", (i+1));
    } else {
      sprintf(cseq, "%s",  "CSeq: 2");
    }
    return cseq;
}

char * call::get_header_field_code(char *msg, char * name)
{
  static char code[MAX_HEADER_LEN];
  char * last_header;
  int i;

    last_header = NULL;
    i = 0;
    /* If we find the field in msg */
    last_header = get_header_content(msg, name);
    if(last_header) {
      /* Extract the integer value of the field */
      while(isspace(*last_header)) last_header++;
      sscanf(last_header,"%d", &i);
      sprintf(code, "%s %d", name, i);
    }
    return code;
}

char * call::get_last_header(char * name)
{
  int len;

  if((!last_recv_msg) || (!strlen(last_recv_msg))) {
    return NULL;
  }

  len = strlen(name);

  /* Ideally this check should be moved to the XML parser so that it is not
   * along a critical path.  We could also handle lowercasing there. */
  if (len > MAX_HEADER_LEN) {
    ERROR_P2("call::get_last_header: Header to parse bigger than %d (%zu)", MAX_HEADER_LEN, strlen(name));
  }

  if (name[len - 1] == ':') {
    return get_header(last_recv_msg, name, false);
  } else {
    char with_colon[MAX_HEADER_LEN];
    sprintf(with_colon, "%s:", name);
    return get_header(last_recv_msg, with_colon, false);
  }
}

char * call::get_header_content(char* message, char * name)
{
  return get_header(message, name, true);
}

/* If content is true, we only return the header's contents. */
char * call::get_header(char* message, char * name, bool content)
{
  /* non reentrant. consider accepting char buffer as param */
  static char last_header[MAX_HEADER_LEN * 10];
  char * src, *dest, *start, *ptr;
  /* Are we searching for a short form header? */
  bool short_form = false;
  bool first_time = true;
  char src_tmp[MAX_HEADER_LEN + 1];

  /* returns empty string in case of error */
  last_header[0] = '\0';

  if((!message) || (!strlen(message))) {
    return last_header;
  }

  /* for safety's sake */
  if (NULL == name || NULL == strrchr(name, ':')) {
    WARNING_P1("Can not searching for header (no colon): %s", name ? name : "(null)");
    return last_header;
  }

  do
  {
    snprintf(src_tmp, MAX_HEADER_LEN, "\n%s", name);
    src = message;
    dest = last_header;

    while(src = strcasestr2(src, src_tmp)) {
      if (content || !first_time) {
        /* just want the header's content */
        src += strlen(name) + 1;
      } else {
	     src++;
      }
      first_time = false;
      ptr = strchr(src, '\n');

      /* Multiline headers always begin with a tab or a space
       * on the subsequent lines */
      while((ptr) &&
	  ((*(ptr+1) == ' ' ) ||
	   (*(ptr+1) == '\t')    )) {
	ptr = strchr(ptr + 1, '\n'); 
      }

      if(ptr) { *ptr = 0; }
      // Add "," when several headers are present
      if (dest != last_header) {
	/* Remove trailing whitespaces, tabs, and CRs */
	while ((dest > last_header) &&
	    ((*(dest-1) == ' ') || (*(dest-1) == '\r') || (*(dest-1) == '\n') || (*(dest-1) == '\t'))) {
	  *(--dest) = 0;
	}

	dest += sprintf(dest, ",");
      }
      dest += sprintf(dest, "%s", src);
      if(ptr) { *ptr = '\n'; }

      src++;
    }
    /* We found the header. */
    if(dest != last_header) {
	break;
    }
    /* We didn't find the header, even in its short form. */
    if (short_form) {
      return last_header;
    }

    /* We should retry with the short form. */
    short_form = true;
    if (!strcasecmp(name, "call-id:")) {
      name = "i:";
    } else if (!strcasecmp(name, "contact:")) {
      name = "m:";
    } else if (!strcasecmp(name, "content-encoding:")) {
      name = "e:";
    } else if (!strcasecmp(name, "content-length:")) {
      name = "l:";
    } else if (!strcasecmp(name, "content-type:")) {
      name = "c:";
    } else if (!strcasecmp(name, "from:")) {
      name = "f:";
    } else if (!strcasecmp(name, "to:")) {
      name = "t:";
    } else if (!strcasecmp(name, "via:")) {
      name = "v:";
    } else {
      /* There is no short form to try. */
      return last_header;
    }
  }
  while (1);

  *(dest--) = 0;

  /* Remove trailing whitespaces, tabs, and CRs */
  while ((dest > last_header) && 
         ((*dest == ' ') || (*dest == '\r')|| (*dest == '\t'))) {
    *(dest--) = 0;
  }
 
  /* Remove leading whitespaces */
  for (start = last_header; *start == ' '; start++);

  /* remove enclosed CRs in multilines */
  /* don't remove enclosed CRs for multiple headers (e.g. Via) (Rhys) */
  while((ptr = strstr(last_header, "\r\n")) != NULL
        && (   *(ptr + 2) == ' ' 
            || *(ptr + 2) == '\r' 
            || *(ptr + 2) == '\t') ) {
    /* Use strlen(ptr) to include trailing zero */
    memmove(ptr, ptr+1, strlen(ptr));
  }

  /* Remove illegal double CR characters */
  while((ptr = strstr(last_header, "\r\r")) != NULL) {
    memmove(ptr, ptr+1, strlen(ptr));
  }
  /* Remove illegal double Newline characters */  
  while((ptr = strstr(last_header, "\n\n")) != NULL) {
    memmove(ptr, ptr+1, strlen(ptr));
  }

  return start;
}

char * call::get_first_line(char * message)
{
  /* non reentrant. consider accepting char buffer as param */
  static char last_header[MAX_HEADER_LEN * 10];
  char * src, *dest;

  /* returns empty string in case of error */
  memset(last_header, 0, sizeof(last_header));

  if((!message) || (!strlen(message))) {
    return last_header;
  }

  src = message;
  dest = last_header;
  
  int i=0;
  while (*src){
    if((*src=='\n')||(*src=='\r')){
      break;
    }
    else
    {
      last_header[i]=*src;
    }
    i++;
    src++;
  }
  
  return last_header;
}

/* Return the last request URI from the To header. On any error returns the
 * empty string.  The caller must free the result. */
char * call::get_last_request_uri ()
{
     char * tmp;
     char * tmp2;
     char * last_request_uri;
     int tmp_len;

     char * last_To = get_last_header("To:");
     if (!last_To) {
	return strdup("");
     }

     tmp = strchr(last_To, '<');
     if (!tmp) {
	return strdup("");
     }
     tmp++;

     tmp2 = strchr(last_To, '>');
     if (!tmp2) {
	return strdup("");
     }

     tmp_len = strlen(tmp) - strlen(tmp2);
     if (tmp_len < 0) {
	return strdup("");
     }

     if(!(last_request_uri = (char *) malloc(tmp_len+1))) ERROR("Cannot allocate !\n");
     memset(last_request_uri, 0, sizeof(last_request_uri));
     if(tmp && (tmp_len > 0)){
       strncpy(last_request_uri, tmp, tmp_len);
     }
     last_request_uri[tmp_len] = '\0';
     return last_request_uri;
  
}

char * call::send_scene(int index, int *send_status)
{
  static char msg_buffer[SIPP_MAX_MSG_SIZE];

#define MAX_MSG_NAME_SIZE 30
  static char msg_name[MAX_MSG_NAME_SIZE];
  char *L_ptr1 ;
  char *L_ptr2 ;

  /* Socket port must be known before string substitution */
  connect_socket_if_needed();

  assert(call_socket);

  if (call_socket->ss_congested) {
    *send_status = -1;
    return NULL;
  }

  if(scenario[index] -> send_scheme) {
    char * dest;
    dest = createSendingMessage(scenario[index] -> send_scheme, index);
    strcpy(msg_buffer, dest);

    if (dest) {
      L_ptr1=msg_name ;
      L_ptr2=msg_buffer ;
      while ((*L_ptr2 != ' ') && (*L_ptr2 != '\n') && (*L_ptr2 != '\t'))  {
        *L_ptr1 = *L_ptr2;
        L_ptr1 ++;
        L_ptr2 ++;
      }
      *L_ptr1 = '\0' ;
    }

    if (strcmp(msg_name,"ACK") == 0) {
      call_established = true ;
      ack_is_pending = false ;
    }

    if(send_status) {
      *send_status = send_raw(msg_buffer, index);
    } else {
      send_raw(msg_buffer, index);
    }
  } else {
    ERROR("Unsupported 'send' message in scenario");
  }

  return msg_buffer;
}

void call::do_bookkeeping(int index) {
  /* If this message increments a counter, do it now. */
  if(int counter = scenario[index] -> counter) {
    CStat::instance()->computeStat(CStat::E_ADD_GENERIC_COUNTER, 1, counter - 1);
  }

  /* If this message can be used to compute RTD, do it now */
  if(int rtd = scenario[index] -> start_rtd) {
    start_time_rtd[rtd - 1] = getmicroseconds();
  }

  if(int rtd = scenario[index] -> stop_rtd) {
    if (!rtd_done[rtd - 1]) {
      unsigned long long start = start_time_rtd[rtd - 1];
      unsigned long long end = getmicroseconds();

      if(dumpInRtt) {
	CStat::instance()->computeRtt(start, end, rtd);
      }

      CStat::instance()->computeStat(CStat::E_ADD_RESPONSE_TIME_DURATION,
	  (end - start) / 1000, rtd - 1);

      if (!scenario[index] -> repeat_rtd) {
	rtd_done[rtd - 1] = true;
      }
    }
  }
}

bool call::next()
{
  int test = scenario[msg_index]->test;
  /* What is the next message index? */
  /* Default without branching: use the next message */
  int new_msg_index = msg_index+1;
  /* If branch needed, overwrite this default */
  if ( scenario[msg_index]->next && 
       ((test == -1) ||
        (test <= maxVariableUsed && M_callVariableTable[test] != NULL && M_callVariableTable[test]->isSet()))
     ) {
    /* Branching possible, check the probability */
    int chance = scenario[msg_index]->chance;
    if ((chance <= 0) || (rand() > chance )) {
      /* Branch == overwrite with the 'next' attribute value */
      new_msg_index = labelArray[scenario[msg_index]->next];
    }
  }
  msg_index=new_msg_index;
  recv_timeout = 0;
  if(msg_index >= scenario_len) {
    // Call end -> was it successful?
    if(call::last_action_result != call::E_AR_NO_ERROR) {
      switch(call::last_action_result) {
        case call::E_AR_REGEXP_DOESNT_MATCH:
          CStat::instance()->computeStat(CStat::E_CALL_FAILED);
          CStat::instance()->computeStat(CStat::E_FAILED_REGEXP_DOESNT_MATCH);
          break;
        case call::E_AR_HDR_NOT_FOUND:
          CStat::instance()->computeStat(CStat::E_CALL_FAILED);
          CStat::instance()->computeStat(CStat::E_FAILED_REGEXP_HDR_NOT_FOUND);
          break;
	case call::E_AR_NO_ERROR:
	case call::E_AR_STOP_CALL:
	  /* Do nothing. */
	  break;
      }
    } else {
      CStat::instance()->computeStat(CStat::E_CALL_SUCCESSFULLY_ENDED);
    }
    delete_call(id);
    return false;
  }

  return run();
}

bool call::run()
{
  bool            bInviteTransaction = false;
  int             actionResult = 0;

  assert(running);

  clock_tick = getmilliseconds();

  if(msg_index >= scenario_len) {
    ERROR_P3("Scenario overrun for call %s (%p) (index = %d)\n",
             id, this, msg_index);
  }

  /* Manages retransmissions or delete if max retrans reached */
  if(next_retrans && (next_retrans < clock_tick)) {
    nb_retrans++;

    if ( (0 == strncmp (last_send_msg, "INVITE", 6)) )
    {
      bInviteTransaction = true;
    }

    if((nb_retrans > (bInviteTransaction ? max_invite_retrans : max_non_invite_retrans)) ||
       (nb_retrans > max_udp_retrans)) {
      scenario[last_send_index] -> nb_timeout ++;
      if (scenario[last_send_index]->on_timeout) {  // action on timeout
          WARNING_P3("Call-Id: %s, timeout on max UDP retrans for message %d, jumping to label %d ", 
                      id, msg_index, scenario[last_send_index]->on_timeout);
          msg_index = labelArray[scenario[last_send_index]->on_timeout];
          next_retrans = 0;
          recv_timeout = 0;
          if (msg_index < scenario_len) {
		return true;
	  }

          // here if asked to go to the last label  delete the call
          CStat::instance()->computeStat(CStat::E_CALL_FAILED);
          CStat::instance()->computeStat(CStat::E_FAILED_MAX_UDP_RETRANS);
          if (default_behavior) {
            // Abort the call by sending proper SIP message
            return(abortCall());
          } else {
            // Just delete existing call
            delete_call(id);
            return false;
          }
      }
      CStat::instance()->computeStat(CStat::E_CALL_FAILED);
      CStat::instance()->computeStat(CStat::E_FAILED_MAX_UDP_RETRANS);
      if (default_behavior) {
        // Abort the call by sending proper SIP message
        WARNING_P1("Aborting call on UDP retransmission timeout for Call-ID '%s'", id);
        return(abortCall());
      } else {
        // Just delete existing call
        delete_call(id);
        return false;
      }
    } else {
      nb_last_delay *= 2;
      if (DEFAULT_T2_TIMER_VALUE < nb_last_delay)
      {
        if (!bInviteTransaction)
        {
          nb_last_delay = DEFAULT_T2_TIMER_VALUE;
      }
      }
      if(send_raw(last_send_msg, last_send_index) < -1) {
        return false;
      }
      scenario[last_send_index] -> nb_sent_retrans++;
      CStat::instance()->computeStat(CStat::E_RETRANSMISSION);
      next_retrans = clock_tick + nb_last_delay;
    }
  }

  if(paused_until) {
    /* Process a pending pause instruction until delay expiration */
    if(paused_until > clock_tick) {
      if (!remove_running_call(this)) {
	ERROR("Tried to remove a running call that wasn't running!\n");
      }
      paused_calls.add_paused_call(this, true);
      return true;
    }
    /* Our pause is over. */
    paused_until = 0;
    return next();
  } else if(scenario[msg_index] -> pause_distribution || scenario[msg_index]->pause_variable) {
    unsigned int pause;
    if (scenario[msg_index]->pause_distribution) {
      pause  = (int)(scenario[msg_index] -> pause_distribution -> sample());
    } else {
      int varId = scenario[msg_index]->pause_variable;
      if(varId <= maxVariableUsed && M_callVariableTable[varId]) {
	pause = (int) M_callVariableTable[varId]->getDouble();
      } else {
	pause = 0;
      }
    }
    if (pause < 0) {
      pause = 0;
    }
    if (pause > INT_MAX) {
      pause = INT_MAX;
    }
    paused_until = clock_tick + pause;

    /* Increment the number of sessions in pause state */
    ++scenario[msg_index]->sessions;
    return run(); /* In case delay is 0 */
  }
#ifdef __3PCC__
  else if(scenario[msg_index] -> M_type == MSG_TYPE_SENDCMD) {
    int send_status;

    if(next_retrans) {
      return true;
    }

    send_status = sendCmdMessage(msg_index);

    if(send_status != 0) { /* Send error */
      return false; /* call deleted */
    }
    scenario[msg_index] -> M_nbCmdSent++;
    next_retrans = 0;
    return(next());
  }
#endif
  else if(scenario[msg_index] -> M_type == MSG_TYPE_NOP) {
    do_bookkeeping(msg_index);
    actionResult = executeAction(NULL, msg_index);
    return(next());
  }

  else if(scenario[msg_index] -> send_scheme) {
    char * msg_snd;
    int send_status;

    /* Do not send a new message until the previous one which had
     * retransmission enabled is acknowledged */

    if(next_retrans) {
      if (!remove_running_call(this)) {
	ERROR("Tried to remove a running call that wasn't running!\n");
      }
      paused_calls.add_paused_call(this, true);
      return true;
    }

    /* Handle counters and RTDs for this message. */
    do_bookkeeping(msg_index);

    /* decide whether to increment cseq or not 
     * basically increment for anything except response, ACK or CANCEL 
     * Note that cseq is only used by the [cseq] keyword, and
     * not by default
     */

    int incr_cseq = 0;
    if (!scenario[msg_index]->send_scheme->isAck() &&
        !scenario[msg_index]->send_scheme->isCancel() &&
        !scenario[msg_index]->send_scheme->isResponse()) {
          ++cseq;
          incr_cseq = 1;
    }
    
    msg_snd = send_scene(msg_index, &send_status);
    if(send_status == -1 && errno == EWOULDBLOCK) {
      if (incr_cseq) --cseq;
      /* Have we set the timeout yet? */
      if (send_timeout) {
	/* If we have actually timed out. */
	if (clock_tick > send_timeout) {
	  WARNING_P2("Call-Id: %s, send timeout on message %d: aborting call",
	      id, msg_index);
	  CStat::instance()->computeStat(CStat::E_CALL_FAILED);
	  CStat::instance()->computeStat(CStat::E_FAILED_TIMEOUT_ON_SEND);
	  if (default_behavior) {
	    return (abortCall());
	  } else {
	    delete_call(id);
	    return false;
	  }
	}
      } else if (scenario[msg_index]->timeout) {
	/* Initialize the send timeout to the per message timeout. */
	send_timeout = clock_tick + scenario[msg_index]->timeout;
      } else if (defl_send_timeout) {
	/* Initialize the send timeout to the global timeout. */
	send_timeout = clock_tick + defl_send_timeout;
      }
      return true; /* No step, nothing done, retry later */
    } else if(send_status < 0) { /* Send error */
      /* The timeout will not be sent, so the timeout is no longer needed. */
      send_timeout = 0;
      return false; /* call deleted */
    }
    /* We have sent the message, so the timeout is no longer needed. */
    send_timeout = 0;

    last_send_index = msg_index;
    last_send_msg = (char *) realloc(last_send_msg, strlen(msg_snd) + 1);
    strcpy(last_send_msg, msg_snd);

    if(last_recv_hash) {
      /* We are sending just after msg reception. There is a great
       * chance that we will be asked to retransmit this message */
      recv_retrans_hash       = last_recv_hash;
      recv_retrans_recv_index = last_recv_index;
      recv_retrans_send_index = msg_index;
    
      /* Prevent from detecting the cause relation between send and recv 
       * in the next valid send */
      last_recv_hash = 0;
    }

    /* Update retransmission information */
    if(scenario[msg_index] -> retrans_delay) {
      if((transport == T_UDP) && (retrans_enabled)) {
        next_retrans = clock_tick + scenario[msg_index] -> retrans_delay;
        nb_retrans = 0;
        nb_last_delay = scenario[msg_index]->retrans_delay;
      }
    } else {
      next_retrans = 0;
    }
    
#ifdef PCAPPLAY
    actionResult = executeAction(msg_snd, msg_index);
#endif
    
    /* Update scenario statistics */
    scenario[msg_index] -> nb_sent++;

    return next();
  } else if (scenario[msg_index]->M_type == MSG_TYPE_RECV
#ifdef __3PCC__
         || scenario[msg_index]->M_type == MSG_TYPE_RECVCMD
#endif
                                                 ) {
    if (recv_timeout) {
      if(recv_timeout > clock_tick || recv_timeout > getmilliseconds()) {
	if (!remove_running_call(this)) {
	  ERROR("Tried to remove a running call that wasn't running!\n");
	}
	paused_calls.add_paused_call(this, true);
	return true;
      }
      recv_timeout = 0;
      ++scenario[msg_index]->nb_timeout;
      if (scenario[msg_index]->on_timeout == 0) {
        // if you set a timeout but not a label, the call is aborted 
        WARNING_P2("Call-Id: %s, receive timeout on message %d without label to jump to (ontimeout attribute): aborting call", 
                   id, msg_index);
        CStat::instance()->computeStat(CStat::E_CALL_FAILED);
        CStat::instance()->computeStat(CStat::E_FAILED_TIMEOUT_ON_RECV);
        if (default_behavior) {
          return (abortCall());
        } else {
          delete_call(id);
          return false;
        }
      }
      WARNING_P3("Call-Id: %s, receive timeout on message %d, jumping to label %d", 
                  id, msg_index, scenario[msg_index]->on_timeout);
      msg_index = labelArray[scenario[msg_index]->on_timeout];
      recv_timeout = 0;
      if (msg_index < scenario_len) return true;
      // special case - the label points to the end - finish the call
      CStat::instance()->computeStat(CStat::E_CALL_FAILED);
      CStat::instance()->computeStat(CStat::E_FAILED_TIMEOUT_ON_RECV);
      if (default_behavior) {
        return (abortCall());
      } else {
        delete_call(id);
        return false;
      }
    } else if ((scenario[msg_index]->timeout) || (defl_recv_timeout)) {
      if (scenario[msg_index]->timeout)
        // If timeout is specified on message receive, use it
        recv_timeout = getmilliseconds() + scenario[msg_index]->timeout;
      else
        // Else use the default timeout if specified
        recv_timeout = getmilliseconds() + defl_recv_timeout;
	return true;
    } else {
	/* We are going to wait forever. */
	if (!remove_running_call(this)) {
	  ERROR("Tried to remove a running call that wasn't running!\n");
	}
	paused_calls.add_paused_call(this, true);
    }
  }
  return true;
}

bool call::process_unexpected(char * msg)
{
  char buffer[MAX_HEADER_LEN];
  char *desc = buffer;

  scenario[msg_index] -> nb_unexp++;

  if (default_behavior) {
	desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "Aborting ");
  } else {
	desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "Continuing ");
  }
  desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "call on unexpected message for Call-Id '%s': ", id);

  if (scenario[msg_index] -> M_type == MSG_TYPE_RECV) {
    if (scenario[msg_index] -> recv_request) {
      desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while expecting '%s' ", scenario[msg_index] -> recv_request);
    } else {
      desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while expecting '%d' ", scenario[msg_index] -> recv_response);
    }
  } else if (scenario[msg_index] -> M_type == MSG_TYPE_SEND) {
      desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while sending ");
  } else if (scenario[msg_index] -> M_type == MSG_TYPE_PAUSE) {
      desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while pausing ");
  } else if (scenario[msg_index] -> M_type == MSG_TYPE_SENDCMD) {
      desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while sending command ");
  } else if (scenario[msg_index] -> M_type == MSG_TYPE_RECVCMD) {
      desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while expecting command ");
  } else {
      desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while in message type %d ", scenario[msg_index]->M_type);
  }
  desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "(index %d)", msg_index);

  WARNING_P2("%s, received '%s'", buffer, msg);

  TRACE_MSG((s, "-----------------------------------------------\n"
             "Unexpected %s message received:\n\n%s\n",
             TRANSPORT_TO_STRING(transport),
             msg));

  if (default_behavior) {
    // if twin socket call => reset the other part here 
    if (twinSippSocket && (msg_index > 0)) {
      //WARNING_P2("call-ID '%s', internal-cmd: abort_call %s",id, "");
      sendCmdBuffer
	(createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n\n", -1));
    }

    // usage of last_ keywords => for call aborting
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(msg) + 1);
    strcpy(last_recv_msg, msg);

    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    CStat::instance()->computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
    return (abortCall());
  } else {
    // Do not abort call nor send anything in reply if default behavior is disabled
    return false;
  }
}

bool call::abortCall()
{
  int is_inv;

  char * src_send = NULL ;
  char * src_recv = NULL ;

  if (last_send_msg != NULL) {
    is_inv = !strncmp(last_send_msg, "INVITE", 6);
  } else {
    is_inv = false;
  }  
  if ((toolMode != MODE_SERVER) && (msg_index > 0)) {
    if ((call_established == false) && (is_inv)) {
      src_recv = last_recv_msg ;
      char   L_msg_buffer[SIPP_MAX_MSG_SIZE];
      L_msg_buffer[0] = '\0';
      char * L_param = L_msg_buffer;

      // Answer unexpected errors (4XX, 5XX and beyond) with an ACK 
      // Contributed by F. Tarek Rogers
      if((src_recv) && (get_reply_code(src_recv) >= 400)) {
        strcpy(L_param,  "ACK [last_Request_URI] SIP/2.0\n");
        sprintf(L_param, "%s%s", L_param, "[last_Via]\n");
        sprintf(L_param, "%s%s", L_param, "[last_From]\n");
        sprintf(L_param, "%s%s", L_param, "[last_To]\n");
        sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
        char * cseq;
        cseq = get_header_field_code(src_recv,(char *) "CSeq:");
        if (cseq != NULL) {
          sprintf(L_param, "%s%s ACK\n", L_param, cseq);
        }
        sprintf(L_param, "%s%s", L_param, "Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n");
        sprintf(L_param, "%s%s", L_param, "Max-Forwards: 70\n");
        sprintf(L_param, "%s%s", L_param, "Subject: Performance Test\n");
        sprintf(L_param, "%s%s", L_param, "Content-Length: 0\n\n");

        sendBuffer(createSendingMessage((char*)(L_param), -2));

      } else if (src_recv) {
        /* Call is not established and the reply is not a 4XX, 5XX */
        /* And we already received a message. */
        if (ack_is_pending == true) {
          char * cseq = NULL;

          /* If an ACK is expected from the other side, send it
           * and send a BYE afterwards                           */
          ack_is_pending = false;
          /* Send an ACK */
          strcpy(L_param,  "ACK [last_Request_URI] SIP/2.0\n");
          sprintf(L_param, "%s%s", L_param, "Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n");
          sprintf(L_param, "%s%s", L_param, "[last_From]\n");
          sprintf(L_param, "%s%s", L_param, "[last_To]\n");
          sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
          src_send = last_send_msg ;
          cseq = get_header_field_code(src_recv,"CSeq:");
          if (cseq != NULL) {
            sprintf(L_param, "%s%s ACK\n", L_param, cseq);
          }
		    sprintf(L_param, "%s%s", L_param, "Max-Forwards: 70\n");
          sprintf(L_param, "%s%s", L_param, "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
          sprintf(L_param, "%s%s", L_param, "Content-Length: 0\n\n");
          sendBuffer(createSendingMessage((char*)(L_param),-1));
          
          /* Send the BYE */
          cseq = NULL;
          strcpy(L_param,  "BYE [last_Request_URI] SIP/2.0\n");
          sprintf(L_param, "%s%s", L_param, "Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n");
          sprintf(L_param, "%s%s", L_param, "[last_From]\n");
          sprintf(L_param, "%s%s", L_param, "[last_To]\n");
          sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
          cseq = compute_cseq(src_recv);
          if (cseq != NULL) {
            sprintf(L_param, "%s%s BYE\n", L_param, compute_cseq(src_recv));
          }
		  sprintf(L_param, "%s%s", L_param, "Max-Forwards: 70\n");
          sprintf(L_param, "%s%s", L_param,  "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
          sprintf(L_param, "%s%s", L_param,  "Content-Length: 0\n\n");
          sendBuffer(createSendingMessage((char*)(L_param),-1));
        } else {
          /* Send a CANCEL */
          strcpy(L_param,  "CANCEL [last_Request_URI] SIP/2.0\n");
          sprintf(L_param, "%s%s", L_param, "[last_Via]\n");
          sprintf(L_param, "%s%s", L_param, "[last_From]\n");
          sprintf(L_param, "%s%s", L_param, "[last_To]\n");
          sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
          sprintf(L_param, "%sCSeq: 1 CANCEL\n", L_param);
		    sprintf(L_param, "%s%s", L_param, "Max-Forwards: 70\n");
          sprintf(L_param, "%s%s", L_param, "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
          sprintf(L_param, "%s%s", L_param, "Content-Length: 0\n\n");
          sendBuffer(createSendingMessage((char*)(L_param),-2));
        }
      } else {
        /* Call is not established and the reply is not a 4XX, 5XX */
        /* and we didn't received any message. This is the case when */
        /* we are aborting after having send an INVITE and not received */
        /* any answer. */
        /* Do nothing ! */
      }
    } else if (last_recv_msg) {
      /* The call may not be established, if we haven't yet received a message,
       * because the earlier check depends on the first message being an INVITE
       * (although it could be something like a message message, therefore we
       * check that we received a message. */
      char * src_recv = last_recv_msg ;
      char   L_msg_buffer[SIPP_MAX_MSG_SIZE];
      L_msg_buffer[0] = '\0';
      char * L_param = L_msg_buffer;
      strcpy(L_param,  "BYE [last_Request_URI] SIP/2.0\n");
      sprintf(L_param, "%s%s", L_param, "Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n");
      sprintf(L_param, "%s%s", L_param, "[last_From:]\n");
      sprintf(L_param, "%s%s", L_param, "[last_To:]\n");
      sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
      char * cseq;
      cseq = compute_cseq(src_recv);
      if (cseq != NULL) {
        sprintf(L_param, "%s%s BYE\n", L_param, compute_cseq(src_recv));
      }
	   sprintf(L_param, "%s%s", L_param, "Max-Forwards: 70\n");
      sprintf(L_param, "%s%s", L_param,  "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
      sprintf(L_param, "%s%s", L_param,  "Content-Length: 0\n\n");
      sendBuffer(createSendingMessage((char*)(L_param),-1));
    }
  }

  delete_call(id);
  return false;
}

bool call::rejectCall()
{
  CStat::instance()->computeStat(CStat::E_CALL_FAILED);
  CStat::instance()->computeStat(CStat::E_FAILED_CALL_REJECTED);
  delete_call(id);
  return false;
}


int call::sendCmdMessage(int index)
{
  char * dest;
  char delimitor[2];
  delimitor[0]=27;
  delimitor[1]=0;

  /* 3pcc extended mode */
  char * peer_dest;
  struct sipp_socket **peer_socket;

  if(scenario[index] -> M_sendCmdData) {
    // WARNING_P1("---PREPARING_TWIN_CMD---%s---", scenario[index] -> M_sendCmdData); 
    dest = createSendingMessage(scenario[index] -> M_sendCmdData, -1);
    strcat(dest, delimitor);
    //WARNING_P1("---SEND_TWIN_CMD---%s---", dest); 

    int rc;

    /* 3pcc extended mode */
    peer_dest = scenario[index]->peer_dest;
    if(peer_dest){ 
      peer_socket = get_peer_socket(peer_dest);
      rc = write_socket(*peer_socket, dest, strlen(dest), WS_BUFFER);
    }else {
      rc = write_socket(twinSippSocket, dest, strlen(dest), WS_BUFFER);
    }
    if(rc <  0) {
      CStat::instance()->computeStat(CStat::E_CALL_FAILED);
      CStat::instance()->computeStat(CStat::E_FAILED_CMD_NOT_SENT);
      delete_call(id);
      return(-1);
    }

    return(0);
  }
  else
    return(-1);
}


int call::sendCmdBuffer(char* cmd)
{
  char * dest;
  char delimitor[2];
  int  rc;

  delimitor[0]=27;
  delimitor[1]=0;

  dest = cmd ;

  strcat(dest, delimitor);

  rc = write_socket(twinSippSocket, dest, strlen(dest), WS_BUFFER);
  if(rc <  0) {
    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    CStat::instance()->computeStat(CStat::E_FAILED_CMD_NOT_SENT);
    delete_call(id);
    return(-1);
  }

  return(0);
}

char* call::createSendingMessage(SendingMessage *src, int P_index)
{
  char * length_marker = NULL;
  char * auth_marker = NULL;
  MessageComponent *auth_comp = NULL;
  bool auth_comp_allocated = false;
  int    len_offset = 0;
  static char msg_buffer[SIPP_MAX_MSG_SIZE+2];
  char *dest = msg_buffer;
  bool supresscrlf = false;

  *dest = '\0';

  for (int i = 0; i < src->numComponents(); i++) {
    MessageComponent *comp = src->getComponent(i);
    int left = sizeof(msg_buffer) - (dest - msg_buffer);
    switch(comp->type) {
      case E_Message_Literal:
	if (supresscrlf) {
	  char *ptr = comp->literal;
	  while (isspace(*ptr)) ptr++;
	  dest += snprintf(dest, left, "%s", ptr);
	  supresscrlf = false;
	} else {
	  dest += snprintf(dest, left, "%s", comp->literal);
	}
	break;
      case E_Message_Remote_IP:
	dest += snprintf(dest, left, "%s", remote_ip_escaped);
	break;
      case E_Message_Remote_Port:
	dest += snprintf(dest, left, "%d", remote_port + comp->offset);
	break;
      case E_Message_Local_IP:
	dest += snprintf(dest, left, "%s", local_ip_escaped);
	break;
      case E_Message_Local_Port:
	int port;
	if((transport == T_UDP) && (multisocket) && (toolMode != MODE_SERVER)) {
	  port = call_port;
	} else {
	  port =  local_port;
	}
	dest += snprintf(dest, left, "%d", port + comp->offset);
	break;
      case E_Message_Transport:
	dest += snprintf(dest, left, "%s", TRANSPORT_TO_STRING(transport));
	break;
      case E_Message_Local_IP_Type:
	dest += snprintf(dest, left, "%s", (local_ip_is_ipv6 ? "6" : "4"));
	break;
      case E_Message_Server_IP: {
	  /* We should do this conversion once per socket creation, rather than
	   * repeating it every single time. */
	  struct sockaddr_storage server_sockaddr;

	  sipp_socklen_t len = SOCK_ADDR_SIZE(&server_sockaddr);
	  getsockname(call_socket->ss_fd,
	      (sockaddr *)(void *)&server_sockaddr, &len);

	  if (server_sockaddr.ss_family == AF_INET6) {
	    char * temp_dest;
	    temp_dest = (char *) malloc(INET6_ADDRSTRLEN);
	    memset(temp_dest,0,INET6_ADDRSTRLEN);
	    inet_ntop(AF_INET6,
		&((_RCAST(struct sockaddr_in6 *,&server_sockaddr))->sin6_addr),
		temp_dest,
		INET6_ADDRSTRLEN);
	    dest += snprintf(dest, left, "%s",temp_dest);
	  } else {
	    dest += snprintf(dest, left, "%s",
		inet_ntoa((_RCAST(struct sockaddr_in *,&server_sockaddr))->sin_addr));
	  }
	}
	break;
      case E_Message_Media_IP:
	dest += snprintf(dest, left, "%s", media_ip_escaped);
	break;
      case E_Message_Media_Port:
      case E_Message_Auto_Media_Port: {
	int port = media_port + comp->offset;
	if (comp->type == E_Message_Auto_Media_Port) {
	  port = media_port + (4 * (number - 1)) % 10000 + comp->offset;
	}
#ifdef PCAPPLAY
	char *begin = dest;
	while (begin > msg_buffer) {
	  if (*begin == '\n') {
	    break;
	  }
	  begin--;
	}
	if (begin == msg_buffer) {
	  ERROR("Can not find beginning of a line for the media port!\n");
	}
	if (strstr(begin, "audio")) {
	  if (media_ip_is_ipv6) {
	    (_RCAST(struct sockaddr_in6 *, &(play_args_a.from)))->sin6_port = port;
	  } else {
	    (_RCAST(struct sockaddr_in *, &(play_args_a.from)))->sin_port = port;
	  }
	} else if (strstr(begin, "video")) {
	  if (media_ip_is_ipv6) {
	    (_RCAST(struct sockaddr_in6 *, &(play_args_v.from)))->sin6_port = port;
	  } else {
	    (_RCAST(struct sockaddr_in *, &(play_args_v.from)))->sin_port = port;
	  }
	} else {
	  ERROR_P1("media_port keyword with no audio or video on the current line (%s)", begin);
	}
#endif
	dest += sprintf(dest, "%u", port);
	break;
      }
      case E_Message_Media_IP_Type:
	dest += snprintf(dest, left, "%s", (media_ip_is_ipv6 ? "6" : "4"));
	break;
      case E_Message_Call_Number:
	dest += snprintf(dest, left, "%u", number);
	break;
      case E_Message_Call_ID:
	dest += snprintf(dest, left, "%s", id);
	break;
      case E_Message_CSEQ:
	dest += snprintf(dest, left, "%u", cseq + comp->offset);
	break;
      case E_Message_PID:
	dest += snprintf(dest, left, "%d", pid);
	break;
      case E_Message_Service:
	dest += snprintf(dest, left, "%s", service);
	break;
      case E_Message_Branch:
	/* Branch is magic cookie + call number + message index in scenario */
	if(P_index == -2){
	  dest += snprintf(dest, left, "z9hG4bK-%u-%u-%d", pid, number, msg_index-1 + comp->offset);
	} else {
	  dest += snprintf(dest, left, "z9hG4bK-%u-%u-%d", pid, number, P_index + comp->offset);
	}
	break;
      case E_Message_Index:
	dest += snprintf(dest, left, "%d", P_index);
	break;
      case E_Message_Next_Url:
	if (next_req_url) {
	  dest += sprintf(dest, "%s", next_req_url);
	}
	break;
      case E_Message_Len:
	length_marker = dest;
	dest += snprintf(dest, left, "     ");
	len_offset = comp->offset;
	break;
      case E_Message_Authentication:
	if (auth_marker) {
	  ERROR("Only one [authentication] keyword is currently supported!\n");
	}
	auth_marker = dest;
	dest += snprintf(dest, left, "[authentication place holder]");
	auth_comp = comp;
	break;
      case E_Message_Peer_Tag_Param:
	if(peer_tag) {
	  dest += snprintf(dest, left, ";tag=%s", peer_tag);
	}
	break;
      case E_Message_Routes:
	if (dialog_route_set) {
	  dest += sprintf(dest, "Route: %s", dialog_route_set);
	} else if (*(dest - 1) == '\n') {
	  supresscrlf = true;
	}
	break;
      case E_Message_ClockTick:
	dest += snprintf(dest, left, "%lu", clock_tick);
	break;
      case E_Message_Variable: {
	 int varId = comp->varId;
	 if(varId <= maxVariableUsed) {
	   if(M_callVariableTable[varId] != NULL) {
	     if(M_callVariableTable[varId]->isSet()) {
	       if (M_callVariableTable[varId]->isRegExp()) {
		 dest += sprintf(dest, "%s", M_callVariableTable[varId]->getMatchingValue());
	       } else if (M_callVariableTable[varId]->isDouble()) {
		 dest += sprintf(dest, "%lf", M_callVariableTable[varId]->getDouble());
	       } else if (M_callVariableTable[varId]->isString()) {
		 dest += sprintf(dest, "%s", M_callVariableTable[varId]->getString());
	       } else if (M_callVariableTable[varId]->isBool()) {
		 dest += sprintf(dest, "true");
	       }
	     } else if (M_callVariableTable[varId]->isBool()) {
	       dest += sprintf(dest, "false");
	     }
	   }
	 }
	 break;
      }
      case E_Message_Fill: {
        int varId = comp->varId;
	int length = 0;
	if(varId <= maxVariableUsed && M_callVariableTable[varId]) {
	  length = (int) M_callVariableTable[varId]->getDouble();
	  if (length < 0) {
	    length = 0;
	  }
	}
	char *filltext = comp->literal;
	int filllen = strlen(filltext);
	if (filllen == 0) {
	  ERROR("Internal error: [fill] keyword has zero-length text.");
	}
	for (int i = 0, j = 0; i < length; i++, j++) {
	  *dest++ = filltext[j % filllen];
	}
	*dest = '\0';
	break;
      }
      case E_Message_Injection: {
	char *orig_dest = dest;
	getFieldFromInputFile(comp->comp_param.field_param.filename, comp->comp_param.field_param.field, dest);
	/* We are injecting an authentication line. */
	if (char *tmp = strstr(orig_dest, "[authentication")) {
	  if (auth_marker) {
	    ERROR("Only one [authentication] keyword is currently supported!\n");
	  }
	  auth_marker = tmp;
	  auth_comp = (struct MessageComponent *)calloc(1, sizeof(struct MessageComponent));
	  if (!auth_comp) { ERROR("Out of memory!"); }
	  auth_comp_allocated = true;

	  tmp = strchr(auth_marker, ']');
	  char c = *tmp;
	  *tmp = '\0';
	  SendingMessage::parseAuthenticationKeyword(auth_comp, auth_marker);
	  *tmp = c;
	}
	if (*(dest - 1) == '\n') {
	  supresscrlf = true;
	}
	break;
      }
      case E_Message_Last_Header: {
	char * last_header = get_last_header(comp->literal);
	if(last_header) {
	  dest += sprintf(dest, "%s", last_header);
	}
	if (*(dest - 1) == '\n') {
	  supresscrlf = true;
	}
	break;
      }
      case E_Message_Last_Request_URI: {
       char * last_request_uri = get_last_request_uri();
       dest += sprintf(dest, "%s", last_request_uri);
       free(last_request_uri);
   break;
      }
      case E_Message_TDM_Map:
	if (!use_tdmmap)
	  ERROR("[tdmmap] keyword without -tdmmap parameter on command line");
	dest += snprintf(dest, left, "%d.%d.%d/%d",
	    tdm_map_x+(int((tdm_map_number)/((tdm_map_b+1)*(tdm_map_c+1))))%(tdm_map_a+1),
	    tdm_map_h,
	    tdm_map_y+(int((tdm_map_number)/(tdm_map_c+1)))%(tdm_map_b+1),
	    tdm_map_z+(tdm_map_number)%(tdm_map_c+1)
	    );
	break;
    }
  }
  /* Need the body for length and auth-int calculation */
  char *body;
  if (length_marker || auth_marker) {
    body = strstr(msg_buffer, "\r\n\r\n");
  }

  /* Fix up the length. */
  if (length_marker) {
    if (auth_marker > body) {
      ERROR("The authentication keyword should appear in the message header, not the body!");
    }

    if (body && dest - body > 4 && dest - body < 100004) {
      char tmp = length_marker[5];
      sprintf(length_marker, "%5u", dest - body - 4 + len_offset);
      length_marker[5] = tmp;
    } else {
      // Other cases: Content-Length is 0
      sprintf(length_marker, "    0\r\n\r\n");
    }
  }

  /*
   * The authentication substitution must be done outside the above
   * loop because auth-int will use the body (which must have already
   * been keyword substituted) to build the md5 hash
   */
  if (auth_marker) {
#ifndef _USE_OPENSSL
    ERROR("Authentication requires OpenSSL!");
#else
    if (!dialog_authentication) {
      ERROR("Authentication keyword without dialog_authentication!");
    }

    int	   auth_marker_len;
    char * tmp;
    int  authlen;

    auth_marker_len = (strchr(auth_marker, ']') + 1) - auth_marker;

    /* Need the Method name from the CSeq of the Challenge */
    char method[MAX_HEADER_LEN];
    tmp = get_last_header("CSeq:") + 5;
    if(!tmp) {
      ERROR("Could not extract method from cseq of challenge");
    }
    while(isspace(*tmp) || isdigit(*tmp)) tmp++;
    sscanf(tmp,"%s", method);

    if (!body) {
      body = "";
    }

    /* Determine the type of credentials. */
    char result[MAX_HEADER_LEN];
    if (dialog_challenge_type == 401) {
      /* Registrars use Authorization */
      authlen = sprintf(result, "Authorization: ");
    } else {
      /* Proxies use Proxy-Authorization */
      authlen = sprintf(result, "Proxy-Authorization: ");
    }

    /* Build the auth credenticals */
    char uri[MAX_HEADER_LEN];
    sprintf (uri, "%s:%d", remote_ip, remote_port);
    if (createAuthHeader(auth_comp->comp_param.auth_param.auth_user, auth_comp->comp_param.auth_param.auth_pass,
	  method, uri, body, dialog_authentication,
	  auth_comp->comp_param.auth_param.aka_OP, auth_comp->comp_param.auth_param.aka_AMF, auth_comp->comp_param.auth_param.aka_K,
	  result + authlen) == 0) {
      ERROR_P1("%s", result + authlen);
    }
    authlen = strlen(result);

    /* Shift the end of the message to its rightful place. */
    memmove(auth_marker + authlen, auth_marker + auth_marker_len, strlen(auth_marker + auth_marker_len) + 1);
    /* Copy our result into the hole. */
    memcpy(auth_marker, result, authlen);
#endif
  }

  if (auth_comp_allocated) {
    SendingMessage::freeMessageComponent(auth_comp);
  }

  return msg_buffer;
}

char* call::createSendingMessage(char *src, int P_index, bool skip_sanity)
{
  if (src == NULL) {
	  ERROR("Unsupported 'send' message in scenario");
  }

  SendingMessage *msgsrc = new SendingMessage(src, skip_sanity);
  char *msg = createSendingMessage(msgsrc, P_index);
  delete msgsrc;
  return msg;
}



#ifdef __3PCC__
bool call::process_twinSippCom(char * msg)
{
  int		  search_index;
  bool            found = false;
  T_ActionResult  actionResult;

  if (!running) {
    paused_calls.remove_paused_call(this);
    add_running_call(this);
  }

  if (checkInternalCmd(msg) == false) {

    for(search_index = msg_index;
      search_index < scenario_len;
      search_index++) {
      if(scenario[search_index] -> M_type != MSG_TYPE_RECVCMD) {
        if(scenario[search_index] -> optional) {
          continue;
        }
        /* The received message is different from the expected one */
	TRACE_MSG((s, "Unexpected control message received (I was expecting a different type of message):\n%s\n", msg));
        return rejectCall();
      } else {
        if(extendedTwinSippMode){                   // 3pcc extended mode 
	  if(check_peer_src(msg, search_index)){
            found = true;
            break;
	  } else{
	    WARNING_P1("Unexpected sender for the received peer message \n%s\n", msg);
	    return rejectCall();
	    }
	 }
	 else {
        found = true;
        break;
      }
    }
    }
    
    if (found) {
      scenario[search_index]->M_nbCmdRecv ++;
      
      // variable treatment
      // Remove \r, \n at the end of a received command
      // (necessary for transport, to be removed for usage)
      while ( (msg[strlen(msg)-1] == '\n') &&
      (msg[strlen(msg)-2] == '\r') ) {
        msg[strlen(msg)-2] = 0;
      }
      actionResult = executeAction(msg, search_index);
      
      if(actionResult != call::E_AR_NO_ERROR) {
        // Store last action result if it is an error
        // and go on with the scenario
        call::last_action_result = actionResult;
        if (actionResult == E_AR_STOP_CALL) {
            return rejectCall();
        }
      }
    } else {
      TRACE_MSG((s, "Unexpected control message received (no such message found):\n%s\n", msg));
      return rejectCall();
    }
    msg_index = search_index; //update the state machine
    return(next());
    
  } else {
    return (false);
  }
}

bool call::checkInternalCmd(char * cmd)
{

  char * L_ptr1, * L_ptr2, L_backup;

  L_ptr1 = strstr(cmd, "internal-cmd:");
  if (!L_ptr1) {return (false);}
  L_ptr1 += 13 ;
  while((*L_ptr1 == ' ') || (*L_ptr1 == '\t')) { L_ptr1++; }
  if (!(*L_ptr1)) {return (false);}
  L_ptr2 = L_ptr1;
  while((*L_ptr2) && 
        (*L_ptr2 != ' ') && 
        (*L_ptr2 != '\t') && 
        (*L_ptr2 != '\r') && 
        (*L_ptr2 != '\n')) { 
    L_ptr2 ++;
  } 
  if(!*L_ptr2) { return (false); }
  L_backup = *L_ptr2;
  *L_ptr2 = 0;

  if (strcmp(L_ptr1, "abort_call") == 0) {
    *L_ptr2 = L_backup;
    abortCall();
    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    return (true);
  }

  *L_ptr2 = L_backup;
  return (false);
}

bool call::check_peer_src(char * msg, int search_index)
{
 char * L_ptr1, * L_ptr2, L_backup ;

 L_ptr1 = strstr(msg, "From:");
 if (!L_ptr1) {return (false);}
 L_ptr1 += 5 ;
 while((*L_ptr1 == ' ') || (*L_ptr1 == '\t')) { L_ptr1++; }
 if (!(*L_ptr1)) {return (false);}
 L_ptr2 = L_ptr1;
  while((*L_ptr2) &&
        (*L_ptr2 != ' ') &&
        (*L_ptr2 != '\t') &&
        (*L_ptr2 != '\r') &&
        (*L_ptr2 != '\n')) {
    L_ptr2 ++;
  }
  if(!*L_ptr2) { return (false); }
  L_backup = *L_ptr2;
  *L_ptr2 = 0;
  if (strcmp(L_ptr1, scenario[search_index] -> peer_src) == 0) {
    *L_ptr2 = L_backup;
    return(true);
  }
 
  *L_ptr2 = L_backup;
  return (false);
}
#endif


void call::extract_cseq_method (char* method, char* msg)
{
  char* cseq ;
  if (cseq = strstr (msg, "CSeq"))
  {
    char * value ;
    if ( value = strchr (cseq,  ':'))
    {
      value++;
      while ( isspace(*value)) value++;  // ignore any white spaces after the :
      while ( !isspace(*value)) value++;  // ignore the CSEQ numnber
      value++;
      char *end = value;
      int nbytes = 0;
      /* A '\r' terminates the line, so we want to catch that too. */
      while ((*end != '\r') && (*end != '\n')) { end++; nbytes++; }
      if (nbytes > 0) strncpy (method, value, nbytes);
      method[nbytes] = '\0';
    }
  }
}

void call::formatNextReqUrl (char* next_req_url)
{

  /* clean up the next_req_url -- Record routes may have extra gunk
     that needs to be removed
   */
  char* actual_req_url = strchr(next_req_url, '<');
  if (actual_req_url) 
  {
    /* using a temporary buffer */
    char tempBuffer[MAX_HEADER_LEN];
    strcpy(tempBuffer, actual_req_url + 1);
    actual_req_url = strrchr(tempBuffer, '>');
    *actual_req_url = '\0';
    strcpy(next_req_url, tempBuffer);
  }

}

void call::computeRouteSetAndRemoteTargetUri (char* rr, char* contact, bool bRequestIncoming)
{
  if (0 >=strlen (rr))
  {
    //
    // there are no RR headers. Simply set up the contact as our target uri
    //
    if (0 < strlen(contact))
    {
      strcpy (next_req_url, contact);
    }

    formatNextReqUrl(next_req_url);

    return;
  }

  char actual_rr[MAX_HEADER_LEN];
  char targetURI[MAX_HEADER_LEN];
  memset(actual_rr, 0, sizeof(actual_rr));

  bool isFirst = true;
  bool bCopyContactToRR = false;

  while (1)
  {
      char* pointer = NULL;
      if (bRequestIncoming)
      {
        pointer = strchr (rr, ',');
      }
      else
      {
        pointer = strrchr(rr, ',');
      }

      if (pointer) 
      {
        if (!isFirst) 
        {
          if (strlen(actual_rr) )
          {
            strcat(actual_rr, pointer + 1);
          }
          else
          {
            strcpy(actual_rr, pointer + 1);
          }
          strcat(actual_rr, ",");
        } 
        else 
        {
          isFirst = false;
          if (NULL == strstr (pointer, ";lr"))
          {
            /* bottom most RR is the next_req_url */
            strcpy (targetURI, pointer + 1);
            bCopyContactToRR = true;
          }
          else
          {
            /* the hop is a loose router. Thus, the target URI should be the
             * contact
             */
            strcpy (targetURI, contact);
            strcpy(actual_rr, pointer + 1);
            strcat(actual_rr, ",");
          }
        }
      } 
      else 
      {
        if (!isFirst) 
        {
            strcat(actual_rr, rr);
        } 
        //
        // this is the *only* RR header that was found
        //
        else 
        {
          if (NULL == strstr (rr, ";lr"))
          {
            /* bottom most RR is the next_req_url */
            strcpy (targetURI, rr);
            bCopyContactToRR = true;
          }
          else
          {
            /* the hop is a loose router. Thus, the target URI should be the
             * contact
             */
            strcpy (actual_rr, rr);
            strcpy (targetURI, contact);
          }
        }
        break;
      }
      *pointer = '\0';
  }

  if (bCopyContactToRR)
  {
    if (0 < strlen (actual_rr))
    {
      strcat(actual_rr, ",");
      strcat(actual_rr, contact);
    }
    else
    {
      strcpy(actual_rr, contact);
    }
  }

  if (strlen(actual_rr)) 
  {
    dialog_route_set = (char *)
        calloc(1, strlen(actual_rr) + 2);
    sprintf(dialog_route_set, "%s", actual_rr);
  } 

  if (strlen (targetURI))
  {
    strcpy (next_req_url, targetURI);
    formatNextReqUrl (next_req_url);
  }
}

bool call::matches_scenario(unsigned int index, int reply_code, char * request, char * responsecseqmethod)
{         
  int        result;
          
  if ((reply_code) && ((scenario[index] -> recv_response) == reply_code) && \
     (index == 0 || ((scenario[index]->recv_response_for_cseq_method_list) && \
     (strstr(scenario[index]->recv_response_for_cseq_method_list, responsecseqmethod))))) {
        return true;
  }   
    
  if ((scenario[index] -> recv_request) && \
     (!strcmp(scenario[index] -> recv_request, request))) {
        return true;
  } 
  
  if ((scenario[index] -> recv_request) && (scenario[index] -> regexp_match)) {
  
     if (scenario[index] -> regexp_compile == NULL) {
        regex_t *re = new regex_t;
        if (regcomp(re, scenario[index] -> recv_request, REG_EXTENDED|REG_NOSUB)) {
           // regexp is not well formed
           scenario[index] -> regexp_match = 0;
           free(re);
           return false;
        }
        scenario[index] -> regexp_compile = re;
     }

     result = regexec(scenario[index] -> regexp_compile, request, (size_t)0, NULL, 0);
     if (!result) return true;
  }

  return false;
}

bool call::process_incoming(char * msg)
{
  int             reply_code;
  static char     request[65];
  char            responsecseqmethod[65];
  unsigned long   cookie;
  char          * ptr;
  int             search_index;
  bool            found = false;
  T_ActionResult  actionResult;

  int             L_case = 0 ;

  if (!running) {
    paused_calls.remove_paused_call(this);
    add_running_call(this);
  }

  /* Ignore the messages received during a pause if -pause_msg_ign is set */
  if(scenario[msg_index] -> M_type == MSG_TYPE_PAUSE && pause_msg_ign) return(true);

  /* Authorize nop as a first command, even in server mode */
  if((msg_index == 0) && (scenario[msg_index] -> M_type == MSG_TYPE_NOP)) {
    actionResult = executeAction(NULL, msg_index);
    return next();
  }
  responsecseqmethod[0] = '\0';

  if((transport == T_UDP) && (retrans_enabled)) {
    /* Detects retransmissions from peer and retransmit the
     * message which was sent just after this one was received */
    cookie = hash(msg);
    if(recv_retrans_hash == cookie) {

      int status;

      if(lost(recv_retrans_recv_index)) {
	TRACE_MSG((s, "%s message (retrans) lost (recv).",
	      TRANSPORT_TO_STRING(transport)));

	if(comp_state) { comp_free(&comp_state); }
	scenario[recv_retrans_recv_index] -> nb_lost++;
	return true;
      }

      scenario[recv_retrans_recv_index] -> nb_recv_retrans++;

      send_scene(recv_retrans_send_index, &status);

      if(status == 0) {
	scenario[recv_retrans_send_index] -> nb_sent_retrans++;
	CStat::instance()->computeStat(CStat::E_RETRANSMISSION);
      } else if(status < 0) {
	return false;
      }

      return true;
    }

    if(last_recv_hash == cookie) {
      /* This one has already been received, but not processed
       * yet => (has not triggered something yet) so we can discard.
       *
       * This case appears when the UAS has send a 200 but not received
       * a ACK yet. Thus, the UAS retransmit the 200 (invite transaction)
       * until it receives a ACK. In this case, it nevers sends the 200
       * from the  BYE, until it has reveiced the previous 200. Thus,
       * the UAC retransmit the BYE, and this BYE is considered as an
       * unexpected.
       *
       * This case can also appear in case of message duplication by
       * the network. This should not be considered as an unexpected.
       */
      scenario[last_recv_index]->nb_recv_retrans++;
      return true;
    }
  }

  /* Is it a response ? */
  if((msg[0] == 'S') && 
     (msg[1] == 'I') &&
     (msg[2] == 'P') &&
     (msg[3] == '/') &&
     (msg[4] == '2') &&
     (msg[5] == '.') &&
     (msg[6] == '0')    ) {    

    reply_code = get_reply_code(msg);
    if(!reply_code) {
      if (!process_unexpected(msg)) {
        return false; // Call aborted by unexpected message handling
      }
#ifdef PCAPPLAY
    } else if ((hasMedia == 1) && *(strstr(msg, "\r\n\r\n")+4) != '\0') {
      /* Get media info if we find something like an SDP */
      get_remote_media_addr(msg);
#endif
    }
    /* It is a response: update peer_tag */
    ptr = get_peer_tag(msg);
    if (ptr) {
      if(strlen(ptr) > (MAX_HEADER_LEN - 1)) {
        ERROR("Peer tag too long. Change MAX_HEADER_LEN and recompile sipp");
      }
      if(peer_tag) { free(peer_tag); }
      peer_tag = strdup(ptr);
      if (!peer_tag) {
	ERROR("Out of memory allocating peer tag.");
      }
    }
    request[0]=0;
    // extract the cseq method from the response
    extract_cseq_method (responsecseqmethod, msg);
  } else if(ptr = strchr(msg, ' ')) {
    if((ptr - msg) < 64) {
      memcpy(request, msg, ptr - msg);
      request[ptr - msg] = 0;
      // Check if we received an ACK => call established
      if (strcmp(request,"ACK")==0) {
        call_established=true;
      }
#ifdef PCAPPLAY
      /* In case of INVITE or re-INVITE, ACK or PRACK
         get the media info if needed (= we got a pcap
         play action) */
      if ((strncmp(request, "INVITE", 6) == 0) 
       || (strncmp(request, "ACK", 3) == 0) 
       || (strncmp(request, "PRACK", 5) == 0)     		
       && (hasMedia == 1)) 
        get_remote_media_addr(msg);
#endif

      reply_code = 0;
    } else {
      ERROR_P1("SIP method too long in received message '%s'",
               msg);
    }
  } else {
    ERROR_P1("Invalid sip message received '%s'",
             msg);
  }

  /* Try to find it in the expected non mandatory responses
   * until the first mandatory response  in the scenario */
  for(search_index = msg_index;
      search_index < scenario_len;
      search_index++) {
    if(!matches_scenario(search_index, reply_code, request, responsecseqmethod)) {
      if(scenario[search_index] -> optional) {
        continue;
      }
      /* The received message is different for the expected one */
      break;
    }

    found = true;
    /* TODO : this is a little buggy: If a 100 trying from an INVITE
     * is delayed by the network until the BYE is sent, it may
     * stop BYE transmission erroneously, if the BYE also expects
     * a 100 trying. */    
    break;
  }

  /* Try to find it in the old non-mandatory receptions */
  if(!found) {
    bool contig = true;
    for(search_index = msg_index - 1;
        search_index >= 0;
        search_index--) {
      if (scenario[search_index]->optional == OPTIONAL_FALSE) contig = false;
      if(matches_scenario(search_index, reply_code, request, responsecseqmethod)) {
        if (contig || scenario[search_index]->optional == OPTIONAL_GLOBAL) {
         found = true;
         break;  
        } else {
          /*
           * we received a non mandatory msg for an old transaction (this could be due to a retransmit.
           * If this response is for an INVITE transaction, retransmit the ACK to quench retransmits.
           */
          if ( (reply_code) &&
             (0 == strncmp (responsecseqmethod, "INVITE", strlen(responsecseqmethod)) ) &&
             (scenario[search_index+1]->M_type == MSG_TYPE_SEND) &&
             (scenario[search_index+1]->send_scheme->isAck()) ) {
            sendBuffer(createSendingMessage(scenario[search_index+1] -> send_scheme, (search_index+1)));
            return true;
          }
        }
      }
    }
  }

  /* If it is still not found, process an unexpected message */
  if(!found) {
    if ((L_case = checkAutomaticResponseMode(request)) == 0) {
      if (!process_unexpected(msg)) {
        return false; // Call aborted by unexpected message handling
      }
    } else {
      // call aborted by automatic response mode if needed
      return automaticResponseMode(L_case, msg);
    }
  }

  int test = (!found) ? -1 : scenario[search_index]->test;
  /* test==0: No branching"
   * test==-1 branching without testing"
   * test>0   branching with testing
   */

  /* Simulate loss of messages */
  if(lost(search_index)) {
    TRACE_MSG((s, "%s message lost (recv).", 
               TRANSPORT_TO_STRING(transport)));
    if(comp_state) { comp_free(&comp_state); }
    scenario[search_index] -> nb_lost++;
    return true;
  }


  /* Handle counters and RTDs for this message. */
  do_bookkeeping(search_index);

  /* Increment the recv counter */
  scenario[search_index] -> nb_recv++;

  // Action treatment
  if (found) {
    //WARNING_P1("---EXECUTE_ACTION_ON_MSG---%s---", msg); 
    
    actionResult = executeAction(msg, search_index);

    if(actionResult != call::E_AR_NO_ERROR) {
      // Store last action result if it is an error
      // and go on with the scenario
      call::last_action_result = actionResult;
      if (actionResult == E_AR_STOP_CALL) {
          return rejectCall();
      }
    }
  }

  if (request) { // update [cseq] with received CSeq
    unsigned long int rcseq = get_cseq_value(msg);
    if (rcseq > cseq) cseq = rcseq;
  }

  /* This is an ACK/PRACK or a response, and its index is greater than the 
   * current active retransmission message, so we stop the retrans timer. 
   * True also for CANCEL and BYE that we also want to answer to */
  if(((reply_code) ||
      ((!strcmp(request, "ACK")) ||
       (!strcmp(request, "CANCEL")) || (!strcmp(request, "BYE")) ||
       (!strcmp(request, "PRACK"))))  &&
     (search_index > last_send_index)) {
   /*
    * We should stop any retransmission timers on receipt of a provisional response only for INVITE
    * transactions. Non INVITE transactions continue to retransmit at T2 until a final response is 
    * received
    */
    if ( (0 == reply_code) || // means this is a request.
         (200 <= reply_code) ||  // final response
         ((0 != reply_code) && (0 == strncmp (responsecseqmethod, "INVITE", strlen(responsecseqmethod)))) ) // prov for INVITE
    {
    next_retrans = 0;
  }
    else
    {
      /*
       * We are here due to a provisional response for non INVITE. Update our next retransmit.
       */
      next_retrans = clock_tick + DEFAULT_T2_TIMER_VALUE;
      nb_last_delay = DEFAULT_T2_TIMER_VALUE;

    }
  }

  /* This is a response with 200 so set the flag indicating that an
   * ACK is pending (used to prevent from release a call with CANCEL
   * when an ACK+BYE should be sent instead)                         */
  if (reply_code == 200) {
    ack_is_pending = true;
  }

  /* store the route set only once. TODO: does not support target refreshes!! */
  if (scenario[search_index] -> bShouldRecordRoutes &&
          NULL == dialog_route_set ) {

      next_req_url = (char*) calloc(1, MAX_HEADER_LEN);

      char rr[MAX_HEADER_LEN];
      memset(rr, 0, sizeof(rr));
      strcpy(rr, get_header_content(msg, (char*)"Record-Route:"));

      // WARNING_P1("rr [%s]", rr);
      char ch[MAX_HEADER_LEN];
      strcpy(ch, get_header_content(msg, (char*)"Contact:"));

      /* decorate the contact with '<' and '>' if it does not have it */
      char* contDecorator = strchr(ch, '<');
      if (NULL == contDecorator) {
         char tempBuffer[MAX_HEADER_LEN];
         sprintf(tempBuffer, "<%s>", ch);
         strcpy(ch, tempBuffer);
      }

      /* should cache the route set */
      if (reply_code) {
        computeRouteSetAndRemoteTargetUri (rr, ch, false);
      }
      else
      {
        computeRouteSetAndRemoteTargetUri (rr, ch, true);
      }
      // WARNING_P1("next_req_url is [%s]", next_req_url);
  }

#ifdef _USE_OPENSSL
  /* store the authentication info */
  if ((scenario[search_index] -> bShouldAuthenticate) && 
          (reply_code == 401 || reply_code == 407)) {

      /* is a challenge */
      char auth[MAX_HEADER_LEN];
      memset(auth, 0, sizeof(auth));
      strcpy(auth, get_header_content(msg, (char*)"Proxy-Authenticate:"));
      if (auth[0] == 0) {
        strcpy(auth, get_header_content(msg, (char*)"WWW-Authenticate:"));
      }
      if (auth[0] == 0) {
        ERROR("Couldn't find 'Proxy-Authenticate' or 'WWW-Authenticate' in 401 or 407!");
      }

      dialog_authentication = (char *) realloc(dialog_authentication, strlen(auth) + 2);
      sprintf(dialog_authentication, "%s", auth);

      /* Store the code of the challenge for building the proper header */
      dialog_challenge_type = reply_code;
  }
#endif

  /* Store last received message information for all messages so that we can
   * correctly identify retransmissions, and use its body for inclusion
   * in our messages. */
  last_recv_index = search_index;
  last_recv_hash = cookie;
  last_recv_msg = (char *) realloc(last_recv_msg, strlen(msg) + 1);
  strcpy(last_recv_msg, msg);

  /* If this was a mandatory message, or if there is an explicit next label set
   * we must update our state machine.  */
  if (!(scenario[search_index] -> optional) ||
       scenario[search_index]->next && 
      ((test == -1) ||
       (test <= maxVariableUsed && M_callVariableTable[test] != NULL && M_callVariableTable[test]->isSet()))
     ) {
    /* If we are paused, then we need to wake up so that we properly go through the state machine. */
    paused_until = 0;
    msg_index = search_index;
    return next();
  } else {
    unsigned int timeout = call_wake(this);
    unsigned int candidate;

    if (scenario[search_index]->next && test <= maxVariableUsed && 
       M_callVariableTable[test] != NULL && M_callVariableTable[test]->isSet()) {
      WARNING_P1("Last message generates an error and will not be used for next sends (for last_ variables):\r\n%s",msg);
    }

    /* We are just waiting for a message to be received, if any of the
     * potential messages have a timeout we set it as our timeout. We
     * start from the next message and go until any non-receives. */
    for(search_index++; search_index < scenario_len; search_index++) {
      if(scenario[search_index] -> M_type != MSG_TYPE_RECV) {
	break;
      }
      candidate = scenario[search_index] -> timeout;
      if (candidate == 0) {
	if (defl_recv_timeout == 0) {
	  continue;
	}
	candidate = defl_recv_timeout;
      }
      if (!timeout || (clock_tick + candidate < timeout)) {
	timeout = clock_tick + candidate;
      }
    }

    if (!remove_running_call(this)) {
      ERROR("Tried to remove a running call that wasn't running!\n");
    }
    paused_calls.add_paused_call(this, true);
  }
  return true;
}

double call::get_rhs(CAction *currentAction) {
  if (currentAction->getVarInId()) {
    return M_callVariableTable[currentAction->getVarInId()]->getDouble();
  } else {
    return currentAction->getDoubleValue();
  }
}

call::T_ActionResult call::executeAction(char * msg, int scenarioIndex)
{
  CActions*  actions;
  CAction*   currentAction;
  CVariable* scenVariable;
  char       msgPart[MAX_SUB_MESSAGE_LENGTH];
  int        currentId;

  actions = scenario[scenarioIndex]->M_actions;
  // looking for action to do on this message
  if(actions != NULL) {
    for(int i=0; i<actions->getActionSize(); i++) {
      currentAction = actions->getAction(i);
      if(currentAction != NULL) {
        if(currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_REGEXP) {
          currentId = currentAction->getVarId();
          scenVariable = scenVariableTable[currentId][scenarioIndex];
          if(scenVariable != NULL) {
            if(currentAction->getLookingPlace() == CAction::E_LP_HDR) {
              extractSubMessage
                                (msg, 
                                currentAction->getLookingChar(), 
                                msgPart,
                                currentAction->getCaseIndep(),
                                currentAction->getOccurence(),
                                currentAction->getHeadersOnly()); 
        
              if(strlen(msgPart) > 0) {
          
                scenVariable->executeRegExp(msgPart, 
                                  M_callVariableTable,
				  currentId,
				  currentAction->getNbSubVarId(),
                                  currentAction->getSubVarId());
          
                if( (!(M_callVariableTable[currentId]->isSet())) 
                && (currentAction->getCheckIt() == true) ) {
                  // the message doesn't match and the checkit 
                  // action say it MUST match
                  // Allow easier regexp debugging
                  WARNING_P2("Failed regexp match: looking "
                  "in '%s', with regexp '%s'", 
                  msgPart, 
                  scenVariable->
                  getRegularExpression());
                  // --> Call will be marked as failed
                  return(call::E_AR_REGEXP_DOESNT_MATCH);
                }
              } else {// sub part of message not found
                if( currentAction->getCheckIt() == true ) {
                  // the sub message is not found and the
                  // checking action say it MUST match
                  // --> Call will be marked as failed but 
                  // will go on
                  WARNING_P2("Failed regexp match: header %s not found in message %s\n", currentAction->getLookingChar(), msg);
                  return(call::E_AR_HDR_NOT_FOUND);
                } 
              }
            } else {// we must look in the entire message
              // WARNING_P1("LOOKING IN MSG -%s-", msg);
                scenVariable->executeRegExp(msg, 
                                  M_callVariableTable,
				  currentId,
				  currentAction->getNbSubVarId(),
                                  currentAction->getSubVarId());
              if((!(M_callVariableTable[currentId]->isSet())) 
              && (currentAction->getCheckIt() == true) ) {
                // the message doesn't match and the checkit 
                // action say it MUST match
                // Allow easier regexp debugging
                WARNING_P2("Failed regexp match: looking in '%s'"
                ", with regexp '%s'", 
                msg, 
                scenVariable->getRegularExpression());
                // --> rejecting the call
                return(call::E_AR_REGEXP_DOESNT_MATCH);
              }
            }
          } // end if scen variable != null
        } else /* end action == E_AT_ASSIGN_FROM_REGEXP */ 
            if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_VALUE) {
	      M_callVariableTable[currentAction->getVarId()]->setDouble(currentAction->getDoubleValue());
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_ADD) {
	  double value = M_callVariableTable[currentAction->getVarId()]->getDouble();
	  double operand = get_rhs(currentAction);
	  M_callVariableTable[currentAction->getVarId()]->setDouble(value + operand);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_SUBTRACT) {
	  double value = M_callVariableTable[currentAction->getVarId()]->getDouble();
	  double operand = get_rhs(currentAction);
	  M_callVariableTable[currentAction->getVarId()]->setDouble(value - operand);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_MULTIPLY) {
	  double value = M_callVariableTable[currentAction->getVarId()]->getDouble();
	  double operand = get_rhs(currentAction);
	  M_callVariableTable[currentAction->getVarId()]->setDouble(value * operand);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_DIVIDE) {
	  double value = M_callVariableTable[currentAction->getVarId()]->getDouble();
	  double operand = get_rhs(currentAction);
	  if (operand == 0) {
	    WARNING_P2("Action failure: Can not divide by zero ($%d/$%d)!\n", currentAction->getVarId(), currentAction->getVarInId());
	  } else {
	    M_callVariableTable[currentAction->getVarId()]->setDouble(value / operand);
	  }
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_TEST) {
	  double value = currentAction->compare(M_callVariableTable);
	  M_callVariableTable[currentAction->getVarId()]->setBool(value);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_STRCMP) {
	  char *rhs = M_callVariableTable[currentAction->getVarInId()]->getString();
	  char *lhs = currentAction->getStringValue();
	  int value = strcmp(rhs, lhs);
	  M_callVariableTable[currentAction->getVarId()]->setDouble((double)value);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_TO_DOUBLE) {
	  double value;

	  if (M_callVariableTable[currentAction->getVarInId()]->toDouble(&value)) {
	    M_callVariableTable[currentAction->getVarId()]->setDouble(value);
	  } else {
	    WARNING_P2("Invalid double conversion from $%d to $%d", currentAction->getVarInId(), currentAction->getVarId());
	  }
	} else if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_SAMPLE) {
	  double value = currentAction->getDistribution()->sample();
	  M_callVariableTable[currentAction->getVarId()]->setDouble(value);
	} else if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_STRING) {
            char* x = createSendingMessage(currentAction->getMessage(), -2 /* do not add crlf*/, true /* skip sanity check */);
	    char *str = strdup(x);
	    if (!str) {
		ERROR("Out of memory duplicating string for assignment!");
	    }
	    M_callVariableTable[currentAction->getVarId()]->setString(str);
	} else if (currentAction->getActionType() == CAction::E_AT_LOG_TO_FILE) {
            char* x = createSendingMessage(currentAction->getMessage(), -2 /* do not add crlf*/, true /* skip sanity check */);
            LOG_MSG((s, "%s\n", x));
        } else if (currentAction->getActionType() == CAction::E_AT_EXECUTE_CMD) {

            if (currentAction->getCmdLine()) {
                char* x = createSendingMessage(currentAction->getCmdLine(), -2 /* do not add crlf*/, true /* skip sanity check. */);
                // TRACE_MSG((s, "Trying to execute [%s]", x)); 
                pid_t l_pid;
                switch(l_pid = fork())
                {
                    case -1:
                        // error when forking !
                        ERROR_NO("Forking error main");
                        break;

                    case 0:
                       // first child process - execute the command
                       if((l_pid = fork()) < 0) {
                         ERROR_NO("Forking error child");
                       } else {
                         if( l_pid == 0){
                         int ret;
                         ret = system(x); // second child runs
                         if(ret == -1) {
                           WARNING_P1("system call error for %s",x);
                          }
                        }
                       exit(EXIT_OTHER); 
                       }
                       break;
                    default:
                       // parent process continue
                       // reap first child immediately
                       pid_t ret;
                       while ((ret=waitpid(l_pid, NULL, 0)) != l_pid) {
                       if (ret != -1) {
                          ERROR_P2("waitpid returns %1d for child %1d",ret,l_pid); 
                         }
                       }
                       break;
                }
            }
        } else /* end action == E_AT_EXECUTE_CMD */
            if (currentAction->getActionType() == CAction::E_AT_EXEC_INTCMD) {
                switch (currentAction->getIntCmd())
                {
                    case CAction::E_INTCMD_STOP_ALL:
                        quitting = 1;
                        break;
                    case CAction::E_INTCMD_STOP_NOW:
                        screen_exit(EXIT_TEST_RES_INTERNAL);
                        break;
                    case CAction::E_INTCMD_STOPCALL:
                    default:
                        return(call::E_AR_STOP_CALL);
                        break;
                }
#ifdef PCAPPLAY
        } else if ((currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_AUDIO) ||
                   (currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_VIDEO)) {
          play_args_t *play_args;
          if (currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_AUDIO) {
            play_args = &(this->play_args_a);
          } else if (currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_VIDEO) {
            play_args = &(this->play_args_v);
          }
          play_args->pcap = currentAction->getPcapPkts();
          /* port number is set in [auto_]media_port interpolation */
          if (media_ip_is_ipv6) {
            struct sockaddr_in6 *from = (struct sockaddr_in6 *)(void *) &(play_args->from);
            from->sin6_family = AF_INET6;
            inet_pton(AF_INET6, media_ip, &(from->sin6_addr));
          }
          else {
            struct sockaddr_in *from = (struct sockaddr_in *)(void *) &(play_args->from);
            from->sin_family = AF_INET;
            from->sin_addr.s_addr = inet_addr(media_ip);
          }
          /* Create a thread to send RTP packets */
          pthread_attr_t attr;
          pthread_attr_init(&attr);
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN	16384
#endif
          //pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
          pthread_attr_setdetachstate(&attr,
				PTHREAD_CREATE_DETACHED);
          int ret = pthread_create(&media_thread, &attr, send_wrapper,
		       (void *) play_args);
          if(ret)
            ERROR("Can create thread to send RTP packets");
          pthread_attr_destroy(&attr);
#endif
        } else {
          ERROR("call::executeAction unknown action");
        }
      } // end if current action != null
    } // end for
  }
  return(call::E_AR_NO_ERROR);
}

void call::extractSubMessage(char * msg, char * matchingString, char* result, bool case_indep, int occurrence, bool headers) {

 char *ptr, *ptr1;
  int sizeOf;
  int i = 0;
 int len = strlen(matchingString);
 char mat1 = tolower(*matchingString);
 char mat2 = toupper(*matchingString);

 ptr = msg;
 while (*ptr) { 
   if (!case_indep) {
     ptr = strstr(ptr, matchingString);
     if (ptr == NULL) break;
     if (headers == true && ptr != msg && *(ptr-1) != '\n') {
       ++ptr;
       continue; 
     }
   } else {
     if (headers) {
       if (ptr != msg) {
         ptr = strchr(ptr, '\n');
         if (ptr == NULL) break;
         ++ptr;
         if (*ptr == 0) break;
       }
     } else {
       ptr1 = strchr(ptr, mat1);
       ptr = strchr(ptr, mat2);
       if (ptr == NULL) {
         if (ptr1 == NULL) break;
         ptr = ptr1;
       } else {
         if (ptr1 != NULL && ptr1 < ptr) ptr = ptr1; 
       }
     }
     if (strncasecmp(ptr, matchingString, len) != 0) {
       ++ptr;
       continue;
     }
   }
   // here with ptr pointing to a matching string
   if (occurrence <= 1) break; 
   --occurrence;
   ++ptr;
 }

 if(ptr != NULL && *ptr != 0) {
   strncpy(result, ptr+len, MAX_SUB_MESSAGE_LENGTH);
    sizeOf = strlen(result);
    if(sizeOf >= MAX_SUB_MESSAGE_LENGTH)  
      sizeOf = MAX_SUB_MESSAGE_LENGTH-1;
    while((i<sizeOf) && (result[i] != '\n') && (result[i] != '\r'))
      i++;
    result[i] = '\0';
  } else {
    result[0] = '\0';
  }
}

void call::getFieldFromInputFile(const char *fileName, int field, char*& dest)
{
  if (inFiles.find(fileName) == inFiles.end()) {
    ERROR_P1("Invalid injection file: %s", fileName);
  }
  int line = (*m_lineNumber)[fileName];
  if (line < 0) {
    return;
  }
  dest += inFiles[fileName]->getField(line, field, dest, SIPP_MAX_MSG_SIZE);
}

int  call::checkAutomaticResponseMode(char * P_recv) {

  int L_res = 0 ;

  if (strcmp(P_recv, "BYE")==0) {
    L_res = 1 ;
  } else if (strcmp(P_recv, "CANCEL") == 0) {
    L_res = 2 ;
  } else if (strcmp(P_recv, "PING") == 0) {
    L_res = 3 ;
  } else if (((strcmp(P_recv, "INFO") == 0) || (strcmp(P_recv, "NOTIFY") == 0) || (strcmp(P_recv, "UPDATE") == 0)) 
               && (auto_answer == true)){
    L_res = 4 ;
  }

  return (L_res) ;
  
}


bool call::automaticResponseMode(int P_case, char * P_recv)
{

  int res ;
  char * old_last_recv_msg = NULL;
  bool last_recv_msg_saved = false;

  switch (P_case) {
  case 1: // response for an unexpected BYE
    // usage of last_ keywords
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
    strcpy(last_recv_msg, P_recv);

    // The BYE is unexpected, count it
    scenario[msg_index] -> nb_unexp++;
    if (default_behavior) {
      WARNING_P1("Aborting call on an unexpected BYE for call: %s", (id==NULL)?"none":id);
    sendBuffer(createSendingMessage(
                    (char*)"SIP/2.0 200 OK\n"
                    "[last_Via:]\n"
                    "[last_From:]\n"
                    "[last_To:]\n"
                    "[last_Call-ID:]\n"
                    "[last_CSeq:]\n"
                    "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
                    "Content-Length: 0\n\n"
                    , -1)) ;

#ifdef __3PCC__
    // if twin socket call => reset the other part here 
    if (twinSippSocket && (msg_index > 0)) {
      res = sendCmdBuffer
      (createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n\n", -1));
    }
#endif /* __3PCC__ */
      CStat::instance()->computeStat(CStat::E_CALL_FAILED);
      CStat::instance()->computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
      delete_call(id);
    } else {
      WARNING_P1("Continuing call on an unexpected BYE for call: %s", (id==NULL)?"none":id);
    }
      break ;
      
  case 2: // response for an unexpected cancel
    // usage of last_ keywords
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
    strcpy(last_recv_msg, P_recv);

    // The CANCEL is unexpected, count it
    scenario[msg_index] -> nb_unexp++;
    if (default_behavior) {
      WARNING_P1("Aborting call on an unexpected CANCEL for call: %s", (id==NULL)?"none":id);
    sendBuffer(createSendingMessage(
                      (char*)"SIP/2.0 200 OK\n"
                      "[last_Via:]\n"
                      "[last_From:]\n"
                      "[last_To:]\n"
                      "[last_Call-ID:]\n"
                      "[last_CSeq:]\n"
                      "Contact: sip:sipp@[local_ip]:[local_port]\n"
                      "Content-Length: 0\n\n"
                      , -1)) ;
    
#ifdef __3PCC__
    // if twin socket call => reset the other part here 
    if (twinSippSocket && (msg_index > 0)) {
      res = sendCmdBuffer
      (createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n\n", -1));
    }
#endif /* __3PCC__ */
    
    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    CStat::instance()->computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
    delete_call(id);
    } else {
      WARNING_P1("Continuing call on unexpected CANCEL for call: %s", (id==NULL)?"none":id);
    }
    break ;
      
  case 3: // response for a random ping
    // usage of last_ keywords
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
    strcpy(last_recv_msg, P_recv);
    
   if (default_behavior) {
    WARNING_P1("Automatic response mode for an unexpected PING for call: %s", (id==NULL)?"none":id);
    count_in_stats = false; // Call must not be counted in statistics
    sendBuffer(createSendingMessage(
                    (char*)"SIP/2.0 200 OK\n"
                    "[last_Via:]\n"
                    "[last_Call-ID:]\n"
                    "[last_To:]\n"
                    "[last_From:]\n"
                    "[last_CSeq:]\n"
                    "Contact: sip:sipp@[local_ip]:[local_port]\n"
                    "Content-Length: 0\n\n"
                    , -1)) ;
    // Note: the call ends here but it is not marked as bad. PING is a 
    //       normal message.
#ifdef __3PCC__
    // if twin socket call => reset the other part here 
    if (twinSippSocket && (msg_index > 0)) {
      res = sendCmdBuffer
      (createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n\n",-1));
    }
#endif /* __3PCC__ */
    
    CStat::instance()->computeStat(CStat::E_AUTO_ANSWERED);
    delete_call(id);
    } else {
      WARNING_P1("Do not answer on an unexpected PING for call: %s", (id==NULL)?"none":id);
    }
    break ;

  case 4: // response for a random INFO, UPDATE or NOTIFY
    // store previous last msg if msg is INFO, UPDATE or NOTIFY
    // restore last_recv_msg to previous one
    // after sending ok
    old_last_recv_msg = NULL;
    if (last_recv_msg != NULL) {
      last_recv_msg_saved = true;
      old_last_recv_msg = (char *) malloc(strlen(last_recv_msg)+1);
      strcpy(old_last_recv_msg,last_recv_msg);
    }
    // usage of last_ keywords
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
    strcpy(last_recv_msg, P_recv);

    WARNING_P1("Automatic response mode for an unexpected INFO, UPDATE or NOTIFY for call: %s", (id==NULL)?"none":id);
    sendBuffer(createSendingMessage(
                    (char*)"SIP/2.0 200 OK\n"
                    "[last_Via:]\n"
                    "[last_Call-ID:]\n"
                    "[last_To:]\n"
                    "[last_From:]\n"
                    "[last_CSeq:]\n"
                    "Contact: sip:sipp@[local_ip]:[local_port]\n"
                    "Content-Length: 0\n\n"
                    , -1)) ;

    // restore previous last msg
    if (last_recv_msg_saved == true) {
      last_recv_msg = (char *) realloc(last_recv_msg, strlen(old_last_recv_msg) + 1);
      strcpy(last_recv_msg, old_last_recv_msg);
      if (old_last_recv_msg != NULL) {
        free(old_last_recv_msg);
        old_last_recv_msg = NULL;
      }
    }
    CStat::instance()->computeStat(CStat::E_AUTO_ANSWERED);
    return true;
    break;

    case 5: // response for an out of call message
    old_last_recv_msg = NULL;
    if (last_recv_msg != NULL) {
      last_recv_msg_saved = true;
      old_last_recv_msg = (char *) malloc(strlen(last_recv_msg)+1);
      strcpy(old_last_recv_msg,last_recv_msg);
    }
    // usage of last_ keywords
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
    strcpy(last_recv_msg, P_recv);

    WARNING("Automatic response mode for an out of call message");
    sendBuffer(createSendingMessage(
                    (char*)"SIP/2.0 200 OK\n"
                    "[last_Via:]\n"
                    "[last_Call-ID:]\n"
                    "[last_To:]\n"
                    "[last_From:]\n"
                    "[last_CSeq:]\n"
                    "Contact: sip:sipp@[local_ip]:[local_port]\n"
                    "Content-Length: 0\n\n"
                    , -1)) ;

    // restore previous last msg
    if (last_recv_msg_saved == true) {
      last_recv_msg = (char *) realloc(last_recv_msg, strlen(old_last_recv_msg) + 1);
      strcpy(last_recv_msg, old_last_recv_msg);
      if (old_last_recv_msg != NULL) {
        free(old_last_recv_msg);
        old_last_recv_msg = NULL;
      }
    }
    CStat::instance()->computeStat(CStat::E_AUTO_ANSWERED);
    return true;

    default:
    ERROR_P1("Internal error for automaticResponseMode - mode %d is not implemented!", P_case);
    break ;
  }

  return false;
  
}

#ifdef PCAPPLAY
void *send_wrapper(void *arg)
{
  play_args_t *s = (play_args_t *) arg;
  //struct sched_param param;
  //int ret;
  //param.sched_priority = 10;
  //ret = pthread_setschedparam(pthread_self(), SCHED_RR, &param);
  //if(ret)
  //  ERROR("Can't set RTP play thread realtime parameters");
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
  send_packets(s);
  pthread_exit(NULL);
  return NULL;
}
#endif
