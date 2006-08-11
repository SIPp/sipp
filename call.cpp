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
 */

#include <iterator>
#include <algorithm>
#include <fstream>
#include <iostream>
#ifdef PCAPPLAY
#include "send_packets.h"
#endif
#include "sipp.hpp"

#define KEYWORD_SIZE 64

#ifdef _USE_OPENSSL
extern  SSL                 *ssl_list[];
extern  struct pollfd        pollfiles[];
extern  SSL_CTX             *sip_trp_ssl_ctx;
#endif

extern  map<string, int>     map_perip_fd;

call_map calls;

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

call * add_call(char * call_id, bool ipv6)
{
  call * new_call;

  new_call = new call(call_id, ipv6);


  if(!new_call) {
    ERROR("Memory Overflow");
  }

  calls[std::string(call_id)] = new_call;

  if(!next_number) { next_number ++; }
  new_call -> number = next_number;

  /* Vital counters update */
  next_number++;
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

#ifdef _USE_OPENSSL
call * add_call(char * call_id , int P_pollset_indx, bool ipv6)
{
  call * new_call;

  new_call = new call(call_id, ipv6);


  if(!new_call) {
    ERROR("Memory Overflow");
  }

  calls[std::string(call_id)] = new_call;

  if(!next_number) { next_number ++; }
  new_call -> number = next_number;
  new_call ->  pollset_index = P_pollset_indx;

  /* Vital counters update */
  next_number++;
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
#endif


call * add_call(bool ipv6)
{
  static char call_id[MAX_HEADER_LEN];
  
  call * new_call;
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
  
  return add_call(call_id, ipv6);
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
    calls.erase(call_it);
    delete call_ptr;
    open_calls--;
  } else {
    if (start_calls == 0) {
    ERROR("Call not found");
  }
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
    char number[5];
    begin = strstr(msg, pattern);
    if (!begin)
      ERROR("get_remote_audio_port_media: No audio media port found in SDP");
    begin += sizeof("m=audio ") - 1;
    end = strstr(begin, "\r\n");
    if (!end)
      ERROR("get_remote_audio_port_media: no CRLF found");
    memset(number, 0, 5);
    strncpy(number, begin, end - begin);
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
  uint16_t video_port;
  if (media_ip_is_ipv6) {
  struct in6_addr ip_media;
    if (get_remote_ipv6_media(msg, ip_media)) {
      (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_flowinfo = 0;
      (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_scope_id = 0;
      (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_family = AF_INET6;
      (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_port = get_remote_audio_port_media(msg);
      (_RCAST(struct sockaddr_in6 *, &(play_args_a.to)))->sin6_addr = ip_media;
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
      (_RCAST(struct sockaddr_in *, &(play_args_a.to)))->sin_family = AF_INET;
      (_RCAST(struct sockaddr_in *, &(play_args_a.to)))->sin_port = get_remote_audio_port_media(msg);
      (_RCAST(struct sockaddr_in *, &(play_args_a.to)))->sin_addr.s_addr = ip_media;
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
  unsigned long rv = 0;
  int len = strlen(msg);
  int index = 0;
  
  if (len > 4) {
    rv  = msg[0] + msg[1] + msg[2] + msg[3];
  }
  
  if (len > 12) {
    rv += msg[9] + msg[10] + msg[11] + msg[12];
  }

  rv <<= 8;
  rv += len;
  rv <<= 16;
  
  for (index = 0; index < len; index ++) {
    rv += + msg[index] * index;
  }
  
  return rv;
}

/******************* Call class implementation ****************/

call::InputFileUsage call::m_usage   = call::InputFileSequentialOrder;
int                  call::m_counter = 0;

call::call(char * p_id, bool ipv6) : use_ipv6(ipv6)
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
  
#ifdef _USE_OPENSSL
  m_ctx_ssl = NULL ;
  m_bio = NULL ;
#endif

  pollset_index = 0 ;
  poll_flag_write = false ;

  call_remote_socket = 0;
  
  // initialising the CallVariable with the Scenario variable
  bool test_var=false;
  int i,j;
  for(i=0; i<SCEN_VARIABLE_SIZE; i++) 
    {
      for (j=0; j<SCEN_MAX_MESSAGES; j++)
      {
      if(scenVariableTable[i][j] != NULL) {
                test_var=true;
                break;
            }
        }
      if (test_var) {
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
  start_time_rtd  = clock_tick; 

  // by default, last action result is NO_ERROR
  last_action_result = call::E_AR_NO_ERROR;

  if (InputFileRandomOrder == m_usage) {
      m_localLineNumber = rand() % numLinesInFile;
  } else {
      m_localLineNumber = m_counter++;
      if (m_counter >= numLinesInFile) {
          m_counter = 0;
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

  peer_tag[0] = '\0';
}

call::~call()
{
  deleted += 1;
  
  if(comp_state) { comp_free(&comp_state); }

  if(count_in_stats) {
    CStat::instance()->computeStat(CStat::E_ADD_CALL_DURATION, 
                                   clock_tick - start_time);
  }

  call_duration_sum += clock_tick - start_time;
  call_duration_nb++;
  
#ifdef _USE_OPENSSL
  
  if ((toolMode == MODE_SERVER)  && (multisocket))  {
   if (ssl_list[call_socket] != NULL) {
    if((pollset_index) &&  (pollfiles[pollset_index].fd == call_socket)) {
      SSL_set_shutdown(ssl_list[call_socket],SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
      SSL_free(ssl_list[call_socket]);
      ssl_list[call_socket] = NULL ;
      pollset_remove(pollset_index);
      shutdown(call_socket, SHUT_RDWR);
      close(call_socket);
     }
   }
  }

  if ((toolMode != MODE_SERVER) && (multisocket))  {
    if(pollset_index ) {
     if (ssl_list[call_socket] != NULL) {
      // SSL_shutdown(ssl_list[call_socket]);
      SSL_set_shutdown(ssl_list[call_socket],SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
       SSL_free(ssl_list[call_socket]);
       // BIO_free(m_bio);
       // m_bio = NULL ;
       m_ctx_ssl = NULL ;
      }
    }
  }
#endif
  
  if (toolMode != MODE_SERVER)   {
  // TRACE_MSG((s,"socket close  %d at idx = %d\n", socket_close, pollset_index));
  if(pollset_index) {
      if (socket_close) {
    pollset_remove(pollset_index);
    shutdown(call_socket, SHUT_RDWR);
    close(call_socket);
  }
    }
  } else {
    if (call_remote_socket) {
      close(call_remote_socket);
    }
  }

  /* Deletion of the call variable */ 
  for(int i=0; i<SCEN_VARIABLE_SIZE; i++) {
    if(M_callVariableTable[i] != NULL) {
      delete M_callVariableTable[i] ;
      M_callVariableTable[i] = NULL;
    }
  }

  if(id) { free(id); }
  if(last_recv_msg) { free(last_recv_msg); }
  if(last_send_msg) { free(last_send_msg); }

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
#ifdef _USE_OPENSSL
   int err;
   SSL      *L_ssl_tcp_multiplex=NULL ;
#endif

  if(call_socket) return;
  if(!multisocket) return;

  if(transport == T_UDP) {
    struct sockaddr_storage saddr;
    sipp_socklen_t len;
    
    int L_status = 0 ;	   // no new socket

    if(toolMode != MODE_CLIENT) return;

    char peripaddr[256];
    if (!peripsocket) {
      if ((call_socket = new_socket(use_ipv6, SOCK_DGRAM, &L_status)) == -1) {
        ERROR_NO("Unable to get a UDP socket");
       }
     } else {
       getIpFieldFromInputFile(peripfield, m_localLineNumber, peripaddr);
       map<string, int>::iterator i;
       i = map_perip_fd.find(peripaddr);
       if (i == map_perip_fd.end()) {
         // Socket does not exist
    if ((call_socket = new_socket(use_ipv6, SOCK_DGRAM, &L_status)) == -1) {
      ERROR_NO("Unable to get a UDP socket");
         } else {
           map_perip_fd[peripaddr] = call_socket;
         }
       } else {
         // Socket exists already
         call_socket = i->second;
       }
    }
    

    if (L_status) {
    memset(&saddr, 0, sizeof(struct sockaddr_storage));

    memcpy(&saddr,
	   local_addr_storage->ai_addr,
           SOCK_ADDR_SIZE(
             _RCAST(struct sockaddr_storage *,local_addr_storage->ai_addr)));

    if (use_ipv6) {
    saddr.ss_family       = AF_INET;
    } else {
      saddr.ss_family       = AF_INET6;
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

    if(bind(call_socket,
            (sockaddr *)(void *)&saddr,
            use_ipv6 ? sizeof(struct sockaddr_in6) :
                       sizeof(struct sockaddr_in))) {
      ERROR_NO("Unable to bind UDP socket");
    }
    }
    
    if (use_ipv6) {
      len = sizeof(struct sockaddr_in6);
    } else {
      len = sizeof(struct sockaddr_in);
    }

    getsockname(call_socket, 
                (sockaddr *)(void *)&saddr,
                &len);

    if (use_ipv6) {
      call_port =
        ntohs((short)((_RCAST(struct sockaddr_in6 *, &saddr))->sin6_port));
    } else {
      call_port
        = ntohs((short)((_RCAST(struct sockaddr_in *, &saddr))->sin_port));
    }
     /* Asks to receive incoming messages */
    if (L_status) {
     pollset_index = pollset_add(this, call_socket);
    }

  } else { /* TCP */

    int L_status = 0 ;	   // no new socket
    struct sockaddr_storage *L_dest = &remote_sockaddr;

    if ((call_socket = new_socket(use_ipv6, SOCK_STREAM, &L_status)) == -1) {
      ERROR_NO("Unable to get a TCP socket");
    }
    
    if (L_status) {
      sipp_customize_socket(call_socket);

      if (use_remote_sending_addr) {
        L_dest = &remote_sending_sockaddr;
      }

    if(connect(call_socket,
                 (struct sockaddr *)(void *)L_dest,
	        SOCK_ADDR_SIZE(&remote_sockaddr))) {
      
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
    } else {
#ifdef _USE_OPENSSL
     if ( transport == T_TLS ) {
       m_ctx_ssl = sip_trp_ssl_ctx ;
       
       
      if (!(L_ssl_tcp_multiplex = SSL_new(m_ctx_ssl))){
            ERROR("Unable to create SSL object : Problem with SSL_new() \n");
       }

       // if ( (m_bio = BIO_new_socket(call_socket,BIO_NOCLOSE)) == NULL) {
        
       if ( (m_bio = BIO_new_socket(call_socket,BIO_CLOSE)) == NULL) {
             ERROR("Unable to create BIO object:Problem with BIO_new_socket()\n");
       }
        

       // SSL_set_fd(L_ssl_tcp_multiplex, call_socket);
       SSL_set_bio(L_ssl_tcp_multiplex,m_bio,m_bio);
       // SSL_set_bio(L_ssl_tcp_multiplex,bio,bio);

      if ( (err = SSL_connect(L_ssl_tcp_multiplex)) < 0 ) {
           ERROR("Error in SSL connection \n");
  }
       ssl_list[call_socket] = L_ssl_tcp_multiplex;

  
     }
#endif


  /* Asks to receive incoming messages */
  pollset_index = pollset_add(this, call_socket);
    }
  }
  }
}

bool lost(int percent)
{
  static int inited = 0;

  if(!lose_packets) return false;
  if(!percent) return false;

  if(!inited) {
    srand((unsigned int) time(NULL));
    inited = 1;
  }

  if((rand() % 100) < percent) {
    return true;
  } else {
    return false;
  }
}

int call::send_raw(char * msg, int index) 
{
  void ** state;
  int sock;
  int rc;
#ifdef _USE_OPENSSL
  SSL *ssl;
  // extern SSL *ssl_list[];
#endif
  if (useMessagef == 1) { 
  struct timeval currentTime;
  GET_TIME (&currentTime);
  TRACE_MSG((s, "----------------------------------------------- %s\n"
             "%s message sent:\n\n%s\n",
             CStat::instance()->formatTime(&currentTime),
             TRANSPORT_TO_STRING(transport),
             msg));
  }
  
  if((index!=-1) && (lost(scenario[index] -> lost))) {
    TRACE_MSG((s, "%s message voluntary lost (while sending).", TRANSPORT_TO_STRING(transport)));
    
    if(comp_state) { comp_free(&comp_state); }
    scenario[index] -> nb_lost++;
    return 0;
  }
  
  if(call_socket) {
    state = &comp_state;
    sock = call_socket;

    if ((use_remote_sending_addr) && (toolMode == MODE_SERVER)) {
      if (!call_remote_socket) {
        struct sockaddr_storage *L_dest = &remote_sending_sockaddr;

        if(transport == T_UDP) {        
        if((call_remote_socket= socket(use_ipv6 ? AF_INET6 : AF_INET,
  				         SOCK_DGRAM,
                            0))== -1) {
          ERROR_NO("Unable to get a socket for rsa option");
        }
	  if(bind(call_remote_socket,
                  (sockaddr *)(void *)L_dest,
                  use_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
              ERROR_NO("Unable to bind UDP socket for rsa option");
          }   
        } else {
	  if((call_remote_socket= socket(use_ipv6 ? AF_INET6 : AF_INET,
		  		          SOCK_STREAM,
					  0))== -1) {
            ERROR_NO("Unable to get a socket for rsa option");
	  }
        sipp_customize_socket(call_remote_socket);

        if(connect(call_remote_socket,
               (struct sockaddr *)(void *)L_dest,
	        SOCK_ADDR_SIZE(&remote_sockaddr))) {
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

#ifdef _USE_OPENSSL
    ssl  = ssl_list[sock];
    // ssl  = m_ssl;
#endif
  } else {
    state = &monosocket_comp_state;
    if(transport == T_UDP) {
      sock = main_socket;
    } else {
      sock = tcp_multiplex;
#ifdef _USE_OPENSSL
      ssl = ssl_tcp_multiplex;
#endif
    }
  }

#ifdef _USE_OPENSSL
  if ( transport == T_TLS ) {
    rc = send_message_tls(ssl, state, msg);
  } else {
#endif
  rc = send_message(sock, state, msg);
#ifdef _USE_OPENSSL
  }
#endif

  if(rc == -1) return -1;

  if(rc < -1) {
    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    CStat::instance()->computeStat(CStat::E_FAILED_CANNOT_SEND_MSG);
    delete_call(id);
  }
  
  return rc; /* OK */
}

/* This method is used to send messages that are not */
/* part of the XML scenario                          */
int call::sendBuffer(char * msg) 
{
  int rc;

  /* call send_raw but with a special scenario index */
  rc=send_raw(msg, -1);

  return rc;
}


char * call::compute_cseq(char * src)
{
  char *dest;
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

char * call::get_last_header(char * name)
{
  static char last_header[MAX_HEADER_LEN * 10];
  char * src, *dest, *ptr;
  char src_tmp[MAX_HEADER_LEN+1] = "\n";

  if((!last_recv_msg) || (!strlen(last_recv_msg))) {
    return NULL;
  }

  src = last_recv_msg;
  dest = last_header;
  strncpy(src_tmp+1, name, MAX_HEADER_LEN);
  if (strlen(name) > MAX_HEADER_LEN) {
    ERROR_P2("call::get_last_header: Header to parse bigger than %d (%d)", MAX_HEADER_LEN, strlen(name));
  }
  while(src = strcasestr2(src, src_tmp)) {
    src++;
    ptr = strchr(src, '\n');
    
    /* Multiline headers always begin with a tab or a space
     * on the subsequent lines */
    while((ptr) &&
          ((*(ptr+1) == ' ' ) ||
           (*(ptr+1) == '\t')    )) {
      ptr = strchr(ptr + 1, '\n'); 
    }

    if(ptr) { *ptr = 0; }
    // Add \r\n when several Via header are present (AgM) 
    if (dest != last_header) {
      dest += sprintf(dest, "\r\n");
    }
    dest += sprintf(dest, "%s", src);
    if(ptr) { *ptr = '\n'; }
    
    src++;
  }
  
  if(dest == last_header) {
    return NULL;
  }

  *(dest--) = 0;

  /* Remove trailing whitespaces, tabs, and CRs */
  while ((dest > last_header) && 
         ((*dest == ' ') || (*dest == '\r')|| (*dest == '\t'))) {
    *(dest--) = 0;
  }

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

  return last_header;
}

char * call::get_header_content(char* message, char * name)
{
  /* non reentrant. consider accepting char buffer as param */
  static char last_header[MAX_HEADER_LEN * 10];
  char * src, *dest, *ptr;

  /* returns empty string in case of error */
  memset(last_header, 0, sizeof(last_header));

  if((!message) || (!strlen(message))) {
    return last_header;
  }

  src = message;
  dest = last_header;
  
  /* for safety's sake */
  if (NULL == name || NULL == strrchr(name, ':')) {
      return last_header;
  }

  while(src = strcasestr2(src, name)) {

      /* just want the header's content */
      src += strlen(name);

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
      dest += sprintf(dest, ",");
    }
    dest += sprintf(dest, "%s", src);
    if(ptr) { *ptr = '\n'; }
    
    src++;
  }
  
  if(dest == last_header) {
    return last_header;
  }

  *(dest--) = 0;

  /* Remove trailing whitespaces, tabs, and CRs */
  while ((dest > last_header) && 
         ((*dest == ' ') || (*dest == '\r')|| (*dest == '\t'))) {
    *(dest--) = 0;
  }
  
  /* Remove leading whitespaces */
  while (*last_header == ' ') {
      strcpy(last_header, &last_header[1]);
  }

  /* remove enclosed CRs in multilines */
  while(ptr = strchr(last_header, '\r')) {
    /* Use strlen(ptr) to include trailing zero */
    memmove(ptr, ptr+1, strlen(ptr));
  }

  return last_header;
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
      *send_status = 
        send_raw(msg_buffer, index);
    } else {
      send_raw(msg_buffer, index);
    }
  } else {
    ERROR("Unsupported 'send' message in scenario");
  }

  return msg_buffer;
}

bool call::next()
{
  int test = scenario[msg_index]->test;
  /* What is the next message index? */
  if ( scenario[msg_index]->next && 
       ((test == -1) ||
        (test < SCEN_VARIABLE_SIZE && M_callVariableTable[test] != NULL && M_callVariableTable[test]->isSet()))
     ) {
    /* For branching, use the 'next' attribute value */
         msg_index = labelArray[scenario[msg_index]->next];
  } else {
    /* Without branching, use the next message */
  msg_index++;
  }
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
  struct timeval  L_currentTime   ;
  double          L_stop_time     ;
  bool            bInviteTransaction = false;
  int             actionResult = 0;

  if(msg_index >= scenario_len) {
    ERROR_P3("Scenario overrun for call %s (%08x) (index = %d)\n", 
             id, this, msg_index);
  }

  /* Manages retransmissions or delete if max retrans reached */
  if(next_retrans && (next_retrans < clock_tick)) {
    nb_retrans++;
    
    if ( (0 == strncmp (last_send_msg, "INVITE", 6)) )
    {
      bInviteTransaction = true;
    }

    if((nb_retrans > (bInviteTransaction ? UDP_MAX_RETRANS_INVITE_TRANSACTION : UDP_MAX_RETRANS_NON_INVITE_TRANSACTION)) || 
       (nb_retrans > max_udp_retrans)) {
      scenario[last_send_index] -> nb_timeout ++;
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
      next_retrans = clock_tick + nb_last_delay;
    }
  }

  if(paused_until) {

    /* Process a pending pause instruction until delay expiration */
    if(paused_until > clock_tick) {
      return true;
    } else {
      paused_until = 0;
      return next();
    }
  } else if(scenario[msg_index] -> pause) {
    /* Starts a pause instruction */
    if((scenario[msg_index] -> pause) == -1) {
      paused_until = clock_tick + duration;
    } else {
      paused_until = clock_tick + scenario[msg_index] -> pause;
    }
    /* Increment the number of sessions in pause state */
    ++scenario[msg_index]->sessions;
    return run(); /* In case delay is 0 */
    
  } else if(scenario[msg_index] -> pause_max) {
    /* Starts a variable pause instruction */
    paused_until = clock_tick + 
      scenario[msg_index] -> pause_min + rand() % (scenario[msg_index] -> pause_max - 
                                                   scenario[msg_index] -> pause_min); 
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
    actionResult = executeAction(NULL, msg_index);
    return(next());
  }
  else if(scenario[msg_index] -> send_scheme) {

    char * msg_snd;
    int send_status;

    /* Do not send a new message until the previous one which had
     * retransmission enabled is acknowledged */

    if(next_retrans) {
      return true;
    }

    /* If this message can be used to compute RTD, do it now */
    if(!rtd_done) {
      if(scenario[msg_index] -> start_rtd) {
        start_time_rtd = clock_tick;
      }
  
      if(scenario[msg_index] -> stop_rtd) {
        rtd_sum += clock_tick - start_time_rtd;

        if(dumpInRtt) {
          GET_TIME (&L_currentTime);
          L_stop_time = (double)L_currentTime.tv_sec*1000.0 +
                        (double)(L_currentTime.tv_usec)/(double)1000.0 ;
          CStat::instance()->computeRtt(start_time_rtd, L_stop_time) ;
        }

        CStat::instance()->computeStat(CStat::E_ADD_RESPONSE_TIME_DURATION,
                                           clock_tick - start_time_rtd);
        rtd_nb ++;
        rtd_done = true;
      }
    }
  
    /* decide whether to increment cseq or not 
     * basically increment for anything except response, ACK or CANCEL 
     * Note that cseq is only used by the [cseq] keyword, and
     * not by default
     */
    
    if (strncmp(::scenario[msg_index]->send_scheme,"ACK",3) &&
       strncmp(::scenario[msg_index]->send_scheme,"CANCEL",6) &&
       strncmp(::scenario[msg_index]->send_scheme,"SIP/2.0",7)) {
          ++cseq;
    }

    if ((ctrlEW) || (poll_flag_write)) {
      send_status = -1;
    } else {
    msg_snd = send_scene(msg_index, &send_status);
    }

    if(send_status == -1) { /* Would Block on TCP */
       if (msg_index == 0 ) 
          delete_call(id) ;
      return true; /* No step, nothing done, retry later */
    }

    if(send_status <-1) { /* Send error */
      return false; /* call deleted */
    }
    
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
  }
  return true;
}

bool call::process_unexpected(char * msg)
{
  int search_index;
  static int first = 1;
  int res ;
  
  scenario[msg_index] -> nb_unexp++;
  
  if (scenario[msg_index] -> recv_request) {
    if (default_behavior) {
      WARNING_P3("Aborting call on unexpected message for Call-ID '%s': while expecting '%s', received '%s' ",
                id, scenario[msg_index] -> recv_request, msg);
  } else {
      WARNING_P3("Continuing call on unexpected message for Call-ID '%s': while expecting '%s', received '%s' ",
                  id, scenario[msg_index] -> recv_request, msg);
    }
  } else {
    if (default_behavior) {
      WARNING_P3("Aborting call on unexpected message for Call-ID '%s': while expecting '%d' response, received '%s' ", 
                  id, scenario[msg_index] -> recv_response, msg);
    } else {
      WARNING_P3("Continuing call on unexpected message for Call-ID '%s': while expecting '%d' response, received '%s' ", 
                id, scenario[msg_index] -> recv_response, msg);
  }
  }
  
  TRACE_MSG((s, "-----------------------------------------------\n"
             "Unexpected %s message received:\n\n%s\n",
             TRANSPORT_TO_STRING(transport),
             msg));
  
  if (default_behavior) {
#ifdef __3PCC__
  // if twin socket call => reset the other part here 
  if (twinSippSocket && (msg_index > 0)) {
    //WARNING_P2("call-ID '%s', internal-cmd: abort_call %s",id, "");
    res = sendCmdBuffer
      (createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n", -1));
  }
#endif /* __3PCC__ */

  // usage of last_ keywords => for call aborting
  last_recv_msg = (char *) realloc(last_recv_msg, strlen(msg) + 1);
  strcpy(last_recv_msg, msg);

    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    CStat::instance()->computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
  return (abortCall());
  } else {
    // Do not abort call nor send anything in reply if default behavior is disabled
    return true;
  }
}

bool call::abortCall()
{
  int res ;
  int is_inv;

  if (last_send_msg != NULL) {
    is_inv = !strncmp(last_send_msg, "INVITE", 6);
  } else {
    is_inv = false;
  }  

  if ((toolMode != MODE_SERVER) && (msg_index > 0)) {
    if ((call_established == false) && (is_inv)) {
      char * src = last_recv_msg ;
      char * dest   ;
      char   L_msg_buffer[SIPP_MAX_MSG_SIZE];
      L_msg_buffer[0] = '\0';
      char * L_param = L_msg_buffer;

      // Answer unexpected errors (4XX, 5XX and beyond) with an ACK 
      // Contributed by F. Tarek Rogers
      if((src) && (get_reply_code(src) > 400)) {
       sendBuffer(createSendingMessage(
         (char*)"ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
           "Via: SIP/2.0/[transport] [local_ip]:[local_port]\n"
           "From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]\n"
           "To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
           "Call-ID: [call_id]\n"
           "CSeq: 1 ACK\n"
           "Contact: sip:sipp@[local_ip]:[local_port]\n"
           "Max-Forwards: 70\n"
           "Subject: Performance Test\n"
           "Content-Length: 0\n\n"
         , -1));
      } else if (src) {
        /* Call is not established and the reply is not a 4XX, 5XX */
        /* And we already received a message. */
        if (ack_is_pending == true) {
          /* If an ACK is expected from the other side, send it
           * and send a BYE afterwards                           */
          ack_is_pending = false;
          /* Send an ACK */
          strcpy(L_param, "ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n");
          sprintf(L_param, "%s%s", L_param, "Via: SIP/2.0/[transport] [local_ip]:[local_port]\n");
          sprintf(L_param, "%s%s", L_param, "From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]\n");
          sprintf(L_param, "%s%s", L_param, "To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n");
          sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
          /* The CSeq of an ACK relating to an INVITE must be the same as  */
          /* the one from the INVITE.                                      */
          /* Let's simplify this by putting 1 (no support for re-invite in */
          /* 3PCC?)                                                        */
          /* FIXME: store CSeq from last INVITE and re-use it              */
          sprintf(L_param, "%sCSeq: 1 ACK\n", L_param);
          sprintf(L_param, "%s%s", L_param, "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
          sprintf(L_param, "%s%s", L_param,  "Content-Length: 0\n");
          res = sendBuffer(createSendingMessage((char*)(L_param),-1));
          
          /* Send the BYE */
          strcpy(L_param, "BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n");
          sprintf(L_param, "%s%s", L_param, "Via: SIP/2.0/[transport] [local_ip]:[local_port]\n");
          sprintf(L_param, "%s%s", L_param, "From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]\n");
          sprintf(L_param, "%s%s", L_param, "To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n");
          sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
          char * cseq;
          cseq = compute_cseq(src);
          if (cseq != NULL) {
            sprintf(L_param, "%s%s BYE\n", L_param, compute_cseq(src));
          }
          sprintf(L_param, "%s%s", L_param, "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
          sprintf(L_param, "%s%s", L_param,  "Content-Length: 0\n");
          res = sendBuffer(createSendingMessage((char*)(L_param),-1));
        } else {
          /* Send a CANCEL */
          strcpy(L_param, "CANCEL sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n");
          sprintf(L_param, "%s%s", L_param, "Via: SIP/2.0/[transport] [local_ip]:[local_port]\n");
          sprintf(L_param, "%s%s", L_param, "From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]\n");
          sprintf(L_param, "%s%s", L_param, "To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n");
          sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
	  sprintf(L_param, "%sCSeq: 1 CANCEL\n", L_param);
          sprintf(L_param, "%s%s", L_param, "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
          sprintf(L_param, "%s%s", L_param,  "Content-Length: 0\n");
          res = sendBuffer(createSendingMessage((char*)(L_param),-1));
        }
      } else {
        /* Call is not established and the reply is not a 4XX, 5XX */
        /* and we didn't received any message. This is the case when */
        /* we are aborting after having send an INVITE and not received */
        /* any answer. */
        /* Do nothing ! */
      }
    } else {
      /* Call is established */
      char * src = last_recv_msg ;
      char   L_msg_buffer[SIPP_MAX_MSG_SIZE];
      L_msg_buffer[0] = '\0';
      char * L_param = L_msg_buffer;
      strcpy(L_param, "BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n");
      sprintf(L_param, "%s%s", L_param, "Via: SIP/2.0/[transport] [local_ip]:[local_port]\n");
      sprintf(L_param, "%s%s", L_param, "From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]\n");
      sprintf(L_param, "%s%s", L_param, "To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n");
      sprintf(L_param, "%s%s", L_param, "Call-ID: [call_id]\n");
      char * cseq;
      cseq = compute_cseq(src);
      if (cseq != NULL) {
        sprintf(L_param, "%s%s BYE\n", L_param, compute_cseq(src));
      }
      sprintf(L_param, "%s%s", L_param, "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n");
      sprintf(L_param, "%s%s", L_param,  "Content-Length: 0\n");
      res = sendBuffer(createSendingMessage((char*)(L_param),-1));
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


#ifdef __3PCC__
int call::sendCmdMessage(int index)
{
  char * dest;
  char delimitor[2];
  delimitor[0]=27;
  delimitor[1]=0;

  if(scenario[index] -> M_sendCmdData) {
    // WARNING_P1("---PREPARING_TWIN_CMD---%s---", scenario[index] -> M_sendCmdData); 
    dest = createSendingMessage(scenario[index] -> M_sendCmdData, -2);
    strcat(dest, delimitor);
    //WARNING_P1("---SEND_TWIN_CMD---%s---", dest); 

    int rc;

    rc = send(twinSippSocket, 
              dest, 
              strlen(dest), 
              0);
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


  rc = send(twinSippSocket, 
            dest, 
            strlen(dest), 
            0);
  if(rc <  0) {
    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
    CStat::instance()->computeStat(CStat::E_FAILED_CMD_NOT_SENT);
    delete_call(id);
    return(-1);
  }

  return(0);
}

#endif

char* call::createSendingMessage(char * src, int P_index)
{
  static char msg_buffer[SIPP_MAX_MSG_SIZE+2];
 
  if(src != NULL) {
    char * dest = msg_buffer;
    char * key;
    char * length_marker = NULL;
    const char * auth_marker = NULL;
    int auth_marker_len = 0;
    int    offset = 0;
    int    len_offset = 0;
    char   current_line[MAX_HEADER_LEN];
    char * line_mark = NULL;

    current_line[0] = '\0';
    while(*src) {
      if (current_line[0] == '\0') {
        line_mark = NULL;
        line_mark = strchr(src, '\n');
        if (line_mark) {
          memcpy(current_line, src, line_mark - src);
          current_line[line_mark-src] = '\0';
        }
      }
      if ((*src == '\\') && (*(src+1) == 'x')) {
        /* Allows any hex coded char like '\x5B' ([) */
        src += 2;
        if (isxdigit(*src)) {
          int val = get_decimal_from_hex(*src);
          src++;
          if (isxdigit(*src)) {
            val = (val << 4) + get_decimal_from_hex(*src);
          }
          *dest++ = val & 0xff;
        }
        src++;
      } else if(*src == '[') {
        char keyword [KEYWORD_SIZE+1];
        src++;
        key = strchr(src, ']');
        if((!key) || ((key - src) > KEYWORD_SIZE) || (!(key - src))){
          ERROR("Syntax error or invalid [keyword] in scenario");
        }
        memcpy(keyword, src,  key - src);
 
        keyword[key - src] = 0;
        src = key + 1;
        // allow +/-n for numeric variables
        if (!strstr(keyword, "authentication") && !strstr(keyword, "map") && ((key = strchr(keyword,'+')) || (key = strchr(keyword,'-')))) {
          offset = atoi(key);
          *key = 0;
        } else offset = 0;

        if(!strcmp(keyword, "remote_ip")) {
          dest += sprintf(dest, "%s", remote_ip_escaped);
        } else if(!strcmp(keyword, "remote_port")) {
          dest += sprintf(dest, "%u", remote_port + offset);
        } else if(!strcmp(keyword, "transport")) {
          dest += sprintf(dest, "%s", TRANSPORT_TO_STRING(transport));
        } else if(!strcmp(keyword, "local_ip")) {
          dest += sprintf(dest, "%s", local_ip_escaped);
        } else if(!strcmp(keyword, "local_ip_type")) {
          dest += sprintf(dest, "%s", (local_ip_is_ipv6 ? "6" : "4"));
        } else if(!strcmp(keyword, "local_port")) {
          if((transport == T_UDP) && (multisocket) && (toolMode != MODE_SERVER)) {
            dest += sprintf(dest, "%u", call_port + offset);
          } else {
            dest += sprintf(dest, "%u", local_port + offset);
          }
        } else if(!strcmp(keyword, "server_ip")) {
          struct sockaddr_storage server_sockaddr;
          sipp_socklen_t len = SOCK_ADDR_SIZE(&server_sockaddr);
          getsockname(call_socket,
                (sockaddr *)(void *)&server_sockaddr,
                &len);
          if (server_sockaddr.ss_family == AF_INET6) {
            char * temp_dest;
            temp_dest = (char *) malloc(INET6_ADDRSTRLEN);
            memset(temp_dest,0,INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, 
                      &((_RCAST(struct sockaddr_in6 *,&server_sockaddr))->sin6_addr),
                      temp_dest,
                      INET6_ADDRSTRLEN); 
            dest += sprintf(dest, "%s",temp_dest);
          } else {
            dest += sprintf(dest, "%s", 
            inet_ntoa((_RCAST(struct sockaddr_in *,&server_sockaddr))->sin_addr));
          }          
        } else if(!strcmp(keyword, "media_ip")) {
          dest += sprintf(dest, "%s", media_ip_escaped);
#ifdef PCAPPLAY
        } else if (!strcmp(keyword, "auto_media_port")) {
          /* to make media ports begin from true media_port exported from sipp.cpp, as number begins to 1
           * * 4 to allow video (audio+rtcp+video+rtcp)
           * Modulo 10000 to limit the port number
           * -> Max 10000 concurrent RTP sessions for pcap_play 
           */
          int port = media_port + (4 * (number - 1)) % 10000 + offset;
          if (strstr(current_line, "m=audio ")) {
            if (media_ip_is_ipv6) {
              (_RCAST(struct sockaddr_in6 *, &(play_args_a.from)))->sin6_port = port;
            } else {
              (_RCAST(struct sockaddr_in *, &(play_args_a.from)))->sin_port = port;
            }
          } else if (strstr(current_line, "m=video ")) {
          if (media_ip_is_ipv6) {
              (_RCAST(struct sockaddr_in6 *, &(play_args_v.from)))->sin6_port = port;
          } else {
              (_RCAST(struct sockaddr_in *, &(play_args_v.from)))->sin_port = port;
            }
          } else {
            ERROR_P1("auto_media_port keyword with no audio or video on the current line (%s)", current_line);
          }
          dest += sprintf(dest, "%u", port);
#endif
        } else if(!strcmp(keyword, "media_port")) {
          int port = media_port + offset;
#ifdef PCAPPLAY
          if (strstr(current_line, "audio")) {
            if (media_ip_is_ipv6) {
              (_RCAST(struct sockaddr_in6 *, &(play_args_a.from)))->sin6_port = port;
            } else {
              (_RCAST(struct sockaddr_in *, &(play_args_a.from)))->sin_port = port;
            }
          } else if (strstr(current_line, "video")) {
          if (media_ip_is_ipv6) {
              (_RCAST(struct sockaddr_in6 *, &(play_args_v.from)))->sin6_port = port;
            } else {
              (_RCAST(struct sockaddr_in *, &(play_args_v.from)))->sin_port = port;
            }
          } else {
            ERROR_P1("media_port keyword with no audio or video on the current line (%s)", current_line);
          }
#endif
          dest += sprintf(dest, "%u", port);
        } else if(!strcmp(keyword, "media_ip_type")) {
          dest += sprintf(dest, "%s", (media_ip_is_ipv6 ? "6" : "4"));
        } else if(!strcmp(keyword, "call_number")) {
          dest += sprintf(dest, "%lu", number);
        } else if(!strcmp(keyword, "call_id")) {
          dest += sprintf(dest, "%s", id);
        } else if(!strcmp(keyword, "cseq")) {
          dest += sprintf(dest, "%u", cseq +offset);
        } else if(!strcmp(keyword, "pid")) {
          dest += sprintf(dest, "%u", pid);
        } else if(!strcmp(keyword, "service")) {
          dest += sprintf(dest, "%s", service);
        } else if(!strncmp(keyword, "field", 5)) {
            char* local_dest = dest;
            getFieldFromInputFile(keyword, m_localLineNumber, dest);
            if (dest == local_dest && ('\r' == *(local_dest-1) || '\n' == *(local_dest-1))) {
                /* If the line begins with a field value and there
                 * is nothing to add for this field, 
                 * Jump to the end of line in scenario. SN 
                 */
                while((*src) && (*src != '\n')) {
                    src++;
                }
                if(*src == '\n') {
                    src++;
                }
            }
        } else if(!strcmp(keyword, "peer_tag_param")) {
          if(peer_tag && strlen(peer_tag)) {
            dest += sprintf(dest, ";tag=%s", peer_tag);
          }
        } else if(strstr(keyword, "map")) {
          /* keyword to generate c= line for TDM 
           * format: g.h.i/j                    
           * g: varies in interval a, offset x
           * h: fix value (99 here)
           * i: varies in interval b, offset y
           * j: varies in interval c, offset z
           * Format: map{1-3}{0-27}{1-24}
           */
          int h=99; 
          int a=0; /* or 2-0 */
          int b=27-0;
          int c=24-1;
          int x=0;
          int y=0;
          int z=1;
          int i1, i2, i3, i4, i5, i6;

          if (sscanf(keyword, "map{%d-%d}{%d-%d}{%d-%d}", &i1, &i2, &i3, &i4, &i5, &i6) == 6) {
            a = i2 - i1;
            x = i1;
            b = i4 - i3;
            y = i3;
            c = i6 - i5;
            z = i5;
            dest += sprintf(dest, "%d.%d.%d/%d", 
                                  x+(int((number-1)/((b+1)*(c+1))))%(a+1),
                                  h,
                                  y+(int((number-1)/(c+1)))%(b+1),
                                  z+(number-1)%(c+1)
                                  );
          } else {
            ERROR_P1("Keyword '%s' cannot be parsed - must be of the form 'map{%%d-%%d}{%%d-%%d}{%%d-%%d}'", keyword);
          }
        } else if(strstr(keyword, "$")) {
          int varId = atoi(keyword+1);
          if(varId < SCEN_VARIABLE_SIZE) {
            if(M_callVariableTable[varId] != NULL) {
              if(M_callVariableTable[varId]->isSet()) {
                dest += sprintf(dest, "%s",
                                M_callVariableTable[varId]->
                                getMatchingValue());
                // WARNING_P1("VARIABLE --%s--", M_callVariableTable[varId]->getMatchingValue());
              } else {
                dest += sprintf(dest, "%s", "");
              }
            }
          }
        } else if(strstr(keyword, "last_")) {
          char * last_header = get_last_header(keyword+5);
          if(last_header) {
            dest += sprintf(dest, "%s", last_header);
          } else {
            /* Jump to the end of line in scenario if nothing
             * to insert in place of this header. */
            while((*src) && (*src != '\n')) {
              src++;
            }
            if(*src == '\n') {
              src++;
            }
          }
        } else if(strstr(keyword, "routes")) {
            if (dialog_route_set) {
                dest += sprintf(dest, "Route: %s", dialog_route_set);
            }
#ifdef _USE_OPENSSL
        } else if(strstr(keyword, "authentication")) {
            /* This keyword is substituted below */
            dest += sprintf(dest, "[%s]", keyword);
#endif
        } else if(strstr(keyword, "branch")) {
          /* Branch is magic cookie + call number + message index in scenario */
          dest += sprintf(dest, "z9hG4bK-%lu-%d", number, P_index);
        } else if(strstr(keyword, "msg_index")) {
          /* Message index in scenario */
          dest += sprintf(dest, "%d", P_index);
        } else if(strstr(keyword, "next_url")) {
          if (next_req_url) {
            dest += sprintf(dest, "%s", next_req_url);
          }
        } else if(strstr(keyword, "len")) {
            length_marker = dest;
            dest += sprintf(dest, "    ");
            len_offset = offset;
        } else {   // scan for the generic parameters - must be last test
          int i = 0;
          while (generic[i]) {
            char *msg1 = *generic[i];
            char *msg2 = *(generic[i] + 1);
            if(!strcmp(keyword, msg1+1)) {
              dest += sprintf(dest, "%s", msg2);
              break;
            }
            ++i;
          }
          if (!generic[i]) {
            ERROR_P1("Unsupported keyword '%s' in xml scenario file",
                   keyword);
          }
        }
      } else if (*src == '\n') {
        *dest++ = '\r';
        *dest++ = *src++;
        current_line[0] = '\0';
      } else {
        *dest++ = *src++;
      }
    }
    *dest = 0;

#ifdef _USE_OPENSSL
    /* 
     * The authentication substitution must be done outside the above
     * loop because auth-int will use the body (which must have already
     * been keyword substituted) to build the md5 hash
     */

    if((src = strstr(msg_buffer, "[authentication")) && dialog_authentication) {

        char my_auth_user[KEYWORD_SIZE];
        char my_auth_pass[KEYWORD_SIZE];
        char * tmp;
        int  authlen;

        auth_marker = src;
        auth_marker_len = strchr(src, ']') - src;
        strcpy(my_auth_user, service);
        strcpy(my_auth_pass, auth_password);
        /* Look for optional username and password paramaters */
        if(tmp = strstr(src, "username=")) {
            tmp += strlen("username=");
            key = tmp;
            while (*key) {
                if (((key - src) > KEYWORD_SIZE) || (!(key - src))) {
                    ERROR("Syntax error parsing authentication paramaters");
                } else if (*key == ']' || *key < 33 || *key > 126) {
                    memset(my_auth_user, 0, sizeof(my_auth_user));
                    strncpy(my_auth_user, tmp, key-tmp);
                    break;
                }
                key++;
            }
        }

        if(tmp = strstr(src, "password=")) {
            tmp += strlen("password=");
            key = tmp;
            while (*key) {
                if (((key - src) > KEYWORD_SIZE) || (!(key - src))) {
                    ERROR("Syntax error parsing authentication paramaters");
                } else if (*key == ']' || *key < 33 || *key > 126) {
                    memset(my_auth_pass, 0, sizeof(my_auth_pass));
                    strncpy(my_auth_pass, tmp, key-tmp);
                    break;
                }
                key++;
            }
        }

        /* Need the Method name from the CSeq of the Challenge */
        char method[MAX_HEADER_LEN];
        tmp = get_last_header("CSeq") + 5;
        if(!tmp) {
            ERROR("Could not extract method from cseq of challenge");
        }
        while(isspace(*tmp) || isdigit(*tmp)) tmp++;
        sscanf(tmp,"%s", &method);

        /* Need the body for auth-int calculation */
        char body[SIPP_MAX_MSG_SIZE];
        memset(body, 0, sizeof(body));
        tmp = msg_buffer;
        while(*(tmp+4)) {
            if (*tmp == '\r' && *(tmp + 1) == '\n' &&
                    *(tmp + 2) == '\r' && *(tmp + 3) == '\n') {
                sprintf(body, "%s", tmp+4);
                break;
            }
            tmp++;                      
        }

        /* Build the auth credenticals */
        char result[MAX_HEADER_LEN];
        char uri[MAX_HEADER_LEN];
        sprintf (uri, "%s:%d", remote_ip, remote_port);
        if (createAuthHeader(my_auth_user, my_auth_pass, method, uri,
                body, dialog_authentication, result) == 0) {
            ERROR_P1("%s", result);
        }
   
        char tmp_buffer[SIPP_MAX_MSG_SIZE];
        dest = strncpy(tmp_buffer, msg_buffer, src - msg_buffer);
        dest += src - msg_buffer;
        key = strchr(src, ']');
        src += key - src + 1;

        if (dialog_challenge_type == 401) {
          /* Registrars use Authorization */
          authlen = sprintf(dest, "Authorization: %s", result);
        } else {
          /* Proxies use Proxy-Authorization */
          authlen = sprintf(dest, "Proxy-Authorization: %s", result);
        }
        dest += authlen;                 
        if (length_marker > auth_marker) {
          length_marker = length_marker - 1 - auth_marker_len + authlen;
        }
        dest += sprintf(dest, "%s", src);
        strcpy(msg_buffer, tmp_buffer);
	dest = msg_buffer + strlen(msg_buffer);
    }
#endif

    // Remove all \r, \n but 1 at the end of a message to send 
    int len = strlen(msg_buffer);
    while ( (msg_buffer[len-1] == '\n') &&
            (msg_buffer[len-2] == '\r') &&
            (msg_buffer[len-3] == '\n') &&
            (msg_buffer[len-4] == '\r')) {
      msg_buffer[len-2] = 0;
      len -= 2;
    }

    int    L_flag_crlf = 0 ; // don't need add crlf
    int    L_content_length = 0;

    if(P_index == -1 ) {
      L_flag_crlf = 1 ; // Add crlf
    } else if(P_index >= 0 ) {
      message::ContentLengthFlag L_flag_content = scenario[P_index] -> content_length_flag ; 
      switch (L_flag_content) {
        case  message::ContentLengthValueZero :
          L_flag_crlf = 1;
          break ;
        case  message::ContentLengthValueNoZero :
          // the msg contains content-length field and his value is greater than 0
          break ;
        default :
          // the msg does not contain content-length field
          // control the crlf
          L_content_length = xp_get_content_length(msg_buffer) ;
          if( L_content_length == 0) {
            L_flag_crlf = 1;
          } else if (L_content_length == -1 ) {
            // The content_length is not present: its a [len] keyword
          } 
          break;
      }
    } 

    if(L_flag_crlf) {
      // Add crlf 
      msg_buffer[len] ='\r';
      msg_buffer[len+1] ='\n';
      msg_buffer[len+2] =0;
    }

    if (length_marker) {
      key = strstr(length_marker,"\r\n\r\n");
      if (key && dest - key > 4 && dest - key < 10004) {
        char tmp = length_marker[4];
        sprintf(length_marker, "%4u", dest - key - 4 + len_offset);
        length_marker[4] = tmp;
      } else {
        // Other cases: Content-Length is 0
        sprintf(length_marker, "   0\r\n\r\n");
      }
    }
  } else {
    ERROR("Unsupported 'send' message in scenario");
  }
  return(msg_buffer);
}


#ifdef __3PCC__
bool call::process_twinSippCom(char * msg)
{
  int             search_index;
  bool            found = false;
  T_ActionResult  actionResult;

  if (checkInternalCmd(msg) == false) {

    for(search_index = msg_index;
      search_index < scenario_len;
      search_index++) {
      if(scenario[search_index] -> M_type != MSG_TYPE_RECVCMD) {
        if(scenario[search_index] -> optional) {
          continue;
        }
        /* The received message is different from the expected one */
        return rejectCall();
      } else {
        found = true;
        break;
      }
    }
    
    if (found) {
      scenario[search_index]->M_nbCmdRecv ++;
      
      // variable treatment
      // WARNING_P1("---RECVD_TWIN_CMD---%s---", msg); 
      // Remove \r, \n at the end of a received command
      // (necessary for transport, to be removed for usage)
      while ( (msg[strlen(msg)-1] == '\n') &&
      (msg[strlen(msg)-2] == '\r') ) {
        msg[strlen(msg)-2] = 0;
      }
      // WARNING_P1("---RECVD_TWIN_CMD AFTER---%s---", msg);
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
      return rejectCall();
    }
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
#endif


void call::extract_cseq_method (char* method, char* msg)
{
  char* cseq ;
  if (cseq = strstr (msg, "CSeq"))
  {
    char * value ;
    if ( value = strstr (cseq,  ":"))
    {
      value++;
      while ( isspace(*value)) value++;  // ignore any white spaces after the :
      while ( !isspace(*value)) value++;  // ignore the CSEQ numnber
      value++;
      char *end = value;
      int nbytes = 0;
      while ((*end != '\n')) { end++; nbytes++;}
      strncpy (method, value, (nbytes-1));
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

bool call::process_incomming(char * msg)
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

  struct timeval  L_currentTime   ;
  double          L_stop_time     ;

#define MATCHES_SCENARIO(index)                                \
      (((reply_code) &&                                        \
        ((scenario[index] -> recv_response) == reply_code) &&            \
         (scenario[index]->recv_response_for_cseq_method_list) &&   \
        (strstr(scenario[index]->recv_response_for_cseq_method_list, responsecseqmethod))) ||  \
       ((scenario[index] -> recv_request) &&                   \
        (!strcmp(scenario[index] -> recv_request,              \
                 request))))

  memset (responsecseqmethod, 0, sizeof(responsecseqmethod));

  if((transport == T_UDP) && (retrans_enabled)) {

  /* Detects retransmissions from peer and retransmit the 
   * message which was sent just after this one was received */
  cookie = hash(msg);
  if(recv_retrans_hash == cookie) {

    int status;

    if(lost(scenario[recv_retrans_recv_index] -> lost)) {
      TRACE_MSG((s, "%s message (retrans) lost (recv).", 
                 TRANSPORT_TO_STRING(transport)));

      if(comp_state) { comp_free(&comp_state); }
      scenario[recv_retrans_recv_index] -> nb_lost++;
      return true;
    }
    
    send_scene(recv_retrans_send_index, &status);

    if(status == 0) {
      scenario[recv_retrans_recv_index] -> nb_recv_retrans++;
      scenario[recv_retrans_send_index] -> nb_sent_retrans++;
    } else if(status < -1) { 
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
    if (strlen(peer_tag) == 0) {
      ptr = get_peer_tag(msg);
      if (ptr) {
        if(strlen(ptr) > (MAX_HEADER_LEN - 1)) {
          ERROR("Peer tag too long. Change MAX_TAG_LEN and recompile sipp");
        }
        strcpy(peer_tag, ptr);
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
      if ((toolMode == MODE_SERVER)
		&& (strncmp(request, "INVITE", 6) == 0)
		&& (hasMedia == 1)) {
        get_remote_media_addr(msg);
      } else if ((toolMode == MODE_CLIENT)
                // Case of re-INVITE
		&& (strncmp(request, "INVITE", 6) == 0)
		&& (hasMedia == 1)) {
        get_remote_media_addr(msg);
      }
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
    if(!MATCHES_SCENARIO(search_index)) {
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
    for(search_index = msg_index - 1;
        search_index >= 0;
        search_index--) {
      if(MATCHES_SCENARIO(search_index)) {
        if ((scenario[search_index] -> optional)) {
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
               (0 == strncmp(scenario[search_index+1]->send_scheme, "ACK", 3)) ) {
            sendBuffer(createSendingMessage(scenario[search_index+1] -> send_scheme, (search_index+1)));
    }
          return true;
  }
      }
    }
  }

  int test = (!found) ? -1 : scenario[search_index]->test;
  /* test==0: No branching"
   * test==-1 branching without testing"
   * test>0   branching with testing
   */

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
      // handle the error
      return next();
    }
  }
  
  /* Not found */
  if(!found) {
    if ((L_case = checkAutomaticResponseMode(request)) == 0) {
      if (!process_unexpected(msg)) {
        return false; // Call aborted by unexpected message handling
      }
    } else {
      // call aborted by automatic response mode if needed
      return (automaticResponseMode(L_case, msg)); 
    }
  }

  /* Simulate loss of messages */
  if(lost(scenario[search_index] -> lost)) {
    TRACE_MSG((s, "%s message lost (recv).", 
               TRANSPORT_TO_STRING(transport)));
    if(comp_state) { comp_free(&comp_state); }
    scenario[search_index] -> nb_lost++;
    return true;
  }
  
  /* This is an ACK or a response, and its index is greater than the 
   * current active retransmission message, so we stop the retrans timer. */
  if(((reply_code) ||
      ((!strcmp(request, "ACK")) ||
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
  
  /* If this message can be used to compute RTD, do it now */
  if(!rtd_done) {
    if(scenario[search_index] -> start_rtd) {
      start_time_rtd = clock_tick;
    }

    if(scenario[search_index] -> stop_rtd) {
      rtd_sum += clock_tick - start_time_rtd; 

    if(dumpInRtt) {
       GET_TIME (&L_currentTime);
       L_stop_time = (double)L_currentTime.tv_sec*1000.0 +
                     (double)(L_currentTime.tv_usec)/(double)1000.0 ;
       CStat::instance()->computeRtt(start_time_rtd, L_stop_time) ;
    }

      CStat::instance()->
        computeStat(CStat::E_ADD_RESPONSE_TIME_DURATION, 
                    clock_tick - start_time_rtd);
      rtd_nb ++;
      rtd_done = true;
    }
  }

  /* Increment the recv counter */
  scenario[search_index] -> nb_recv++;

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

      dialog_authentication = (char *) calloc(1, strlen(auth) + 2);
      sprintf(dialog_authentication, "%s", auth);

      /* Store the code of the challenge for building the proper header */
      dialog_challenge_type = reply_code;
  }
#endif

  /* If this was a mandatory message, and keeps its cookie for
   * future retransmissions, and its body for fields inclusion
   * in our messages. Similarly if there is an explicit next label set 
   */
  if (!(scenario[search_index] -> optional) ||
       scenario[search_index]->next && 
      ((test == -1) ||
       (test < SCEN_VARIABLE_SIZE && M_callVariableTable[test] != NULL && M_callVariableTable[test]->isSet()))
     ) {
    msg_index = search_index;

    /* Store last recv msg information */
    last_recv_index = search_index;
    last_recv_hash = cookie;

    last_recv_msg = (char *) realloc(last_recv_msg, strlen(msg) + 1);
    strcpy(last_recv_msg, msg);
    return next();
  }
  return true;
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
    for(int i=0; i<actions->getUsedAction(); i++) {
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
                                msgPart);
        
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
            if (currentAction->getActionType() == CAction::E_AT_LOG_TO_FILE) {
            char* x = createSendingMessage(currentAction->getMessage(), -2 /* do not add crlf*/);
            LOG_MSG((s, "%s\n", x));
        } else /* end action == E_AT_LOG_TO_FILE */ 
            if (currentAction->getActionType() == CAction::E_AT_EXECUTE_CMD) {

            if (currentAction->getCmdLine()) {
                char* x = createSendingMessage(currentAction->getCmdLine(), -2 /* do not add crlf*/);
                // TRACE_MSG((s, "Trying to execute [%s]", x)); 
                pid_t l_pid;
                switch(l_pid = fork())
                {
                    case -1:
                        // error when forking !
                        ERROR("Forking error");
                        break;

                    case 0:
                        // child process - execute the command
                        system(x);
                        exit(EXIT_OTHER);

                    default:
                        // parent process continue
                        break;
                }
            }
        } else /* end action == E_AT_LOG_TO_FILE */ 
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
        } else {// end action == E_AT_EXECUTE_CMD
          ERROR("call::executeAction unknown action");
        }
      } // end if current action != null
    } // end for
  }
  return(call::E_AR_NO_ERROR);
}

void call::extractSubMessage(char * msg, char * matchingString, char* result)
{
  char * ptr;
  int sizeOf;
  int i = 0;
  int len;

  ptr = strstr(msg, matchingString); 
  if(ptr != NULL) {
    len = strlen(matchingString);
    strcpy(result, ptr+len);
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

void call::dumpFileContents(void)
{
    WARNING_P3("Line choosing strategy is [%s]. m_counter [%d] numLinesInFile [%d]",
               m_usage == InputFileSequentialOrder ? "SEQUENTIAL" : "RANDOM",
               m_counter, numLinesInFile);

    for (int i(0); i < numLinesInFile && fileContents[i][0]; ++i) {
        WARNING_P2("%dth line reads [%s]", i, fileContents[i].c_str());
    }
}

/* Read MAX_CHAR_BUFFER_SIZE size lines from the
 * "fileName" and populate it in the fileContents
 * vector. The file should not be more than
 * MAX_LINES_IN_FILE lines long and each line
 * should be terminated with a '\n'
 */

void call::readInputFileContents(const char* fileName)
{
  ifstream *inFile    = new ifstream(fileName);
  ifstream &inFileObj = *inFile;
  char      line[MAX_CHAR_BUFFER_SIZE];
  
  if (!inFile->good()) {
    ERROR_P1("Unable to open file %s", fileName);
    return ;
  }

  numLinesInFile = 0;
  call::m_counter = 0;
  line[0] = '\0';
  inFileObj.getline(line, MAX_CHAR_BUFFER_SIZE);

  if (NULL != strstr(line, "RANDOM")) {
      call::m_usage = InputFileRandomOrder;
  } else if (NULL != strstr(line, "SEQUENTIAL")) {
      call::m_usage = InputFileSequentialOrder;
  } else {
      // default
      call::m_usage = InputFileSequentialOrder;
  }

  while (!inFileObj.eof()) {
    line[0] = '\0';
    inFileObj.getline(line, MAX_CHAR_BUFFER_SIZE);
    if (line[0]) {
      if ('#' != line[0]) {
        fileContents.push_back(line);
        numLinesInFile++; /* this counts number of valid data lines */
      }
    } else {
      break;
    }
  }
  // call::dumpFileContents();
  delete inFile;
}
 
void call::getFieldFromInputFile(const char* keyword, int lineNum, char*& dest)
{
  int nthField    = atoi(keyword+5 /*strlen("field")*/);
  int origNth     = nthField;
  
  if (fileContents.size() > lineNum) {
    const string& line = fileContents[lineNum];
    
    // WARNING_P3("lineNum [%d] nthField [%d] line [%s]",
    //         lineNum, nthField, line.c_str());
    
    int pos(0), oldpos(0);
    do {
      oldpos = pos;
      int localint = line.find(';', oldpos);
      
      if (localint != string::npos) {
        pos = localint + 1;
      } else {
        pos = localint;
        break;
      }
      
      //string x = line.substr(oldpos, pos - oldpos);
      // WARNING_P3("pos [%d] oldpos [%d] is [%s]", pos, oldpos, x.c_str());
      
      if (nthField) {
        --nthField;
      } else {
        break;
      }
      
    } while (oldpos != string::npos);
    
    if (nthField) {
      WARNING_P1("Field %d not found in the file", origNth);
      // field not found in line
    } else {
      if (string::npos != oldpos) {
        if (string::npos != pos) {
          // should not be decremented for fieldN
          pos -= (oldpos + 1);
        }
    
        string x = line.substr(oldpos, pos);
        if (x.length()) {
        dest += sprintf(dest, "%s", x.c_str());
        }
        
        // WARNING_P2("nthField [%d] is [%s]", origNth, x.c_str());
      }
    }
  } else {
    // WARNING_P1("Field %d definition not found", nthField);
  }
}

void call::getIpFieldFromInputFile(int fieldNr, int lineNum, char *dest)
{
      char keyword[10];
      sprintf(keyword, "field%d", fieldNr);
      char *p = dest;
      getFieldFromInputFile(keyword, lineNum, p);
}

int  call::checkAutomaticResponseMode(char * P_recv) {

  int L_res = 0 ;

  if (strcmp(P_recv, "BYE")==0) {
    L_res = 1 ;
  } else if (strcmp(P_recv, "CANCEL") == 0) {
    L_res = 2 ;
  } else if (strcmp(P_recv, "PING") == 0) {
    L_res = 3 ;
  } else if ((strcmp(P_recv, "INFO") == 0) && (call_established == true) && (auto_answer == true)){
    L_res = 4 ;
  }

  return (L_res) ;
  
}


bool call::automaticResponseMode(int P_case, char * P_recv)
{

  int res ;
  char * old_last_recv_msg = NULL;

  switch (P_case) {
  case 1: // response for an unexpected BYE
    // usage of last_ keywords
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
    strcpy(last_recv_msg, P_recv);

    // The BYE is unexpected, count it
    scenario[msg_index] -> nb_unexp++;
    if (default_behavior) {
      WARNING_P1("Aborting call on an unexpected BYE for call: %s", (id==NULL)?"none":id);
    res = sendBuffer(createSendingMessage(
                    (char*)"SIP/2.0 200 OK\n"
                    "[last_Via:]\n"
                    "[last_From:]\n"
                    "[last_To:]\n"
                    "[last_Call-ID:]\n"
                    "[last_CSeq:]\n"
                    "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
                    "Content-Length: 0\n"
                    , -1)) ;

#ifdef __3PCC__
    // if twin socket call => reset the other part here 
    if (twinSippSocket && (msg_index > 0)) {
      res = sendCmdBuffer
      (createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n", -1));
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
    res = sendBuffer(createSendingMessage(
                      (char*)"SIP/2.0 200 OK\n"
                      "[last_Via:]\n"
                      "[last_From:]\n"
                      "[last_To:]\n"
                      "[last_Call-ID:]\n"
                      "[last_CSeq:]\n"
                      "Contact: sip:sipp@[local_ip]:[local_port]\n"
                      "Content-Length: 0\n"
                      , -1)) ;
    
#ifdef __3PCC__
    // if twin socket call => reset the other part here 
    if (twinSippSocket && (msg_index > 0)) {
      res = sendCmdBuffer
      (createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n", -1));
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
    res = sendBuffer(createSendingMessage(
                    (char*)"SIP/2.0 200 OK\n"
                    "[last_Via:]\n"
                    "[last_Call-ID:]\n"
                    "[last_To:]\n"
                    "[last_From:]\n"
                    "[last_CSeq:]\n"
                    "Contact: sip:sipp@[local_ip]:[local_port]\n"
                    "Content-Length: 0\n"
                    , -1)) ;
    // Note: the call ends here but it is not marked as bad. PING is a 
    //       normal message.
#ifdef __3PCC__
    // if twin socket call => reset the other part here 
    if (twinSippSocket && (msg_index > 0)) {
      res = sendCmdBuffer
      (createSendingMessage((char*)"call-id: [call_id]\ninternal-cmd: abort_call\n",-1));
    }
#endif /* __3PCC__ */
    
    CStat::instance()->computeStat(CStat::E_AUTO_ANSWERED);
    delete_call(id);
    } else {
      WARNING_P1("Do not answer on an unexpected PING for call: %s", (id==NULL)?"none":id);
    }
    break ;

  case 4: // response for a random INFO
    // store previous last msg if msg is INFO
    // restore last_recv_msg to previous one
    // after sending ok
    old_last_recv_msg = NULL;
    old_last_recv_msg = (char *) malloc(strlen(last_recv_msg)+1);
    strcpy(old_last_recv_msg,last_recv_msg);
    
    // usage of last_ keywords
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
    strcpy(last_recv_msg, P_recv);

    WARNING_P1("Automatic response mode for an unexpected INFO for call: %s", (id==NULL)?"none":id);
    res = sendBuffer(createSendingMessage(
                    (char*)"SIP/2.0 200 OK\n"
                    "[last_Via:]\n"
                    "[last_Call-ID:]\n"
                    "[last_To:]\n"
                    "[last_From:]\n"
                    "[last_CSeq:]\n"
                    "Contact: sip:sipp@[local_ip]:[local_port]\n"
                    "Content-Length: 0\n"
                    , -1)) ;

    // restore previous last msg
    last_recv_msg = (char *) realloc(last_recv_msg, strlen(old_last_recv_msg) + 1);
    strcpy(last_recv_msg, old_last_recv_msg);
    if (old_last_recv_msg != NULL) {
      free(old_last_recv_msg);
      old_last_recv_msg = NULL;
    }
    CStat::instance()->computeStat(CStat::E_AUTO_ANSWERED);
    return true;
    break;

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
  struct sched_param param;
  int ret;
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
