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
 *           Marc LAMBERTON
 *           Olivier JACQUES
 *           Herve PELLAN
 *           David MANSUTTI
 *           Francois-Xavier Kowalski
 *           Gerard Lyonnaz
 *           From Hewlett Packard Company.
 *           F. Tarek Rogers
 *           Peter Higginson
 *           Vincent Luba
 *           Shriram Natarajan
 *           Guillaume Teissier from FTR&D
 *           Clement Chen
 *           Wolfgang Beck
 */

#define GLOBALS_FULL_DEFINITION

#include "sipp.hpp"

#ifdef _USE_OPENSSL
SSL_CTX  *sip_trp_ssl_ctx = NULL; /* For SSL cserver context */
SSL_CTX  *sip_trp_ssl_ctx_client = NULL; /* For SSL cserver context */
SSL_CTX  *twinSipp_sip_trp_ssl_ctx_client = NULL; /* For SSL cserver context */

enum ssl_init_status {
  SSL_INIT_NORMAL, /* 0   Normal completion    */
  SSL_INIT_ERROR   /* 1   Unspecified error    */
};

#define CALL_BACK_USER_DATA "ksgr"

int passwd_call_back_routine(char  *buf , int size , int flag, void *passwd)
{
  strncpy(buf, (char *)(passwd), size);
  buf[size - 1] = '\0';
  return(strlen(buf));
}
#endif

/***************** System Portability Features *****************/

unsigned int getmilliseconds()
{
  struct timeval LS_system_time;
  unsigned long long int VI_milli;
  static unsigned long long int VI_milli_base = 0;
  
  gettimeofday(&LS_system_time, NULL);
  VI_milli = ((unsigned long long) LS_system_time.tv_sec) 
    * 1000LL + (LS_system_time.tv_usec / 1000LL);
  if (!VI_milli_base) VI_milli_base = VI_milli - 1;
  VI_milli = VI_milli - VI_milli_base;
  
  return (unsigned int) VI_milli;
}

#ifdef _USE_OPENSSL
/****** SSL error handling                         *************/
void sip_tls_error_handling(SSL *ssl, int size) {
  int err;
  err=SSL_get_error(ssl, size);
  switch(err) {
    case SSL_ERROR_NONE:
      break;
    case SSL_ERROR_WANT_WRITE:
      WARNING("SSL_read returned SSL_ERROR_WANT_WRITE");
      break;
    case SSL_ERROR_WANT_READ:
      WARNING("SSL_read returned SSL_ERROR_WANT_READ");
      break;
    case SSL_ERROR_WANT_X509_LOOKUP:
      WARNING("SSL_read returned SSL_ERROR_WANT_X509_LOOKUP");
      break;
    case SSL_ERROR_SYSCALL:
      if(size<0) { /* not EOF */
        switch(errno) {
          case EINTR:
            WARNING("SSL_read interrupted by a signal");
            break;
          case EAGAIN:
            WARNING("SSL_read returned EAGAIN");
            break; 
          default:
            WARNING("SSL_read (ERROR_SYSCALL)");
        }
      } else { /* EOF */
        WARNING("SSL socket closed on SSL_read");
      }
      break;
  }
}

/****** Certificate Verification Callback FACILITY *************/
int sip_tls_verify_callback(int ok , X509_STORE_CTX *store)
{
  char data[512];
  
  if (!ok) {
     X509 *cert = X509_STORE_CTX_get_current_cert(store);
     int  depth = X509_STORE_CTX_get_error_depth(store);
     int  err   = X509_STORE_CTX_get_error(store);

     X509_NAME_oneline(X509_get_issuer_name(cert),
                                   data,512);
     WARNING_P1("TLS verification error for issuer: '%s'", data);
     X509_NAME_oneline(X509_get_subject_name(cert),
                                   data,512);
     WARNING_P1("TLS verification error for subject: '%s'", data);
  }
  return ok;
}

/***********  Load the CRL's into SSL_CTX **********************/
int sip_tls_load_crls( SSL_CTX *ctx , char *crlfile)
{
  X509_STORE          *store;
  X509_LOOKUP         *lookup;

  /*  Get the X509_STORE from SSL context */
  if (!(store = SSL_CTX_get_cert_store(ctx))) {
    return (-1);
  }

  /* Add lookup file to X509_STORE */
  if (!(lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file()))) {
    return (-1);
  }

  /* Add the CRLS to the lookpup object */
  if (X509_load_crl_file(lookup,crlfile,X509_FILETYPE_PEM) != 1) {
    return (-1);
  }

  /* Set the flags of the store so that CRLS's are consulted */
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
  X509_STORE_set_flags( store,X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#else
#warning This version of OpenSSL (<0.9.7) cannot handle CRL files in capath
  ERROR("This version of OpenSSL (<0.9.7) cannot handle CRL files in capath");
#endif

  return (1);
}

/************* Prepare the SSL context ************************/
static ssl_init_status FI_init_ssl_context (void)
{
  sip_trp_ssl_ctx = SSL_CTX_new( SSLv23_method() ); 
  if ( sip_trp_ssl_ctx == NULL ) {
    ERROR("FI_init_ssl_context: SSL_CTX_new with SSLv23_method failed");
    return SSL_INIT_ERROR;
  }

  sip_trp_ssl_ctx_client = SSL_CTX_new( TLSv1_method() );
  if ( sip_trp_ssl_ctx_client == NULL)
  {
    ERROR("FI_init_ssl_context: SSL_CTX_new with TLSv1_method failed");
    return SSL_INIT_ERROR;
  }

  /*  Load the trusted CA's */
  SSL_CTX_load_verify_locations(sip_trp_ssl_ctx, tls_cert_name, NULL);
  SSL_CTX_load_verify_locations(sip_trp_ssl_ctx_client, tls_cert_name, NULL);
  
  /*  CRL load from application specified only if specified on the command line */
  if (strlen(tls_crl_name) != 0) {
    if(sip_tls_load_crls(sip_trp_ssl_ctx,tls_crl_name) == -1) {
      ERROR_P1("FI_init_ssl_context: Unable to load CRL file (%s)", tls_crl_name);
      return SSL_INIT_ERROR;
    }
  
    if(sip_tls_load_crls(sip_trp_ssl_ctx_client,tls_crl_name) == -1) {
      ERROR_P1("FI_init_ssl_context: Unable to load CRL (client) file (%s)", tls_crl_name);
      return SSL_INIT_ERROR;
    }
    /* The following call forces to process the certificates with the */
    /* initialised SSL_CTX                                            */
    SSL_CTX_set_verify(sip_trp_ssl_ctx,
                       SSL_VERIFY_PEER |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       sip_tls_verify_callback);

    SSL_CTX_set_verify(sip_trp_ssl_ctx_client,
                       SSL_VERIFY_PEER |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       sip_tls_verify_callback);
  }


  /* Selection Cipher suits - load the application specified ciphers */
  SSL_CTX_set_default_passwd_cb_userdata(sip_trp_ssl_ctx,
                                             (void *)CALL_BACK_USER_DATA );
  SSL_CTX_set_default_passwd_cb_userdata(sip_trp_ssl_ctx_client,
                                             (void *)CALL_BACK_USER_DATA );
  SSL_CTX_set_default_passwd_cb( sip_trp_ssl_ctx,
                                             passwd_call_back_routine );
  SSL_CTX_set_default_passwd_cb( sip_trp_ssl_ctx_client,
                                             passwd_call_back_routine );

  if ( SSL_CTX_use_certificate_file(sip_trp_ssl_ctx,
                                        tls_cert_name,
                                        SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_certificate_file failed");
    return SSL_INIT_ERROR;
  }

  if ( SSL_CTX_use_certificate_file(sip_trp_ssl_ctx_client,
                                        tls_cert_name,
                                        SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_certificate_file (client) failed");
    return SSL_INIT_ERROR;
  }
  if ( SSL_CTX_use_PrivateKey_file(sip_trp_ssl_ctx,
                                       tls_key_name,
                                       SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_PrivateKey_file failed");
    return SSL_INIT_ERROR;
  }

  if ( SSL_CTX_use_PrivateKey_file(sip_trp_ssl_ctx_client,
                                       tls_key_name,
                                       SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_PrivateKey_file (client) failed");
    return SSL_INIT_ERROR;
  }

  return SSL_INIT_NORMAL;
}

int send_nowait_tls(SSL *ssl, const void *msg, int len, int flags)
{
  int initial_fd_flags;
  int rc;
  int fd;
  int fd_flags;
  if ( (fd = SSL_get_fd(ssl)) == -1 ) {
    return (-1);
  }
  fd_flags = fcntl(fd, F_GETFL , NULL);
  initial_fd_flags = fd_flags;
  fd_flags |= O_NONBLOCK;
  fcntl(fd, F_SETFL , fd_flags);
  rc = SSL_write(ssl,msg,len);
  if ( rc <= 0 ) {
    return(rc);
  }
  fcntl(fd, F_SETFL , initial_fd_flags);
  return rc;
}
#endif 

int send_nowait(int s, const void *msg, int len, int flags)
{
#ifdef MSG_DONTWAIT
  return send(s, msg, len, flags | MSG_DONTWAIT);
#else
  int fd_flags = fcntl(s, F_GETFL , NULL);
  int initial_fd_flags;
  int rc;

  initial_fd_flags = fd_flags;
  //  fd_flags &= ~O_ACCMODE; // Remove the access mode from the value
  fd_flags |= O_NONBLOCK;
  fcntl(s, F_SETFL , fd_flags);
  
  rc = send(s, msg, len, flags);

  fcntl(s, F_SETFL , initial_fd_flags);

  return rc;
#endif 
}

char * get_inet_address(struct sockaddr_storage * addr)
{
  static char * ip_addr = NULL;

  if (!ip_addr) {
    ip_addr = (char *)malloc(1024*sizeof(char));
  }
  if (getnameinfo(_RCAST(struct sockaddr *, addr),
                  SOCK_ADDR_SIZE(addr),
                  ip_addr,
                  1024,
                  NULL,
                  0,
                  NI_NUMERICHOST) != 0) {
    strcpy(ip_addr, "addr not supported");
  }

  return ip_addr;
}

void get_host_and_port(char * addr, char * host, int * port)
{
  /* Separate the port number (if any) from the host name.
   * Thing is, the separator is a colon (':').  The colon may also exist
   * in the host portion if the host is specified as an IPv6 address (see
   * RFC 2732).  If that's the case, then we need to skip past the IPv6
   * address, which should be contained within square brackets ('[',']').
   */
  char *p;
  p = strchr( addr, '[' );                      /* Look for '['.            */
  if( p != NULL ) {                             /* If found, look for ']'.  */
    p = strchr( p, ']' );
  }
  if( p == NULL ) {                             /* If '['..']' not found,   */
    p = addr;                                   /* scan the whole string.   */
  } else {                                      /* If '['..']' found,       */
    char *p1;                                   /* extract the remote_host  */
    char *p2;
    p1 = strchr( addr, '[' );
    p2 = strchr( addr, ']' );
    *p2 = '\0';
    strcpy(host, p1 + 1);
    *p2 = ']';
  }
  /* Starting at <p>, which is either the start of the host substring
   * or the end of the IPv6 address, find the last colon character.
   */
  p = strchr( p, ':' );
  if( NULL != p ) {
    *p = '\0';
    *port = atol(p + 1);
  } else {
    *port = 0;
  }
}

char * strcasestr2(char *s, char *find) {
  char c, sc;
  size_t len;

  if ((c = *find++) != 0) {
    c = tolower((unsigned char)c);
    len = strlen(find);
    do {
      do {
        if ((sc = *s++) == 0)
        return (NULL);
      } while ((char)tolower((unsigned char)sc) != c);
    } while (strncasecmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

int get_decimal_from_hex(char hex) {
  if (isdigit(hex))
    return hex - '0';
  else
    return tolower(hex) - 'a' + 10;
}


/******************** Recv Poll Processing *********************/

int                  pollnfds;
struct pollfd        pollfiles[SIPP_MAXFDS];
call               * pollcalls[SIPP_MAXFDS];
map<string, int>     map_perip_fd;
#ifdef _USE_OPENSSL
SSL                * ssl_list[SIPP_MAXFDS];
#endif

char               * pending_msg[SIPP_MAXFDS];

/***************** Check of the message received ***************/

bool sipMsgCheck (char *P_msg, int P_msgSize
#ifdef __3PCC__
		  ,int P_pollSetIdx
#endif
		  ) {
  
  const char C_sipHeader[] = "SIP/2.0" ;

#ifdef __3PCC__
  if (pollfiles[P_pollSetIdx].fd == twinSippSocket) {
    return true ;
  } else {
#endif // __3PCC__

    if (strstr(P_msg, C_sipHeader) !=  NULL) {
      return true ;
    }

    return false ;

#ifdef __3PCC__
  }
#endif // __3PCC__
}

void pollset_reset()
{
  pollnfds = 0;

  memset((void *)pending_msg,0,SIPP_MAXFDS*sizeof(char *));

  memset((void *)pollfiles,0,SIPP_MAXFDS*sizeof(struct pollfd));
  pollfiles[pollnfds].fd      = main_socket;
  pollfiles[pollnfds].events  = POLLIN | POLLERR;
  pollfiles[pollnfds].revents = 0;
  pollcalls[pollnfds]         = NULL;
  pollnfds++;
  
  if(tcp_multiplex) {
    /* Adds the TCP multiplex in the file descriptor array */
    pollfiles[pollnfds].fd      = tcp_multiplex;
    pollfiles[pollnfds].events  = POLLIN | POLLERR;
    pollfiles[pollnfds].revents = 0;
    pollcalls[pollnfds]         = NULL;
    pollnfds++;
  } 

#ifdef __3PCC__
  if(twinSippSocket) {
    /* Adds the twinSippSocket */
    pollfiles[pollnfds].fd      = twinSippSocket;
    pollfiles[pollnfds].events  = POLLIN | POLLERR;
    pollfiles[pollnfds].revents = 0;
    pollcalls[pollnfds]         = NULL;
    pollnfds++;
  } 

  if(localTwinSippSocket) {
    /* Adds the twinSippSocket */
    pollfiles[pollnfds].fd      = localTwinSippSocket;
    pollfiles[pollnfds].events  = POLLIN | POLLERR;
    pollfiles[pollnfds].revents = 0;
    pollcalls[pollnfds]         = NULL;
    pollnfds++;
  } 
#endif


  // Add additional server sockets for socket per IP address
  if (peripsocket && toolMode == MODE_SERVER) {
    for (map<string, int>::iterator i = map_perip_fd.begin();
         i != map_perip_fd.end(); i++)
    {
      // main_socket is already in pollfiles
      if (i->second != main_socket) {
        pollset_add(0, i->second);
      }
    }
  }

}

int pollset_add(call * p_call, int sock)
{  


  pollfiles[pollnfds].fd      = sock;
  pollfiles[pollnfds].events  = POLLIN | POLLERR;
  pollfiles[pollnfds].revents = 0;
  pollcalls[pollnfds]         = p_call;
  pollnfds++;
  
  /*
  int L_i ;
  TRACE_MSG((s,"Adding socket : %d at idx = %d\n", sock, (pollnfds-1)));
  for (L_i = 0; L_i <  pollnfds ; L_i++) {
    TRACE_MSG((s,"Adding socket : L_i %d and socket = %d\n", L_i , pollfiles[L_i].fd));
  }
    TRACE_MSG((s,"Adding socket :\n"));
  */
  
  return pollnfds - 1;
}

void pollset_attached(call * p_call, int P_pollset_idx){

  pollcalls[P_pollset_idx]         = p_call;

}

void pollset_remove(int idx)
{  
  // TRACE_MSG((s,"remove socket : idx %d\n", idx));
  if(idx >= pollnfds) {
    ERROR("Pollset error");
  }

  /*
  int L_i ;
  TRACE_MSG((s,"remove socket : idx %d\n", idx));
  for (L_i = 0; L_i <  pollnfds ; L_i++) {
    TRACE_MSG((s,"remove socket : L_i %d and socket = %d\n", L_i , pollfiles[L_i].fd));
  }
  TRACE_MSG((s,"remove socket :\n"));
  */

  /* Adds call sockets in the array */
  if(pollnfds) {
    // WARNING_P2("Removing socket %d at idx = %d", pollfiles[idx].fd, idx);
    pollnfds--;
    pollfiles[idx] = pollfiles[pollnfds];
    pollcalls[idx] = pollcalls[pollnfds];

    if((pollcalls[idx]) && (pollcalls[idx] -> pollset_index)) {
      pollcalls[idx] -> pollset_index = idx;
    }
  } else {
    ERROR("Pollset underflow");
  }
}



/************** Statistics display & User control *************/

void print_stats_in_file(FILE * f, int last)
{
  int index;
  static char temp_str[256];
  int divisor;

#define SIPP_ENDL "\r\n"

  /* Optional timestamp line for files only */
  if(f != stdout) {
    time_t tim;
    time(&tim);
    fprintf(f, "  Timestamp: %s" SIPP_ENDL, ctime(&tim));
  }
  
  /* Header line with global parameters */
  sprintf(temp_str, "%3.1f(%d ms)/%5.3fs", rate, duration, rate_period_s);
  if( toolMode == MODE_SERVER) {
    fprintf
      (f,
       "  Port   Total-time  Total-calls  Transport" 
       SIPP_ENDL
       "  %-5d %6d.%02d s     %8d  %s" 
       SIPP_ENDL SIPP_ENDL,
       local_port,
       clock_tick / 1000, (clock_tick % 1000) / 10,
       total_calls,
       TRANSPORT_TO_STRING(transport));
  } else {
    fprintf
      (f,
       "  Call-rate(length)     Port   Total-time  Total-calls  Remote-host" 
       SIPP_ENDL
       "%19s   %-5d %6d.%02d s     %8d  %s:%d(%s)" 
       SIPP_ENDL SIPP_ENDL,
       temp_str,
       local_port,
       clock_tick / 1000, (clock_tick % 1000) / 10,
       total_calls,
       remote_ip, 
       remote_port,
       TRANSPORT_TO_STRING(transport));
  }
  
  /* 1st line */
  if(total_calls < stop_after) {
    sprintf(temp_str, "%d new calls during %d.%03d s period ",
            total_calls - last_report_calls,
            (clock_tick-last_report_time) / 1000, 
            ((clock_tick-last_report_time) % 1000));
  } else {
    sprintf(temp_str, "Call limit reached (-m %d), %d.%03d s period ",
            stop_after,
            (clock_tick-last_report_time) / 1000, 
            ((clock_tick-last_report_time) % 1000));
  }
  divisor = scheduling_loops; if(!divisor) { divisor = 1; }
  fprintf(f,"  %-38s %d ms scheduler resolution" 
         SIPP_ENDL,
         temp_str,
         (clock_tick-last_report_time) / divisor);

  /* 2nd line */
  if( toolMode == MODE_SERVER) { 
    sprintf(temp_str, "%d calls", open_calls);
  } else {
    sprintf(temp_str, "%d calls (limit %d)", open_calls, open_calls_allowed);
  }
  fprintf(f,"  %-38s Peak was %d calls, after %d s" SIPP_ENDL, 
         temp_str, 
         open_calls_peak, 
         open_calls_peak_time);
  fprintf(f,"  %d Running, %d Paused, %d Woken up" SIPP_ENDL,
	 last_running_calls, last_paused_calls, last_woken_calls);

  /* 3rd line (optional) */
  if( toolMode != MODE_SERVER) { 
    sprintf(temp_str,"%d out-of-call msg (discarded)", 
            nb_out_of_the_blue);
    fprintf(f,"  %-37s", temp_str);
  }
  if(compression) {
    fprintf(f,"  Comp resync: %d sent, %d recv" , 
           resynch_send, resynch_recv);
  }
  if(compression || (toolMode != MODE_SERVER)) {
    fprintf(f,SIPP_ENDL);
  }
  
  /* 4th line , sockets and optional errors */ 
  sprintf(temp_str,"%d open sockets", 
          pollnfds);
  fprintf(f,"  %-38s", temp_str);
  if(nb_net_recv_errors || nb_net_send_errors || nb_net_cong) {
    fprintf(f,"  %d/%d/%d %s errors (send/recv/cong)" SIPP_ENDL,
           nb_net_send_errors, 
           nb_net_recv_errors,
           nb_net_cong,
           TRANSPORT_TO_STRING(transport));
  } else {
    fprintf(f,SIPP_ENDL);
  }

#ifdef PCAPPLAY
  /* if has media abilities */
  if (hasMedia != 0) {
    sprintf(temp_str, "%d Total RTP pckts sent ",
            rtp_pckts_pcap);
    if (clock_tick-last_report_time) {
       fprintf(f,"  %-38s %d.%03d last period RTP rate (kB/s)" SIPP_ENDL,
              temp_str,
              (rtp_bytes_pcap)/(clock_tick-last_report_time),
              (rtp_bytes_pcap)%(clock_tick-last_report_time));
    }
    rtp_bytes_pcap = 0;
    rtp2_bytes_pcap = 0;
  }
#endif

  /* 5th line, RTP echo statistics */
  if (rtp_echo_enabled && (media_socket > 0)) {
    sprintf(temp_str, "%d Total echo RTP pckts 1st stream",
            rtp_pckts);

    // AComment: Fix for random coredump when using RTP echo
    if (clock_tick-last_report_time) {
       fprintf(f,"  %-38s %d.%03d last period RTP rate (kB/s)" SIPP_ENDL,
              temp_str,
              (rtp_bytes)/(clock_tick-last_report_time),
              (rtp_bytes)%(clock_tick-last_report_time));
    }
    /* second stream statitics: */
    sprintf(temp_str, "%d Total echo RTP pckts 2nd stream",
            rtp2_pckts);

    // AComment: Fix for random coredump when using RTP echo
    if (clock_tick-last_report_time) {
      fprintf(f,"  %-38s %d.%03d last period RTP rate (kB/s)" SIPP_ENDL,
	      temp_str,
	      (rtp2_bytes)/(clock_tick-last_report_time),
	      (rtp2_bytes)%(clock_tick-last_report_time));
    }
    rtp_bytes = 0;
    rtp2_bytes = 0;
  }

  /* Scenario counters */
  fprintf(f,SIPP_ENDL);
  if(!lose_packets) {
    fprintf(f,"                                 "
           "Messages  Retrans   Timeout   Unexpected-Msg" 
           SIPP_ENDL);
  } else {
    fprintf(f,"                                 "
           "Messages  Retrans   Timeout   Unexp.    Lost" 
           SIPP_ENDL);
  }
  for(index = 0;
      index < scenario_len;
      index ++) {
    
    if(scenario[index] -> send_scheme) {
      char *dest, *src;
      int len;
      dest = temp_str;
      src  = scenario[index] -> send_scheme;

      if( strncmp(src, "SIP/2.0", 7) == 0) {
        src += 8;
      }
      while((*src) && (*src != ' ') && (*src != '\t') && (*src != '\n')) {
        *dest++ = *src ++;
      }
      *dest = 0;
      if(toolMode == MODE_SERVER) {
        fprintf(f,"  <---------- %-10s ", temp_str);
      } else {
        fprintf(f,"  %10s ----------> ", temp_str);
      }
      if (scenario[index] -> start_rtd) {
	fprintf(f, " B-RTD%d ", scenario[index] -> start_rtd);
      } else if (scenario[index] -> stop_rtd) {
	fprintf(f, " E-RTD%d ", scenario[index] -> stop_rtd);
      } else {
	fprintf(f, "        ");
      }

      if(scenario[index] -> retrans_delay) {
        fprintf(f,"%-9d %-9d %-9d" ,
               scenario[index] -> nb_sent,
               scenario[index] -> nb_sent_retrans,
               scenario[index] -> nb_timeout);
      } else {
        fprintf(f,"%-9d %-9d                    " ,
               scenario[index] -> nb_sent,
               scenario[index] -> nb_sent_retrans);
      }
    } else if(scenario[index] -> recv_response) {
      if(toolMode == MODE_SERVER) {
	fprintf(f,"  ----------> %-10d ", scenario[index] -> recv_response);
      } else { 
	fprintf(f,"  %10d <---------- ", scenario[index] -> recv_response);
      }

      if (scenario[index] -> start_rtd) {
	fprintf(f, " B-RTD%d ", scenario[index] -> start_rtd);
      } else if (scenario[index] -> stop_rtd) {
	fprintf(f, " E-RTD%d ", scenario[index] -> stop_rtd);
      } else {
	fprintf(f, "        ");
      }

      if(scenario[index]->retrans_delay) {
        fprintf(f,"%-9ld %-9ld %-9ld %-9ld" ,
               scenario[index]->nb_recv,
               scenario[index]->nb_recv_retrans,
               scenario[index]->nb_timeout,
               scenario[index]->nb_unexp);
      } else {
        fprintf(f,"%-9ld %-9ld           %-9ld" ,
               scenario[index] -> nb_recv,
               scenario[index] -> nb_recv_retrans,
               scenario[index] -> nb_unexp);
      }
    } else if (scenario[index] -> pause_function) {
      char *desc = scenario[index]->pause_desc;
      int len = strlen(desc) < 9 ? 9 : strlen(desc);

      if(toolMode == MODE_SERVER) {
	fprintf(f,"  [%9s] Pause%*s", desc, 23 - len > 0 ? 23 - len : 0, "");
      } else {
	fprintf(f,"       Pause [%9s]%*s", desc, 18 - len > 0 ? 18 - len : 0, "");
      }

      fprintf(f,"%-9d", scenario[index]->sessions);
      fprintf(f,"                     %-9d" , scenario[index]->nb_unexp);
    } else if(scenario[index] -> recv_request) {
      if(toolMode == MODE_SERVER) {
	fprintf(f,"  ----------> %-10s ", scenario[index] -> recv_request);
      } else {
	fprintf(f,"  %10s <---------- ", scenario[index] -> recv_request);
      }

      if (scenario[index] -> start_rtd) {
	fprintf(f, " B-RTD%d ", scenario[index] -> start_rtd);
      } else if (scenario[index] -> stop_rtd) {
	fprintf(f, " E-RTD%d ", scenario[index] -> stop_rtd);
      } else {
	fprintf(f, "        ");
      }

      if(scenario[index]->retrans_delay) {
        fprintf(f,"%-9ld %-9ld %-9ld %-9ld" ,
               scenario[index]->nb_recv,
               scenario[index]->nb_recv_retrans,
               scenario[index]->nb_timeout,
               scenario[index]->nb_unexp);
      } else {
        fprintf(f,"%-9ld %-9ld           %-9ld" ,
               scenario[index] -> nb_recv,
               scenario[index] -> nb_recv_retrans,
               scenario[index] -> nb_unexp);
      }
    }
    else if(scenario[index] -> M_type == MSG_TYPE_NOP) {
      fprintf(f,"              [ NOP ]              ");
    }
#ifdef __3PCC__
    else if(scenario[index] -> M_type == MSG_TYPE_RECVCMD) {
      fprintf(f,"       [ Received Command ]        ");
      if(scenario[index]->retrans_delay) {
        fprintf(f,"%-9ld %-9s %-9ld %-9s" ,
                scenario[index]->M_nbCmdRecv,
                "",
                scenario[index]->nb_timeout,
                "");
      } else {
         fprintf(f,"%-9ld %-9s           %-9s" ,
                scenario[index] -> M_nbCmdRecv,
                "",
                "");
      }
    } else if(scenario[index] -> M_type == MSG_TYPE_SENDCMD) {
      fprintf(f,"         [ Sent Command ]          ");
      fprintf(f,"%-9d %-9s           %-9s" ,
             scenario[index] -> M_nbCmdSent,
             "",
             "");
    }
#endif
    else {
      ERROR("Scenario command not implemented in display\n");
    }
    
    if(lose_packets && (scenario[index] -> nb_lost)) {
      fprintf(f," %-9d" SIPP_ENDL,
             scenario[index] -> nb_lost);
    } else {
      fprintf(f,SIPP_ENDL);
    }
    
    if(scenario[index] -> crlf) {
      fprintf(f,SIPP_ENDL);
    }
  }
}

void print_header_line(FILE *f, int last)
{  
  switch(currentScreenToDisplay)
    {
    case DISPLAY_STAT_SCREEN :
      fprintf(f,"----------------------------- Statistics Screen ------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_REPARTITION_SCREEN :
      fprintf(f,"---------------------------- Repartition Screen ------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_VARIABLE_SCREEN  :
      fprintf(f,"----------------------------- Variables Screen -------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_TDM_MAP_SCREEN  :
      fprintf(f,"------------------------------ TDM map Screen --------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_SECONDARY_REPARTITION_SCREEN :
      fprintf(f,"--------------------------- Repartition %d Screen ------ [1-9]: Change Screen --" SIPP_ENDL, currentRepartitionToDisplay);
      break;
    case DISPLAY_SCENARIO_SCREEN :
    default:
      fprintf(f,"------------------------------ Scenario Screen -------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    }
}

void print_bottom_line(FILE *f, int last)
{
  if(last) {
    fprintf(f,"------------------------------ Test Terminated --------------------------------" SIPP_ENDL);
  } else if(quitting) {
    fprintf(f,"------- Waiting for active calls to end. Press [q] again to force exit. -------" SIPP_ENDL );
  } else if(paused) {
    fprintf(f,"----------------- Traffic Paused - Press [p] again to resume ------------------" SIPP_ENDL );
  } else if(cpu_max) {
    fprintf(f,"-------------------------------- CPU CONGESTED ---------------------------------" SIPP_ENDL);
  } else if(outbound_congestion) {
    fprintf(f,"------------------------------ OUTBOUND CONGESTION -----------------------------" SIPP_ENDL);
  } else {
    switch(toolMode)
      {
      case MODE_SERVER :
        fprintf(f,"------------------------------ Sipp Server Mode -------------------------------" SIPP_ENDL);
        break;
#ifdef __3PCC__
      case MODE_3PCC_CONTROLLER_B :
        fprintf(f,"----------------------- 3PCC Mode - Controller B side -------------------------" SIPP_ENDL);
        break;
      case MODE_3PCC_A_PASSIVE :
        fprintf(f,"------------------ 3PCC Mode - Controller A side (passive) --------------------" SIPP_ENDL);
        break;
      case MODE_3PCC_CONTROLLER_A :
        fprintf(f,"----------------------- 3PCC Mode - Controller A side -------------------------" SIPP_ENDL);
        break;
#endif
      case MODE_CLIENT :
      default:
        fprintf(f,"------ [+|-|*|/]: Adjust rate ---- [q]: Soft exit ---- [p]: Pause traffic -----" SIPP_ENDL);
        break;
      }
  }
  fprintf(f,SIPP_ENDL);
  fflush(stdout);
}

void print_tdm_map()
{
  int interval = 0;
  int i = 0;
  int j = 0;
  int in_use = 0;
  interval = (tdm_map_a+1) * (tdm_map_b+1) * (tdm_map_c+1);

  printf("TDM Circuits in use:"  SIPP_ENDL);
  while (i<interval) {
    if (tdm_map[i]) {
      printf("*");
      in_use++;
    } else {
      printf(".");
    }
    i++;
    if (i%(tdm_map_c+1) == 0) printf(SIPP_ENDL);
  }
  printf(SIPP_ENDL);
  printf("%d/%d circuits (%d%%) in use", in_use, interval, int(100*in_use/interval));
  printf(SIPP_ENDL);
  for(i=0; i<(scenario_len + 8 - int(interval/(tdm_map_c+1))); i++) {
    printf(SIPP_ENDL);
  }
}

void print_variable_list()
{
  CActions  * actions;
  CAction   * action;
  CVariable * variable;
  int i,j;
  bool found;

  printf("Action defined Per Message :" SIPP_ENDL);
  found = false;
  for(i=0; i<scenario_len; i++)
    {
      actions = scenario[i]->M_actions;
      if(actions != NULL)
        {
          switch(scenario[i]->M_type)
            {
            case MSG_TYPE_RECV:
              printf("=> Message[%d] (Receive Message) - "
                     "[%d] action(s) defined :" SIPP_ENDL,
                     i,             
                     actions->getUsedAction());
              break;
#ifdef __3PCC__
            case MSG_TYPE_RECVCMD:
              printf("=> Message[%d] (Receive Command Message) - "
                     "[%d] action(s) defined :" SIPP_ENDL,
                     i,             
                     actions->getUsedAction());
              break;
#endif
            default:
              printf("=> Message[%d] - [%d] action(s) defined :" SIPP_ENDL,
                     i,             
                     actions->getUsedAction());
              break;
            }
      
          for(int j=0; j<actions->getUsedAction(); j++)
            {
              action = actions->getAction(j);
              if(action != NULL)
                {
                  printf("   --> action[%d] = ", j);
                  action->afficheInfo();
                  printf(SIPP_ENDL);
                  found = true;
                }
            }
        }
    }
  if(!found) printf("=> No action found on any messages"SIPP_ENDL);
  
  printf(SIPP_ENDL);
  printf("Setted Variable List:" SIPP_ENDL);
  found = false;
  j=0;
  for(i=0; i<SCEN_VARIABLE_SIZE; i++) {
    for (int j=0;j<SCEN_MAX_MESSAGES;j++)
    {
      variable = scenVariableTable[i][j];
      if(variable != NULL)
        {
          printf("=> Variable[%d] : setted regExp[%s]" SIPP_ENDL,
                 i,
                 variable->getRegularExpression());
          found = true;
          j++;
        }
    }
  }
  if(!found) printf("=> No variable found for this scenario"SIPP_ENDL);
  for(i=0; i<(scenario_len + 5 - j); i++) {
    printf(SIPP_ENDL);
  }
  
}

/* Function to dump all available screens in a file */
void print_screens(void)
{
  int oldScreen = currentScreenToDisplay;
  int oldRepartition = currentRepartitionToDisplay;

  currentScreenToDisplay = DISPLAY_SCENARIO_SCREEN;  
  print_header_line(   screenf, 0);
  print_stats_in_file( screenf, 0);
  print_bottom_line(   screenf, 0);

  currentScreenToDisplay = DISPLAY_STAT_SCREEN;  
  print_header_line(   screenf, 0);
  CStat::instance()->displayStat(screenf);
  print_bottom_line(   screenf, 0);

  currentScreenToDisplay = DISPLAY_REPARTITION_SCREEN;
  print_header_line(   screenf, 0);
  CStat::instance()->displayRepartition(screenf);
  print_bottom_line(   screenf, 0);

  currentScreenToDisplay = DISPLAY_SECONDARY_REPARTITION_SCREEN;
  for (int i = 1; i < MAX_RTD_INFO_LENGTH; i++) {
    currentRepartitionToDisplay = i;
    print_header_line(   screenf, 0);
    CStat::instance()->displaySecondaryRepartition(screenf, i);
    print_bottom_line(   screenf, 0);
  }

  currentScreenToDisplay = oldScreen;
  currentRepartitionToDisplay = oldRepartition;
}

void print_statistics(int last)
{
  static int first = 1;

  if(backgroundMode == false) {
    if(!last) {
      screen_clear();
    }

    if(first) {
      first = 0;
      printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
             "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    }
    print_header_line(stdout,last);
    switch(currentScreenToDisplay) {
      case DISPLAY_STAT_SCREEN :
        CStat::instance()->displayStat(stdout);
        break;
      case DISPLAY_REPARTITION_SCREEN :
        CStat::instance()->displayRepartition(stdout);
        break;
      case DISPLAY_VARIABLE_SCREEN  :
        print_variable_list();
        break;
      case DISPLAY_TDM_MAP_SCREEN  :
        print_tdm_map();
        break;
      case DISPLAY_SECONDARY_REPARTITION_SCREEN :
	CStat::instance()->displaySecondaryRepartition(stdout, currentRepartitionToDisplay);
	break;
      case DISPLAY_SCENARIO_SCREEN :
      default:
        print_stats_in_file(stdout, last);
        break;
    }
    print_bottom_line(stdout,last);

    if(last) { fprintf(stdout,"\n"); }
  }
}

void set_rate(double new_rate)
{

  double L_temp ;
  
  if(toolMode == MODE_SERVER) {
    rate = 0;
    open_calls_allowed = 0;
  }

  rate = new_rate;
  if(rate < 0) {
    rate = 0;
  }

  last_rate_change_time = clock_tick;
  calls_since_last_rate_change = 0;
  
  if(!open_calls_user_setting) {
    
    int call_duration_min =  scenario_duration;

    if(duration > call_duration_min) call_duration_min = duration;

    if(call_duration_min < 1000) call_duration_min = 1000;
    
    L_temp = (3 * rate * call_duration_min) / rate_period_s / 1000 ;
    open_calls_allowed = (unsigned int) L_temp ;
    if(!open_calls_allowed) {
      open_calls_allowed = 1;
    }
  }
}

void sipp_sigusr1(int /* not used */)
{
  /* Smooth exit: do not place any new calls and exit */
  quitting+=10;
}

void sipp_sigusr2(int /* not used */)
{
  if (!signalDump) {
     signalDump = true ;
  }
}

bool process_key(int c) {
    switch (c) {
    case '1':
      currentScreenToDisplay = DISPLAY_SCENARIO_SCREEN;
      print_statistics(0);
      break;

    case '2':
      currentScreenToDisplay = DISPLAY_STAT_SCREEN;
      print_statistics(0);
      break;

    case '3':
      currentScreenToDisplay = DISPLAY_REPARTITION_SCREEN;
      print_statistics(0);
      break;

    case '4':
      currentScreenToDisplay = DISPLAY_VARIABLE_SCREEN;
      print_statistics(0);
      break;

    case '5':
      if (use_tdmmap) {
        currentScreenToDisplay = DISPLAY_TDM_MAP_SCREEN;
        print_statistics(0);
      }
      break;

    /* Screens 6, 7, 8, 9  are for the extra RTD repartitions. */
    case '6':
    case '7':
    case '8':
    case '9':
      currentScreenToDisplay = DISPLAY_SECONDARY_REPARTITION_SCREEN;
      currentRepartitionToDisplay = (c - '6') + 1;
      print_statistics(0);
      break;

    case '+':
      set_rate(rate + 1);
      print_statistics(0);
      break;

    case '-':
      set_rate(rate - 1);
      print_statistics(0);
      break;

    case '*':
      set_rate(rate + 10);
      print_statistics(0);
      break;

    case '/':
      set_rate(rate - 10);
      print_statistics(0);
      break;

    case 'p':
      if(paused) { 
	paused = 0;
	set_rate(rate);
      } else {
	paused = 1;
      }
      print_statistics(0);
      break;

    case 'q':
      quitting+=10;
      print_statistics(0);
      return true;
    }
    return false;
}

/* User interface threads */
/* Socket control thread */
void ctrl_thread (void * param)
{
  int soc,ret;
  short prt;
  int port, try_counter;
  unsigned char bufrcv [20], c; 
  struct sockaddr_in sin;
  
  port = DEFAULT_CTRL_SOCKET_PORT;
  try_counter = 0;
  /* Allow 10 control socket on the same system */
  /* (several SIPp instances)                   */
  while (try_counter < 10) {
    prt = htons(port);
    memset(&sin,0,sizeof(struct sockaddr_in));
    soc = socket(AF_INET,SOCK_DGRAM,0);
    sin.sin_port = prt;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    if (!bind(soc,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))) {
      /* Bind successful */
      break;
    }
    try_counter++;
    port++;
  }
  if (try_counter == 10) {
    WARNING_P3("Unable to bind remote control socket (tried UDP ports %d-%d)", 
                  DEFAULT_CTRL_SOCKET_PORT, 
                  DEFAULT_CTRL_SOCKET_PORT+10, 
                  strerror(errno));
    return;
  }

  while(!feof(stdin)){
    ret = recv(soc,bufrcv,20,0);
    if (process_key(bufrcv[0])) {
	return;
    }
  }
}

/* KEYBOARD thread */
void keyb_thread (void * param)
{
  int c;

  while(!feof(stdin)){
    c = screen_readkey();
    if (process_key(c)) {
	return;
    }
  }
}

/*************************** Mini SIP parser ***************************/

char * get_peer_tag(char *msg)
{
  char        * to_hdr;
  char        * ptr; 
  char        * end_ptr;
  static char   tag[MAX_HEADER_LEN];
  int           tag_i = 0;
  
  to_hdr = strstr(msg, "\r\nTo:");
  if(!to_hdr) to_hdr = strstr(msg, "\r\nto:");
  if(!to_hdr) to_hdr = strstr(msg, "\r\nTO:");
  if(!to_hdr) to_hdr = strstr(msg, "\r\nt:");
  if(!to_hdr) {
    ERROR("No valid To: header in reply");
  }

  // Remove CRLF
  to_hdr += 2;

  end_ptr = strchr(to_hdr,'\n');

  ptr = strchr(to_hdr, '>');
  if (!ptr) {
    return NULL;
  }
  
  ptr = strchr(to_hdr, ';'); 
  
  if(!ptr) {
    return NULL;
  }
  
  to_hdr = ptr;

  ptr = strstr(to_hdr, "tag");
  if(!ptr) { ptr = strstr(to_hdr, "TAG"); }
  if(!ptr) { ptr = strstr(to_hdr, "Tag"); }

  if(!ptr) {
    return NULL;
  }

  if (ptr>end_ptr) {
    return NULL ;
  }
  
  ptr = strchr(ptr, '='); 
  
  if(!ptr) {
    ERROR("Invalid tag param in To: header");
  }

  ptr ++;

  while((*ptr)         && 
        (*ptr != ' ')  && 
        (*ptr != ';')  && 
        (*ptr != '\t') && 
        (*ptr != '\t') && 
        (*ptr != '\r') &&  
        (*ptr != '\n') && 
        (*ptr)) {
    tag[tag_i++] = *(ptr++);
  }
  tag[tag_i] = 0;
  
  return tag;
}

char * get_call_id(char *msg)
{
  static char call_id[MAX_HEADER_LEN];
  char * ptr1, * ptr2, * ptr3, backup;
  bool short_form;

  short_form = false;

  ptr1 = strstr(msg, "Call-ID:");
  if(!ptr1) { ptr1 = strstr(msg, "Call-Id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "Call-id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "call-Id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "call-id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "CALL-ID:"); }
  // For short form, we need to make sure we start from beginning of line
  // For others, no need to
  if(!ptr1) { ptr1 = strstr(msg, "\r\ni:"); short_form = true;}
  if(!ptr1) { ERROR_P1("(1) No valid Call-ID: header in reply '%s'", msg); }
  
  if (short_form) {
    ptr1 += 4;
  } else {
    ptr1 += 8;
  }
  
  while((*ptr1 == ' ') || (*ptr1 == '\t')) { ptr1++; }
  
  if(!(*ptr1)) { ERROR("(2) No valid Call-ID: header in reply"); }
  
  ptr2 = ptr1;

  while((*ptr2) && 
        (*ptr2 != ' ') && 
        (*ptr2 != '\t') && 
        (*ptr2 != '\r') && 
        (*ptr2 != '\n')) { 
    ptr2 ++;
  } 

  if(!*ptr2) { ERROR("(3) No valid Call-ID: header in reply"); }

  backup = *ptr2;
  *ptr2 = 0;
  if ((ptr3 = strstr(ptr1, "///")) != 0) ptr1 = ptr3+3;
  strcpy(call_id, ptr1);
  *ptr2 = backup;
  return (char *) call_id;
}

unsigned long int get_cseq_value(char *msg) {
  char *ptr1;
 

  // no short form for CSeq:
  ptr1 = strstr(msg, "\r\nCSeq:");
  if(!ptr1) { ptr1 = strstr(msg, "\r\nCSEQ:"); }
  if(!ptr1) { ptr1 = strstr(msg, "\r\ncseq:"); }
  if(!ptr1) { ptr1 = strstr(msg, "\r\nCseq:"); }
  if(!ptr1) { WARNING_P1("No valid Cseq header in request %s", msg); return 0;}
 
  ptr1 += 7;
 
  while((*ptr1 == ' ') || (*ptr1 == '\t')) {++ptr1;}
 
  if(!(*ptr1)) { WARNING("No valid Cseq data in header"); return 0;}
 
  return strtoul(ptr1, NULL, 10);
}

unsigned long get_reply_code(char *msg)
{
  while((msg) && (*msg != ' ') && (*msg != '\t')) msg ++;
  while((msg) && ((*msg == ' ') || (*msg == '\t'))) msg ++;

  if ((msg) && (strlen(msg)>0)) {
    return atol(msg);
  } else {
    return 0;
  }
}

/*************************** I/O functions ***************************/

#ifdef _USE_OPENSSL
int recv_all_tls(SSL *ssl, char *buffer, int size, int trace_id)
{
  int    recv_size = 0;
  char * start_buffer = buffer;
  int    to_be_recvd = size;
  int    part_size ;
  int    err;

  recv_size = SSL_read(ssl,buffer, size);
  sip_tls_error_handling(ssl, recv_size);
  if(recv_size <= 0) {
	   
    if(recv_size != 0) {
      nb_net_recv_errors++;
      WARNING_P3("TLS %d Recv error : size = %d,Dummy : %d ",
                 trace_id, recv_size, trace_id);
    } else {
      /* This is normal for a server to have its client close
       * the connection */
      if(toolMode != MODE_SERVER) {
        WARNING_P3("TLS %d Recv error : size = %d, dummy : %d  "
                   "remote host closed connection",
                   trace_id, recv_size,trace_id);
        nb_net_recv_errors++;
      }
    }
  }
  
  return recv_size;
}
#endif

int recv_all_tcp(int sock, char *buffer, int size, int trace_id)
{
  int    recv_size = 0;
  char * start_buffer = buffer;
  int    to_be_recvd = size;
  int    part_size ;
  do {
    part_size = recv(sock, start_buffer, to_be_recvd, 0);
    
    if(part_size > 0) {
      to_be_recvd -= part_size;
      start_buffer += part_size;
      recv_size += part_size;
    } else {
      recv_size = part_size;
    }
    
  } while((part_size > 0) && to_be_recvd);
  
  if(recv_size <= 0) {
    if(recv_size != 0) {
      nb_net_recv_errors++;
      WARNING_P3("TCP %d Recv error : size = %d, sock = %d",
                 trace_id, recv_size, sock);
      WARNING_NO("TCP Recv error");
      // ERROR_NO("TCP recv error");
    } else {
#ifdef __3PCC__
      if (toolMode == MODE_3PCC_CONTROLLER_B) {
        /* In 3PCC controller B mode, twin socket is closed at peer closing.
         * This is a normal case: 3PCC controller B should end now */
        if (localTwinSippSocket) close(localTwinSippSocket);
        if (twinSippSocket) close(twinSippSocket);
        ERROR("3PCC controller A has ended -> exiting");
      } else
#endif
        /* This is normal for a server to have its client close
         * the connection */
        if(toolMode != MODE_SERVER) {
          WARNING_P3("TCP %d Recv error : size = %d, sock = %d, "
                     "remote host closed connection",
                     trace_id, recv_size, sock);
#ifdef __3PCC__
	  if(sock == twinSippSocket || sock == localTwinSippSocket) {
            int L_poll_idx = 0 ;
	    quitting = 1;
	    for((L_poll_idx) = 0;
	        (L_poll_idx) < pollnfds;
	        (L_poll_idx)++) {
	         if(pollfiles[L_poll_idx].fd == twinSippSocket) {
		   pollset_remove(L_poll_idx);
                  }
		 if(pollfiles[L_poll_idx].fd == localTwinSippSocket) {
		    pollset_remove(L_poll_idx);
                  }
              }
	      if(twinSippSocket) {
		       shutdown(twinSippSocket, SHUT_RDWR);
		       close(twinSippSocket);
		       twinSippSocket = 0 ;
              }
	      if(localTwinSippSocket) {
		       shutdown(localTwinSippSocket, SHUT_RDWR);
		       close(localTwinSippSocket);
		       localTwinSippSocket = 0 ;
              }
          }
#endif


          nb_net_recv_errors++;
        }
    }
  }
  
  return recv_size;
}


#ifdef _USE_OPENSSL
int recv_tls_message(SSL * ssl,
                     char *buffer,
                     int buffer_size,
                     E_Alter_YesNo alter_msg)
{
  int len = 0;
  int recv_size;
  char * ctl_hdr;
  int content_length;

  len = recv_size = recv_all_tls(ssl, buffer, buffer_size, 1);

  if(recv_size <= 0) {
    return recv_size;
  }

  if(len >= buffer_size) {
    ERROR("TLS msg too big");
  }
  buffer[len] = 0;
  return len;
}
#endif
    
int recv_tcp_message(int sock,
                     char *buffer,
                     int buffer_size,
                     E_Alter_YesNo alter_msg,
                     E_Alter_YesNo isControlMsg = E_ALTER_NO)
{
  int len = 0;
  int recv_size;
  char * ctl_hdr;
  int content_length;
  bool short_form;

  short_form = false;

  // Try to read SIP Header Message only
  // or CMD Message
  while(len < buffer_size) {
    
    // Read one char on tcp socket
    recv_size = recv_all_tcp(sock, &(buffer[len]), 1, 1);
    
    // Check read problem return
    if(recv_size <= 0) {
      return recv_size;
    }

    len++;

    // Search the end Message condition 
    if ((len > 3) && (isControlMsg == E_ALTER_NO)) {
      // In case of SIP Message \r\n follow by 
      // \r\n is header end
      if((buffer[len-1] == '\n') && 
         (buffer[len-2] == '\r') && 
         (buffer[len-3] == '\n') && 
         (buffer[len-4] == '\r')) {
        /* CRLF CRLF Detected */
        buffer[len] = 0;
        break;
      }
    }
    else
    {
      // In case of CMD Message
      // escape char is the end of message
      if((alter_msg==E_ALTER_NO) &&
         (buffer[len-1] == 27)) {
        /* End delimitor detected, stop receiving */
        buffer[len-1] = 0;
        return (len - 1);
      }
    }
  }

  if(len >= buffer_size) {
    ERROR("TCP msg too big");
  }
  
  // Now search the content length of the body
  // part of SIP or CMD Message
  ctl_hdr = strstr(buffer, "\r\nContent-Length:");
  if(!ctl_hdr) {ctl_hdr = strstr(buffer, "\r\nContent-length:"); }
  if(!ctl_hdr) {ctl_hdr = strstr(buffer, "\r\ncontent-Length:"); }
  if(!ctl_hdr) {ctl_hdr = strstr(buffer, "\r\ncontent-length:"); }
  if(!ctl_hdr) {ctl_hdr = strstr(buffer, "\r\nCONTENT-LENGTH:"); }
  if(!ctl_hdr) {ctl_hdr = strstr(buffer, "\r\nl:"); short_form = true; }

  // Content Length was found
  // Read its value
  if((ctl_hdr) && (alter_msg==E_ALTER_YES)) {
    if (short_form) {
      ctl_hdr += 4; 
    } else {
      ctl_hdr += 17; 
    }
    content_length = atoi(ctl_hdr);
  } else {
    content_length = 0;
  }
  
  // If a body exist read it
  if(content_length) {

    /* Ensure remaining content will fit in remaining buffer size */
    if(content_length > (buffer_size - len)) {
      ERROR("TCP msg too big");
    }
    // Read Body part 
    do {
      recv_size = recv_all_tcp(sock, &(buffer[len]), content_length, 2);
      
      if(recv_size <= 0) {
        return recv_size;
      }
      
      len += recv_size;
      content_length -= recv_size;
    } while(content_length);
  }
  
  // Add the final '\0'
  buffer[len] = 0;
  
  return len;
}

int decompress_if_needed(int sock, char *buff,  int len, void **st)
{
  if(compression && len) {
    if (useMessagef == 1) {	  
    struct timeval currentTime;
    GET_TIME (&currentTime);
    TRACE_MSG((s,
               "----------------------------------------------- %s\n"
               "Compressed message received, header :\n"
               "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
               "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
               CStat::instance()->formatTime(&currentTime),
               buff[0] , buff[1] , buff[2] , buff[3],
               buff[4] , buff[5] , buff[6] , buff[7],
               buff[8] , buff[9] , buff[10], buff[11],
               buff[12], buff[13], buff[14], buff[15]));
    }
    
    int rc = comp_uncompress(st,
                             buff, 
                             (unsigned int *)&len);
    
    switch(rc) {
    case COMP_OK:
      TRACE_MSG((s,"Compressed message decompressed properly.\n"));
      break;

    case COMP_REPLY:
      TRACE_MSG((s, 
                 "Compressed message KO, sending a reply (resynch).\n"));
      sendto(sock,
             buff, 
             len, 
             0,
             (sockaddr *)(void *)&remote_sockaddr,
             SOCK_ADDR_SIZE(&remote_sockaddr));
      resynch_send++;
      return 0;

    case COMP_DISCARD:
      TRACE_MSG((s, "Compressed message discarded by pluggin.\n"));
      resynch_recv++;
      return 0;

    default:
    case COMP_KO:
      ERROR("Compression pluggin error");
      return 0;
    }
  }
  return len;
}

void sipp_customize_socket(int s)
{
  unsigned int buffsize = 65535;

  /* Allows fast TCP reuse of the socket */
#ifdef _USE_OPENSSL
  if (transport == T_TCP || transport == T_TLS ) { 
#else
  if (transport == T_TCP) { 
#endif
    int sock_opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt,
                   sizeof (sock_opt)) == -1) {
      ERROR_NO("setsockopt(SO_REUSEADDR) failed");
    }
#ifndef SOL_TCP
#define SOL_TCP 6
#endif
    if (setsockopt (s, SOL_TCP, TCP_NODELAY, (void *)&sock_opt,
                    sizeof (sock_opt)) == -1) {
      {
        ERROR_NO("setsockopt(TCP_NODELAY) failed");
      }
    }

    {
      struct linger linger;
      
      linger.l_onoff = 1;
      linger.l_linger = 1;
      if (setsockopt (s, SOL_SOCKET, SO_LINGER, 
                      &linger, sizeof (linger)) < 0) {
        ERROR_NO("Unable to set SO_LINGER option");
      }
    }
  }
    
    /* Increase buffer sizes for this sockets */
  if(setsockopt(s,
                SOL_SOCKET,
                SO_SNDBUF,
                &buffsize,
                sizeof(buffsize))) {
    ERROR_NO("Unable to set socket sndbuf");
  }
  
  buffsize = 65535;
  if(setsockopt(s,
                SOL_SOCKET,
                SO_RCVBUF,
                &buffsize,
                sizeof(buffsize))) {
    ERROR_NO("Unable to set socket rcvbuf");
  }
  
}
  
#ifdef _USE_OPENSSL
int send_message_tls(SSL *ssl, void ** comp_state, char * msg)
{
	int rc;
	
	 rc = send_nowait_tls(ssl, msg, strlen(msg), 0);

  if(rc == 0) {
    nb_net_send_errors++;
    WARNING_NO("Unable to send TLS message");
    return -2;
  }

  return rc;
}
#endif

int send_message(int s, void ** comp_state, char * msg)
{

  struct sockaddr_storage *L_dest = &remote_sockaddr;

  if(transport == T_TCP) {

    int rc;

    rc = send_nowait(s, 
                     msg, 
                     strlen(msg), 
                     0);
    
   if (rc >= 0 && rc != strlen(msg))
    {
      int idx;
		  
      /* Truncated message sent ... we need to store pending msg */
      for(idx = 0;
          idx < pollnfds;
          idx++) {
        if (pollfiles[idx].fd == s) {
          pending_msg[idx] = strdup(msg+rc);
          return 0;
        }
      }
    }
    
    if(rc <= 0) {
    TRACE_MSG((s,"Error send\n"));    
    
#ifdef EAGAIN
    if((ctrlEWGlobal == false) && (errno == EAGAIN)) {
      int             L_idx     ;

      TRACE_MSG((s,"problem EAGAIN \n"));

      if (multisocket) {
         char          * L_call_id;
         call          * L_call_ptr;

         L_call_id = get_call_id(msg);
         L_call_ptr = get_call(L_call_id);
         L_call_ptr -> poll_flag_write = true ;

      } else {
        ctrlEW  = true ;
      }

      ctrlEWGlobal = true ;

      for(L_idx = 0;
          L_idx < pollnfds;
          L_idx++) {
       if (pollfiles[L_idx].fd == s) {
            TRACE_MSG((s,"problem EAGAIN on socket  %d and poll_idx  is %d \n", pollfiles[L_idx].fd, L_idx));
            pollfiles[L_idx].events  = POLLOUT ;
        }
      }
      nb_net_cong++;
      return 0;
    }
#endif


    if((ctrlEWGlobal == false) && (errno == EWOULDBLOCK)) {
      int             L_idx     ;

      TRACE_MSG((s,"problem EWOULDBLOCK \n"));

      if (multisocket) {
         char          * L_call_id;
         call          * L_call_ptr;

         L_call_id = get_call_id(msg);
         L_call_ptr = get_call(L_call_id);
         L_call_ptr -> poll_flag_write = true ;

      } else {
        ctrlEW  = true ;
      }

      ctrlEWGlobal = true ;

      for(L_idx = 0;
          L_idx < pollnfds;
          L_idx++) {
       if (pollfiles[L_idx].fd == s) {
            TRACE_MSG((s,"problem EWOULDBLOCK on socket  %d and poll_idx  is %d \n", pollfiles[L_idx].fd, L_idx));
            pollfiles[L_idx].events  = POLLOUT ;
        }
      }
      nb_net_cong++;
      return 0;
    }
    

    
    if(errno == EPIPE) {
      nb_net_send_errors++;
      if (reset_number > 0) {
        WARNING("Broken pipe on TCP connection, remote peer "
                "probably closed the socket");
        start_calls = 1;
        return -2;
      } else {
        ERROR("Broken pipe on TCP connection, remote peer "
            "probably closed the socket");
      }
    }

      nb_net_send_errors++;
      WARNING_NO("Unable to send TCP message");
      return -2;
    }
  } else { /* UDP */

    unsigned int len = strlen(msg);
    
    if(compression) {
      static char comp_msg[SIPP_MAX_MSG_SIZE];
      strcpy(comp_msg, msg);
      if(comp_compress(comp_state,
                       comp_msg, 
                       &len) != COMP_OK) {
        ERROR("Compression pluggin error");
      }
      msg = (char *)comp_msg;

      TRACE_MSG((s, "---\nCompressed message len: %d\n",
                 len));
    }

    // different remote sending address from received
    if (use_remote_sending_addr) {
      L_dest = &remote_sending_sockaddr ;
    }

    if(sendto(s, 
              msg, 
              len, 
              0,
              (struct sockaddr *)(void *)L_dest,
              SOCK_ADDR_SIZE(L_dest)) == -1) {
      nb_net_send_errors++;
      ERROR_NO("Unable to send UDP message");
      return -2;
    }
  }
  return 0;
}

/****************************** Network Interface *******************/

int recv_message(char * buffer, int buffer_size, int * poll_idx)
{
  int size = 0;

#ifdef _USE_OPENSSL 
  BIO *bio;
  SSL *ssl;
#endif
  int err;
  
  for((*poll_idx) = 0;
      (*poll_idx) < pollnfds;
      (*poll_idx)++) {

    if((pollfiles[(*poll_idx)].revents & POLLOUT) != 0 ) {
       TRACE_MSG((s,"exit problem event %d  on socket  %d \n", pollfiles[(*poll_idx)].revents,pollfiles[(*poll_idx)].fd));
       if (multisocket) {
          call * L_recv_call = pollcalls[(*poll_idx)];
          if(L_recv_call) {
            L_recv_call ->  poll_flag_write = false ;
            TRACE_MSG((s,"exit problem EAGAIN on socket  %d \n", L_recv_call -> call_socket));
          } 
       } else {
         ctrlEW  = false ;
       }

      if (pending_msg[(*poll_idx)] != NULL)
      {
        char * VP_tmp = strdup(pending_msg[(*poll_idx)]);
        free(pending_msg[(*poll_idx)]);
        pending_msg[(*poll_idx)] = NULL;
        send_message(pollfiles[(*poll_idx)].fd, NULL, VP_tmp);
        free(VP_tmp);
      }



      pollfiles[(*poll_idx)].revents = 0;
      pollfiles[(*poll_idx)].events = POLLIN | POLLERR;
      return 0 ;
    } else  {

    if((pollfiles[(*poll_idx)].revents & POLLIN) != 0) {
      
      call * recv_call = pollcalls[(*poll_idx)];
      int s = pollfiles[(*poll_idx)].fd;
      int ss = s;

      pollfiles[(*poll_idx)].revents = 0;

#ifdef __3PCC__
      if(s == localTwinSippSocket)
        {
          sipp_socklen_t len = sizeof(twinSipp_sockaddr);
          twinSippSocket = accept(s,
                                  (sockaddr *)(void *)&twinSipp_sockaddr,
                                  &len);
          
          pollset_add(0, twinSippSocket);

          return(-2);
        } 
      else if (s == twinSippSocket)
        {
          size = recv_tcp_message(s,
                                  buffer,
                                  buffer_size,
                                  E_ALTER_NO,
                                  E_ALTER_YES);
          if(size >= 0) {
            buffer[size] = 0;
          }
          else
            buffer[0] = 0;
          return size;
        }
        else
        {
#endif
      
#ifdef _USE_OPENSSL
      if(transport == T_TCP ||  transport == T_TLS ) {
#else
      if(transport == T_TCP ) {
#endif
        
        if(s == main_socket) {

          /* New incoming connection */
          sipp_socklen_t len = SOCK_ADDR_SIZE(&remote_sockaddr);
          int new_sock = accept(s,
                                (sockaddr *)(void *)&remote_sockaddr,
                                &len);
          
#ifdef _USE_OPENSSL
          if (transport == T_TLS ) {

            /* Create a SSL object */
            if (!(ssl = SSL_new(sip_trp_ssl_ctx))){
              ERROR("Unable to create new SSL context recv_message: Fail SSL_new\n");
            }

            // if ( (bio = BIO_new_socket(new_sock,BIO_NOCLOSE)) == NULL) {
	     
            if ( (bio = BIO_new_socket(new_sock,BIO_CLOSE)) == NULL) {
              ERROR("Unable to create the BIO- New TLS connection - recv_message\n");
	    } 
	    

	    // SSL_set_fd(ssl, new_sock);

            SSL_set_bio(ssl,bio,bio);

            if ( (err = SSL_accept(ssl)) < 0 ) {
              if (reset_number > 0) {
                WARNING("SSL_accept Fails - recv_message()\n");
                start_calls = 1;
                return -2;
              } else {
                ERROR("SSL_accept Fails - recv_message()\n");
              }
            }

            ssl_list[new_sock] = ssl;

          }

          (*poll_idx) = pollset_add(0, new_sock);
	  // TRACE_MSG((s,"new call server sock  %d and poll_idx  is %d \n", new_sock, (*poll_idx))); 
#else 
          pollset_add(0, new_sock);
#endif

          return -2;
        }
#ifdef _USE_OPENSSL
        if ( transport == T_TLS ) {
          int ss = s;
          ssl = ssl_list[s];
          size = recv_tls_message(ssl,
                                  buffer,
                                  buffer_size,
                                  E_ALTER_YES);
        } else {
#endif
        size = recv_tcp_message(s,
                                buffer,
                                buffer_size,
                                E_ALTER_YES);
#ifdef _USE_OPENSSL
        }
#endif
        
        if(size <= 0) { /* Remote side closed TCP connection */
          
          nb_net_recv_errors++;
          /* Preventive cleaning */
          if(size < 0) {
            WARNING_P2("TCP/TLS recv error on socket %d, index = %d",
                       s, *poll_idx);
            if (reset_number > 0) {
              start_calls = 1;
              return 0;
            } else { 
              ERROR_NO("TCP/TLS recv_error");
            }
          } else {
            /* Remote side closed TCP connection */
          }

          if(recv_call) {
            recv_call -> call_socket = 0;
            if(recv_call -> pollset_index) {
              recv_call -> pollset_index = 0;
            }
          }
          
          pollset_remove((*poll_idx));
          shutdown(s, SHUT_RDWR);
          close(s);
          return 0;
        }
        
      } else { /* T_UDP */
        
        if(toolMode == MODE_SERVER) {
          sipp_socklen_t len = SOCK_ADDR_SIZE(&remote_sockaddr);
          
          size  = recvfrom(s,
                           buffer,
                           buffer_size,
                           0,
                           (sockaddr *)(void *)&remote_sockaddr,
                           &len);
          
        } else {
          size  = recvfrom(s, 
                           buffer, 
                           buffer_size, 
                           0, NULL, NULL);
        }
        
        if(size < 0) {
          WARNING_P3("Unexpected UDP recv error, idx = %d, "
                     "socket = %d, recv_call = 0x%08x",
                     (*poll_idx), s, recv_call);
          ERROR_NO("Unexpected UDP recv error");
#if 0
          nb_net_recv_errors++;
          pollset_remove((*poll_idx));
          shutdown(s, SHUT_RDWR);
          close(s);
#endif
          return 0;
        }

        if (size > 0) {

          size = decompress_if_needed(s,
                                      buffer,
                                      size,
                                      ((recv_call) ? 
                                       (&(recv_call -> comp_state)) : 
                                       &monosocket_comp_state));
        }

      } /* else ... T_UDP */
      
      break;

#ifdef __3PCC__
      }
#endif
    } /* if(pollfiles[(*poll_idx)].revents) */
	} // POLLOUT
  } /* for((*poll_idx)) */
  
  buffer[size] = 0;

  if (useMessagef == 1) {
  struct timeval currentTime;
  GET_TIME (&currentTime);
  TRACE_MSG((s, "----------------------------------------------- %s\n"
             "%s message received [%d] bytes :\n\n%s\n",
             CStat::instance()->formatTime(&currentTime),
             TRANSPORT_TO_STRING(transport), size,
             buffer));
  }

  return size;
}

void pollset_process(bool ipv6)
{
  int rs; /* Number of times to execute recv().
	     For TCP with 1 socket per call:
	         no. of events returned by poll
	     For UDP and TCP with 1 global socket:
	         recv_count is a flag that stays up as
	         long as there's data to read */

  int loops = max_recv_loops;
  int update_freq = (div(loops,update_nb)).quot ;
  
  while((loops-- > 0) && /* Ensure some minimal statistics display sometime */
        (rs = poll(pollfiles, pollnfds,  1)) > 0) {
    if((rs < 0) && (errno == EINTR)) {
      return;
    }
    
    if (update_freq > 0) {
      if ((div(loops,update_freq)).rem == 0 ) { 
      /*if (loops % update_freq == 0 ) {*/
        clock_tick = getmilliseconds();
      }
    }

    if(rs < 0) {
      ERROR_NO("poll() error");
    }
    
    while(rs > 0) {
      char            msg[SIPP_MAX_MSG_SIZE];
      int             msg_size;
      char          * call_id;
      call          * call_ptr;
      int             pollset_index = 0;
      
      memset(msg,0,sizeof(msg));
      msg_size = recv_message(msg, 
                              SIPP_MAX_MSG_SIZE, 
                              &pollset_index
			);
      
      //    TRACE_MSG((s,"msg_size %d and pollset_index is %d \n", msg_size, pollset_index));
      if(msg_size > 0) {
	
	if (sipMsgCheck(msg, 
			msg_size
#ifdef __3PCC__
			,pollset_index
#endif // __3PCC__
			) == true) {
	  
          call_id = get_call_id(msg);
          call_ptr = get_call(call_id);
        
          if(!call_ptr)
            {
              if(toolMode == MODE_SERVER) 
                {
                  if (quitting < 1) {
                    // Adding a new INCOMING call !
                    CStat::instance()->computeStat
                      (CStat::E_CREATE_INCOMING_CALL);
#ifdef _USE_OPENSSL  
                    call_ptr = add_call(call_id , pollset_index, ipv6); 
                    pollset_attached(call_ptr,pollset_index);
#else	
                    call_ptr = add_call(call_id , ipv6); 
#endif
                    if(!call_ptr) {
                      outbound_congestion = true;
                      CStat::instance()->computeStat(CStat::E_CALL_FAILED);
                      CStat::instance()->computeStat(CStat::E_FAILED_OUTBOUND_CONGESTION);
                    } else {
                      outbound_congestion = false;
                      if((pollset_index) && 
                         (pollfiles[pollset_index].fd != main_socket) && 
                         (pollfiles[pollset_index].fd != tcp_multiplex) ) {
                        call_ptr -> call_socket = pollfiles[pollset_index].fd;
                      }
                    }
                } else {
                  nb_out_of_the_blue++;
                  CStat::instance()->computeStat
                    (CStat::E_OUT_OF_CALL_MSGS);
                  TRACE_MSG((s,"Discarded message for new calls while quitting\n"));

                }
              }
#ifdef __3PCC__
              else if(toolMode == MODE_3PCC_CONTROLLER_B || toolMode == MODE_3PCC_A_PASSIVE)
                {
                  // Adding a new OUTGOING call !
                  CStat::instance()->computeStat
                    (CStat::E_CREATE_OUTGOING_CALL);
                  call_ptr = add_call(call_id ,ipv6);
                  if(!call_ptr) {
                    outbound_congestion = true;
                    CStat::instance()->computeStat(CStat::E_CALL_FAILED);
                    CStat::instance()->computeStat(CStat::E_FAILED_OUTBOUND_CONGESTION);
                  } else {
                    outbound_congestion = false;
                    if((pollset_index) && 
                       (pollfiles[pollset_index].fd != main_socket) && 
                       (pollfiles[pollset_index].fd != tcp_multiplex) &&
                       (pollfiles[pollset_index].fd != localTwinSippSocket) &&
                       (pollfiles[pollset_index].fd != twinSippSocket)) {
                      call_ptr -> call_socket = pollfiles[pollset_index].fd;
                    }
                  }
                }
#endif
              else // mode != from SERVER and 3PCC Controller B
                {
                  // This is a message that is not relating to any known call
                  if (auto_answer == true) {
                    // If auto answer mode, try to answer the incoming message
                    // with automaticResponseMode
                    // call is discarded before exiting the block
#ifdef _USE_OPENSSL  
                    call_ptr = add_call(call_id , pollset_index, ipv6); 
                    pollset_attached(call_ptr,pollset_index);
#else	
                    call_ptr = add_call(call_id , ipv6); 
#endif
                    if (call_ptr) {
                      call_ptr->last_recv_msg = (char *) realloc(call_ptr->last_recv_msg, strlen(msg) + 1);
                      strcpy(call_ptr->last_recv_msg, msg);
                      call_ptr->automaticResponseMode(4, msg);
                      delete_call(call_id);
                      call_ptr = NULL;
                      total_calls--;
                      call::m_counter--;
                    }
                  } else {
                    nb_out_of_the_blue++;
                    CStat::instance()->computeStat
                      (CStat::E_OUT_OF_CALL_MSGS);
                    WARNING_P1("Discarding message which can't be mapped to a known SIPp call:\n%s", msg);
		  }
                }
            }
		
          if(call_ptr)
            {
#ifdef __3PCC__
              if( (pollfiles[pollset_index].fd == localTwinSippSocket) ||
                  (pollfiles[pollset_index].fd == twinSippSocket))
                {
                  if(!call_ptr -> process_twinSippCom(msg))
                    {
                      return;
                    } 
                }
              else
#endif
                {
                  if(!call_ptr -> process_incoming(msg))
                    {
                      /* Needs to rebuild the pollset (socket removed, 
                       * call deleted, etc... Cause pollcalls is now 
                       * invalid and will alway lead poll() to return 
                       * an error.*/
                      return;
                    }
                }
            }
	} else { // sipMsgCheck == false
	  // unrecognized message => discard it
	  WARNING("non SIP message discarded");
	}
	if (pollnfds > 0) /* refer to note at the beginning of this function */
               rs--;
        if (!start_calls) { 
          rs = 0;
        }
           
      } // end if msg >=0
      else 
      rs--;
    }
  }
  cpu_max = loops <= 0;
}

void timeout_alarm(int param){
  quitting = 1;
  timeout_exit = true;
}

/* Send loop & trafic generation*/

void traffic_thread(bool ipv6)
{
  unsigned int calls_to_open = 0;
  unsigned int new_time;
  unsigned int last_time;
  bool         firstPass;

  /* create the file */
  char         L_file_name [MAX_PATH];
  sprintf (L_file_name, "%s_%d_screen.log", scenario_file, getpid());

  firstPass = true;
  last_time = getmilliseconds();
 
  /* Prepare pollset with basic sockets */
  pollset_reset();

  /* Arm the global timer if needed */
  if (global_timeout > 0) { 
    signal(SIGALRM, timeout_alarm);
    alarm(global_timeout);
  }
  
  while(1) {

    scheduling_loops ++;

    /* update local time, except if resetted*/
    new_time = getmilliseconds();

    clock_tick = new_time;
    last_time = new_time;

    if (start_calls == 1) {
      reset_connections();
    }

    if (signalDump) {
       /* Screen dumping in a file */
       if (screenf) {
          print_screens();
       } else {
         /* If the -trace_screen option has not been set, */
         /* create the file at this occasion              */
         screenf = fopen(L_file_name, "a");
	 if (!screenf) {
            WARNING_P1("Unable to create '%s'", L_file_name); 
         }
	 print_screens();
	 fclose(screenf);
	 screenf = 0;
       }

       if(dumpInRtt) {
          CStat::instance()->dumpDataRtt ();
       }

       signalDump = false ;
    }

    if ((!quitting) && (!paused) && (!start_calls)) {
      long l=0;

      if (users) {
	calls_to_open = ((l = (users - open_calls)) > 0) ? l : 0;
      } else {
	calls_to_open = (unsigned int)
              ((l=(long)floor((((clock_tick - last_rate_change_time) * rate/rate_period_s) / 1000)
              - calls_since_last_rate_change))>0?l:0);
      }


      if( (toolMode == MODE_CLIENT)
#ifdef __3PCC__
          || (toolMode == MODE_3PCC_CONTROLLER_A)
#endif
          )
        {
          while((calls_to_open--) && 
                (open_calls < open_calls_allowed) &&
                (total_calls < stop_after)) 
            {
              // adding a new OUTGOING CALL
              CStat::instance()->computeStat(CStat::E_CREATE_OUTGOING_CALL);
              call * call_ptr = add_call(ipv6);
              if(!call_ptr) {
                outbound_congestion = true;
                CStat::instance()->computeStat(CStat::E_CALL_FAILED);
                CStat::instance()->computeStat(CStat::E_FAILED_OUTBOUND_CONGESTION);
              } else {
                 outbound_congestion = false;
                 call_ptr -> run();
	      }

	      new_time = getmilliseconds();
	      /* Never spend more than half of our time processing new call requests. */
	      if (new_time > (clock_tick + (timer_resolution < 2 ? 1 : (timer_resolution / 2)))) {
		break;
	      }
            }
        
          if(open_calls >= open_calls_allowed) {
            set_rate(rate);
          }
        }

        // Quit after asked number of calls is reached
        if(total_calls >= stop_after) {
          quitting = 1;
        }
      
      
    } else if (quitting) {
      if (quitting > 11) {
        /* Force exit: abort all calls */
        delete_calls();
      }
      /* Quitting and no more openned calls, close all */
      if(!open_calls) {
        // Dump the latest statistics if necessary
        if(dumpInFile) {
          CStat::instance()->dumpData();
        }

        if(dumpInRtt) {
          CStat::instance()->dumpDataRtt();
        }

        /* Screen dumping in a file if asked */
        if(screenf) {
          print_screens();
        }
#ifndef _USE_OPENSSL
        if (multisocket) {
          if (!socket_open) {
             int    L_counter;
             for (L_counter = 0; L_counter < pollnfds; L_counter++) {
               if (pollfiles[L_counter].fd != 0) { 
                  pollset_remove(L_counter);
               }
             }

             for (L_counter = min_socket; L_counter < (max_multi_socket+min_socket) ; L_counter ++) {
                shutdown(L_counter, SHUT_RDWR);
                close(L_counter);
             }
           }

         if (tab_multi_socket != NULL) {
           delete [] tab_multi_socket ;
           tab_multi_socket = NULL ;
         }
        }
#endif
	
        screen_exit(EXIT_TEST_RES_UNKNOWN);
      }
    }

    if(compression) {
      timer_resolution = 50;
    }

    new_time = getmilliseconds();
    clock_tick = new_time;
    last_time = new_time;

    /* Schedule all pending calls and process their timers */
    if((clock_tick - last_timer_cycle) > timer_resolution) {
      call_list *running_calls;
      call_list::iterator iter;

      /* Just for the count. */
      running_calls = get_running_calls();
      last_running_calls = running_calls->size();

      /* If we have expired paused calls, move them to the run queue. */
      last_woken_calls = expire_paused_calls();

      /* Now we process calls that are on the run queue. */
      running_calls = get_running_calls();
      last_paused_calls = paused_calls_count();

      /* Workaround hpux problem with iterators. Deleting the
       * current object when iterating breaks the iterator and
       * leads to iterate again on the destroyed (deleted)
       * object. Thus, we have to wait ont step befere actual
       * deletion of the object*/
      call * last = NULL;


      for(iter = running_calls->begin(); iter != running_calls->end(); iter++) {
        if(last) { last -> run(); }
        last = *iter;
      }
      if(last) { last -> run(); }

      last_timer_cycle = clock_tick;

      new_time = getmilliseconds();
      clock_tick = new_time ;
      last_time = new_time;

    }

    /* Receive incoming messages */
    pollset_process(ipv6);

    new_time = getmilliseconds();
    clock_tick = new_time ;
    last_time = new_time;

    if(firstPass)
      {
        // dumping (to create file on disk) and showing 
        // screen at the beginning even if the report
        // period is not reach
        firstPass = false;
        print_statistics(0);
        /* Dumping once to create the file on disk */
        if(dumpInFile)
          {
            CStat::instance()->dumpData();
          }
        if(dumpInRtt)
          {
            CStat::instance()->dumpDataRtt();
          }

      }

    if((clock_tick - last_report_time) >= report_freq)
      {
        print_statistics(0);
        CStat::instance()->computeStat(CStat::E_RESET_PD_COUNTERS);
        last_report_time  = clock_tick;
        last_report_calls = total_calls;
        scheduling_loops = 0;
      }

    // FIXME - Should we recompute time ? print stat take 
    // a lot of time, so the clock_time is no more 
    // the current time !
    if(dumpInFile) {
      if((clock_tick - last_dump_time) >= report_freq_dumpLog)  {
        CStat::instance()->dumpData();
        CStat::instance()->computeStat(CStat::E_RESET_PL_COUNTERS);
        last_dump_time  = clock_tick;
      }
    }
  }
}

/*************** RTP ECHO THREAD ***********************/
/* param is a pointer to RTP socket */

void rtp_echo_thread (void * param)
{
  char *msg = (char*)alloca(media_bufsize);
  size_t nr, ns;
  sipp_socklen_t len;
  struct sockaddr_storage remote_rtp_addr;


   int                   rc;
   sigset_t              mask;
   sigfillset(&mask); /* Mask all allowed signals */
   rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);

  for (;;) {
    len = sizeof(remote_rtp_addr);
    nr = recvfrom(*(int *)param, 
                  msg, 
                  media_bufsize, 0, 
                  (sockaddr *)(void *) &remote_rtp_addr, 
                  &len);

    if (((long)nr) < 0) {
      WARNING_P2("%s %i", 
                 "Error on RTP echo reception - stopping echo - errno=", 
                 errno);
      return;
    }
    ns = sendto(*(int *)param, msg, nr, 
                0, (sockaddr *)(void *) &remote_rtp_addr, 
                len);

    if (ns != nr) {
      WARNING_P2("%s %i", 
                 "Error on RTP echo transmission - stopping echo - errno=", 
                 errno);
      return;
    }
    
    if (*(int *)param==media_socket) {    
    rtp_pckts++;
    rtp_bytes += ns;
  }
    else {
      /* packets on the second RTP stream */
      rtp2_pckts++;
      rtp2_bytes += ns;
    }
  }
}

/* Help screen */

void help() 
{
  printf
    ("\n"
     "Usage:\n"
     "\n"
     "  sipp remote_host[:remote_port] [options]\n"
     "\n"
     "  Available options:\n"
     "\n"
     "   -v               : Display version and copyright information.\n"
     "\n"
     "   -bg              : Launch SIPp in background mode.\n"
     "\n"
     "   -p local_port    : Set the local port number. Default is a\n"
     "                      random free port chosen by the system.\n"
     "\n"
     "   -i local_ip      : Set the local IP address for 'Contact:',\n"
     "                      'Via:', and 'From:' headers. Default is\n"
     "                      primary host IP address.\n"
     "\n"
     "   -bind_local      : Bind socket to local IP address, i.e. the local IP\n"
     "                      address is used as the source IP address.\n"
     "                      If SIPp runs in server mode it will only listen on the\n"
     "                      local IP address instead of all IP addresses.\n"
     "\n"
     "   -inf file_name   : Inject values from an external CSV file during calls\n"
     "                      into the scenarios.\n"
     "                      First line of this file say whether the data is \n"
     "                      to be read in sequence (SEQUENTIAL) or random \n"
     "                      (RANDOM) order.\n"
     "                      Each line corresponds to one call and has one or \n"
     "                      more ';' delimited data fields. Those fields can be \n"
     "                      referred as [field0], [field1], ... in the xml \n"
     "                      scenario file.\n"
     "\n"
     "   -d duration      : Controls the length (in milliseconds) of\n"
     "                      calls. More precisely, this controls\n"
     "                      the duration of 'pause' instructions in\n"
     "                      the scenario, if they do not have a\n"
     "                      'milliseconds' section. Default value is 0.\n"
     "\n"
     "   -r rate (cps)    : Set the call rate (in calls per seconds).\n"
     "                      This value can be changed during test by\n"
     "                      pressing '+','_','*' or '/'. Default is 10.\n"
     "                      pressing '+' key to increase call rate by 1,\n"
     "                      pressing '-' key to decrease call rate by 1,\n"
     "                      pressing '*' key to increase call rate by 10,\n"
     "                      pressing '/' key to decrease call rate by 10.\n"
     "                      If the -rp option is used, the call rate is\n"
     "                      calculated with the period in ms given \n"
     "                      by the user.\n"
     "\n"
     "   -rp period (ms)  : Specify the rate period in milliseconds for the call\n"
     "                      rate.\n"
     "                      Default is 1 second.\n"
     "                      This allows you to have n calls every m milliseconds \n"
     "                      (by using -r n -rp m).\n"
     "                      Example: -r 7 -rp 2000 ==> 7 calls every 2 seconds.\n"
     "\n"
     "   -max_socket max  : Set the max number of sockets to open simultaneously.\n"
     "                      This option is significant if you use one socket\n"
     "                      per call. Once this limit is reached, traffic is\n"
     "                      distributed over the sockets already opened.\n"
     "                      Default value is 50000.\n"
     "\n"
     "   -timer_resol     : Set the timer resolution in milliseconds.\n"
     "                      This option has an impact on timers precision.\n"
     "                      Small values allow more precise scheduling but\n"
     "                      impacts CPU usage.\n"
     "                      If the compression is on, the value is set to 50ms.\n"
     "                      The default value is 200ms.\n"
     "\n"
     "   -max_recv_loops  : Set the maximum number of messages received read per\n"
     "                      cycle. Increase this value for high traffic level.\n"
     "                      The default value is 1000.\n"
     "\n"
     "   -up_nb           : Set the number of updates of the internal clock during\n"
     "                      the reading of received messages.\n"
     "                      Default value is 1.\n"
     "\n"
     "   -base_cseq n     : Start value of [cseq] for each call.\n"
     "\n"
     "   -cid_str string  : Call ID string (default %%u-%%p@%%s).\n"
     "                      %%u=call_number, %%s=ip_address, %%p=process_number,\n"
     "                      %%%%=%% (in any order).\n"
#ifdef _USE_OPENSSL
     "\n"
     "   -auth_uri uri    : Force the value of the URI for authentication.\n"
     "                      By default, the URI is composed of \n"
     "                      remote_ip:remote_port.\n" 
#endif
     "\n"
     "   -sf filename     : Loads an alternate xml scenario file.\n"
     "                      To learn more about XML scenario syntax,\n"
     "                      use the -sd option to dump embedded \n"
     "                      scenarios. They contain all the necessary\n"
     "                      help.\n"
     "\n"
     "   -sn name         : Use a default scenario (embedded in\n"
     "                      the sipp executable). If this option is omitted,\n"
     "                      the Standard SipStone UAC scenario is loaded.\n"
     "                      Available values in this version:\n"
     "\n"
     "                        'uac'      : Standard SipStone UAC (default).\n"
#ifdef PCAPPLAY
     "                        'uac_pcap' : Standard SipStone UAC with pcap\n"
     "                                     play (RTP)\n"
#endif
     "                        'uas'      : Simple UAS responder.\n"
     "                        'regexp'   : Standard SipStone UAC - with\n"
     "                                     regexp and variables.\n"
     "                        'branchc'  : Branching and conditional\n"
     "                                     branching in scenarios - client.\n"
     "                        'branchs'  : Branching and conditional\n"
     "                                     branching in scenarios - server.\n"
#ifdef __3PCC__
     "\n"
     "                      Default 3pcc scanerios (see -3pcc option):\n"
     "\n"
     "                        '3pcc-C-A' : Controller A side (must be started\n"
     "                                     after all other 3pcc scenarios)\n"
     "                        '3pcc-C-B' : Controller B side.\n"
     "                        '3pcc-A'   : A side.\n"
     "                        '3pcc-B'   : B side.\n"
#endif
     "   -ip_field nr     : Set which field from the injection file contains the\n"
     "                      IP address from which the client will send its\n"
     "                      messages.\n"
     "                      If this option is omitted and the '-t ui' option is\n"
     "                      present, then field 0 is assumed.\n"
     "                      Use this option together with '-t ui'\n"
     "\n"
     "   -sd name         : Dumps a default scenario (embeded in\n"
     "                      the sipp executable)\n"
     "\n"
#ifdef _USE_OPENSSL
     "   -t [u1|un|ui|t1|tn|l1|ln] : Set the transport mode:\n"
#else
     "   -t [u1|un|ui|t1|tn] : Set the transport mode:\n"
#endif
     "\n"
     "                        u1: UDP with one socket (default),\n"
     "                        un: UDP with one socket per call,\n"
     "                        ui: UDP with one socket per IP address\n"
     "                            The IP addresses must be defined in the\n"
     "                            injection file.\n"
     "                        t1: TCP with one socket,\n"
     "                        tn: TCP with one socket per call,\n"
#ifdef _USE_OPENSSL
     "                        l1: TLS with one socket,\n"
     "                        ln: TLS with one socket per call.\n"
#endif
     "\n");
  if(!strlen(comp_error)) {
    printf
      ("                      It appears that you installed the\n"
       "                      " COMP_PLUGGIN " plugin. 2 additionnal\n"
       "                      transport modes are available:\n"
       "\n"
       "                        c1: u1 + compression,\n"
       "                        cn: un + compression.\n"
       "\n");
  }
  printf
    ("   -trace_msg       : Displays sent and received SIP messages in\n"
     "                      <scenario file name>_<pid>_messages.log\n"
     "\n"
     "   -trace_screen    : Dump statistic screens in the \n"
     "                      <scenario_name>_<pid>_screens.log file when\n"
     "                      quitting SIPp. Useful to get a final status report\n"
     "                      in background mode (-bg option).\n"
     "\n"
     "   -trace_timeout   : Displays call ids for calls with timeouts in\n"
     "                      <scenario file name>_<pid>_timeout.log\n"
     "\n"
     "   -trace_stat      : Dumps all statistics in <scenario_name>_<pid>.csv\n"
     "                      file. Use the '-h stat' option for a detailed\n"
     "                      description of the statistics file content.\n"
     "\n"
     "   -stf file_name   : Set the file name to use to dump statistics\n"
     "\n"
     "   -trace_err       : Trace all unexpected messages in\n"
     "                      <scenario file name>_<pid>_errors.log.\n"
     "\n"
     "   -trace_logs      : Allow tracing of <log> actions in\n"
     "                      <scenario file name>_<pid>_logs.log.\n"
     "\n"
     "   -trace_rtt       : Allow tracing of all response times in\n"
     "                      <scenario file name>_<pid>_rtt.csv.\n"
     "\n"
     "   -rtt_freq freq   : freq is mandatory. Dump response times \n"
     "                      every freq calls in the log file defined \n"
     "                      by -trace_rtt. Default value is 200.\n"
     "\n"
     "   -s service_name  : Set the username part of the resquest URI.\n"
     "                      Default is 'service'.\n"
     "\n"
#ifdef _USE_OPENSSL
     "   -ap password     : Set the password for authentication challenges.\n"
     "                      Default is 'password'\n"
     "\n"
     "   -tls_cert name   : Set the name for TLS Certificate file.\n"
     "                      Default is 'cacert.pem'\n"
     "\n"
     "   -tls_key name    : Set the name for TLS Private Key file.\n"
     "                      Default is 'cakey.pem'\n"
     "\n"
     "   -tls_crl name    : Set the name for Certificate Revocation List file.\n"
     "                      If not specified, X509 CRL is not activated.\n"
     "\n"
#endif
     "   -f frequency     : Set the statistics report frequency on screen\n"
     "                      (in seconds). Default is 1.\n"
     "\n"
     "   -fd frequency    : Set the statistics dump log report frequency\n"
     "                      (in seconds). Default is 60.\n"
     "\n"
     "   -l calls_limit   : Set the maximum number of simultaneous\n"
     "                      calls. Once this limit is reached, traffic\n"
     "                      is decreased until the number of open calls\n"
     "                      goes down. Default:\n"
     "\n"
     "                        (3 * call_duration (s) * rate).\n"
     "\n"
     "   -m calls         : Stop the test and exit when 'calls' calls are\n"
     "                      processed.\n"
     "\n"
     "   -rtp_echo        : Enable RTP echo. RTP/UDP packets received\n"
     "                      on port defined by -mp are echoed to their\n"
     "                      sender.\n"
     "                      RTP/UDP packets coming on this port + 2\n"
     "                      are also echoed to their sender (used for\n"
     "                      sound and video echo).\n"
     "\n"
     "   -mp media_port   : Set the local RTP echo port number. Default\n"
     "                      is 6000.\n"
     "\n"
     "   -mi local_rtp_ip : Set the local media IP address.\n"
     "\n"
     "   -mb buf_size     : Set the RTP echo buffer size (default: 2048).\n"
     "\n"
#ifdef __3PCC__
     "   -3pcc ip:port    : Launch the tool in 3pcc mode (\"Third Party\n"
     "                      call control\"). The passed ip address\n"
     "                      is depending on the 3PCC role.\n"
     "                      - When the first twin command is 'sendCmd' then\n"
     "                      this is the address of the remote twin socket.\n"
     "                      SIPp will try to connect to this address:port to\n"
     "                      send the twin command (This instance must be started\n"
     "                      after all other 3PCC scenarii).\n"
     "                      Example: 3PCC-C-A scenario.\n"
     "                      - When the first twin command is 'recvCmd' then\n"
     "                      this is the address of the local twin socket. SIPp \n"
     "                      will open this address:port to listen for twin command.\n"
     "                      Example: 3PCC-C-B scenario.\n"
     "\n"

#endif
     "   -nr              : Disable retransmission in UDP mode.\n"
     "\n"
     "   -max_retrans     : Maximum number of UDP retransmissions before call\n"
     "                      ends on timeout.\n"
     "                      Default is 5 for INVITE transactions and 7 for\n"
     "                      others.\n"
     "\n"
     "   -recv_timeout nb : Global receive timeout in milliseconds.\n"
     "                      If the expected message is not received, the call\n"
     "                      times out and is aborted\n"
     "\n"
     "   -timeout nb      : Global timeout in seconds.\n"
     "                      If this option is set, SIPp quits after nb seconds\n"
     "\n"
     "   -nd              : No Default. Disable all default behavior of SIPp\n"
     "                      which are the following:\n"
     "                      - On UDP retransmission timeout, abort the call by\n"
     "                      sending a BYE or a CANCEL\n"
     "                      - On receive timeout with no ontimeout attribute, \n"
     "                      abort the call by sending a BYE or a CANCEL\n"
     "                      - On unexpected BYE send a 200 OK and close the call\n"
     "                      - On unexpected CANCEL send a 200 OK and close the call\n"
     "                      - On unexpected PING send a 200 OK and continue the call\n"
     "                      - On any other unexpected message, abort the call by\n"
     "                      sending a BYE or a CANCEL\n"
     "\n"
     "   -rsa host:port   : Set the remote sending address to host:port.\n"
     "                      for sending the messages.\n"
     "\n"
     "   -max_reconnect   : Set the the maximum number of reconnection.\n"
     "\n"
     "   -aa              : Enable automatic 200 OK answer for INFO and NOTIFY\n"
     "                      messages.\n"
     "\n"
     "   -tdmmap map      : Generate and handle a table of TDM circuits.\n"
     "                      A circuit must be available for the call to be placed.\n"
     "                      Format: -tdmmap {0-3}{99}{5-8}{1-31}\n"
     "\n"
     "   -xyz string      : Any other parameter used in SIP messages as [xyz].\n"
     "\n"
     "Signal handling:\n"
     "\n"
     "   SIPp can be controlled using posix signals. The following signals\n"
     "   are handled:\n"
     "   USR1: Similar to press 'q' keyboard key. It triggers a soft exit\n"
     "         of SIPp. No more new calls are placed and all ongoing calls\n"
     "         are finished before SIPp exits.\n"
     "         Example: kill -SIGUSR1 732\n"
     "   USR2: Triggers a dump of all statistics screens in\n"
     "         <scenario_name>_<pid>_screens.log file. Especially useful \n"
     "         in background mode to know what the current status is.\n"
     "         Example: kill -SIGUSR2 732\n"
     "\n"
     "Exit code:\n"
     "\n"
     "   Upon exit (on fatal error or when the number of asked calls (-m\n"
     "   option) is reached, sipp exits with one of the following exit\n"
     "   code:\n"
     "    0: All calls were successful\n"
     "    1: At least one call failed\n"
     "   97: exit on internal command. Calls may have been processed\n"
     "   99: Normal exit without calls processed\n"
     "   -1: Fatal error\n"
     "\n"
     "\n"
     "Example:\n"
     "\n"
     "   Run sipp with embedded server (uas) scenario:\n"
     "     ./sipp -sn uas\n"
     "   On the same host, run sipp with embedded client (uac) scenario\n"
     "     ./sipp -sn uac 127.0.0.1\n"
     "\n");
}


void help_stats() 
{
  printf(
"\n"
"  The  -trace_stat option dumps all statistics in the\n"
"  <scenario_name.csv> file. The dump starts with one header\n" 
"  line with all counters. All following lines are 'snapshots' of \n"
"  statistics counter given the statistics report frequency\n"
"  (-fd option). This file can be easily imported in any\n"
"  spreadsheet application, like Excel.\n"
"\n"
"  In counter names, (P) means 'Periodic' - since last\n"
"  statistic row and (C) means 'Cumulated' - since sipp was\n"
"  started.\n"
"\n"
"  Available statistics are:\n"
"\n"
"  - StartTime: \n"
"    Date and time when the test has started.\n"
"\n"
"  - LastResetTime:\n"
"    Date and time when periodic counters where last reseted.\n"
"\n"
"  - CurrentTime:\n"
"    Date and time of the statistic row.\n"
"\n"
"  - ElapsedTime:\n"
"    Elapsed time.\n"
"\n"
"  - CallRate:\n"
"    Call rate (calls per seconds).\n"
"\n"
"  - IncomingCall:\n"
"    Number of incoming calls.\n"
"\n"
"  - OutgoingCall:\n"
"    Number of outgoing calls.\n"
"\n"
"  - TotalCallCreated:\n"
"    Number of calls created.\n"
"\n"
"  - CurrentCall:\n"
"    Number of calls currently ongoing.\n"
"\n"
"  - SuccessfulCall:\n"
"    Number of successful calls.\n"
"\n"
"  - FailedCall:\n"
"    Number of failed calls (all reasons).\n"
"\n"
"  - FailedCannotSendMessage:\n"
"    Number of failed calls because Sipp cannot send the\n"
"    message (transport issue).\n"
"\n"
"  - FailedMaxUDPRetrans:\n"
"    Number of failed calls because the maximum number of\n"
"    UDP retransmission attempts has been reached.\n"
"\n"
"  - FailedUnexpectedMessage:\n"
"    Number of failed calls because the SIP message received\n"
"    is not expected in the scenario.\n"
"\n"
"  - FailedCallRejected:\n"
"    Number of failed calls because of Sipp internal error.\n"
"    (a scenario sync command is not recognized or a scenario\n"
"    action failed or a scenario variable assignment failed).\n"
"\n"
"  - FailedCmdNotSent:\n"
"    Number of failed calls because of inter-Sipp\n"
"    communication error (a scenario sync command failed to\n"
"    be sent).\n"
"\n"
"  - FailedRegexpDoesntMatch:\n"
"    Number of failed calls because of regexp that doesn't\n"
"    match (there might be several regexp that don't match\n"
"    during the call but the counter is increased only by\n"
"    one).\n"
"\n"
"  - FailedRegexpHdrNotFound:\n"
"    Number of failed calls because of regexp with hdr    \n"
"    option but no matching header found.\n"
"\n"
"  - OutOfCallMsgs:\n"
"    Number of SIP messages received that cannot be associated\n"
"    to an existing call.\n"
"\n"
"  - AutoAnswered:\n"
"    Number of unexpected specific messages received for new Call-ID.\n"
"    The message has been automatically answered by a 200 OK\n"
"    Currently, implemented for 'PING' message only.\n"
"\n");
}

/************* exit handler *****************/

void print_last_stats()
{
  interrupt = 1;
  // print last current screen
  print_statistics(1);
  // and print statistics screen
  currentScreenToDisplay = DISPLAY_STAT_SCREEN;
  print_statistics(1);
}

void releaseGlobalAllocations()
{
  int i,j;
  message * L_ptMsg = NULL;

  CStat::instance()->close();

  for(i=0; i<SCEN_VARIABLE_SIZE; i++) {
    for (j=0; j<SCEN_MAX_MESSAGES;j++)
    {
      if (scenVariableTable[i][j] != NULL)
        delete(scenVariableTable[i][j]);
      scenVariableTable[i][j] = NULL;
    }
    }
  for(i=0; i<scenario_len; i++)
  {
    L_ptMsg = scenario[i];
    if (L_ptMsg != NULL)
    {
      delete(L_ptMsg);
      scenario[i] = NULL;
    }
  }
}

char* remove_pattern(char* P_buffer, char* P_extensionPattern) {

  char *L_ptr = P_buffer;

  if (P_extensionPattern == NULL) {
    return P_buffer ;
  }

  if (P_buffer == NULL) {
    return P_buffer ;
  }

  L_ptr = strstr(P_buffer, P_extensionPattern) ;
  if (L_ptr != NULL) {
    *L_ptr = '\0' ;
  }

  return P_buffer ;
  
}

int new_socket(bool P_use_ipv6, int P_type_socket,int * P_status) {

   int  L_socket = -1 ;

   if ((!socket_open) || 
       (CStat::instance()->get_current_counter_call() > max_multi_socket)) {

       if (test_socket) {
         socket_close = false ;
         socket_open  = false ;
         test_socket  = false ;

         int    L_counter;
         tab_multi_socket = new int [ max_multi_socket + min_socket ] ;
         for (L_counter = 0; L_counter < (max_multi_socket + min_socket) ; L_counter ++) {
           tab_multi_socket [L_counter] = 0 ;
         }
       }

       L_socket = select_socket ; 
       tab_multi_socket [select_socket] ++;
       select_socket++;

       if(select_socket == (max_multi_socket + min_socket)) {
          select_socket = min_socket ; 
        }

   } else {

     // create a new socket
     if((L_socket= socket(P_use_ipv6 ? AF_INET6 : AF_INET,
                        P_type_socket,
                        0))== -1) {
          ERROR_P1("Unable to get a %s socket", TRANSPORT_TO_STRING(transport));
      }

     *P_status = 1;
     if (L_socket < min_socket ) { 
       min_socket = L_socket ;
       select_socket = min_socket ;
      }
   } 

   return (L_socket);
}


int delete_socket(int P_socket) {

   if (CStat::instance()->get_current_counter_call() > max_multi_socket) {
     tab_multi_socket[P_socket]--;
   } 
   return 0;
}


/* Main */
int main(int argc, char *argv[])
{
  int                  argi = 0;
  int                  index = 0;
  struct sockaddr_storage   media_sockaddr;
  pthread_t            pthread_id, pthread2_id,  pthread3_id;
  int                  argiFileName = 0;
  int                  argiInputFile = 0;
  char                *scenario_name = NULL;
  int                  err;
  int                  L_maxSocketPresent = 0;
  unsigned int         generic_count = 0;
  
  generic[0] = NULL;

  /* At least one argument is needed */
  if(argc < 2) {
    help();
    exit(EXIT_OTHER);
  }

  /* Ignore the SIGPIPE signal */
  {
    struct sigaction action_pipe;
    memset(&action_pipe, 0, sizeof(action_pipe));
    action_pipe.sa_handler=SIG_IGN;
    sigaction(SIGPIPE, &action_pipe, NULL);
	 
    /* sig usr1 management */
    struct sigaction action_usr1;
    memset(&action_usr1, 0, sizeof(action_usr1));
    action_usr1.sa_handler = sipp_sigusr1;
    sigaction(SIGUSR1, &action_usr1, NULL);

    /* sig usr2 management */
    struct sigaction action_usr2;
    memset(&action_usr2, 0, sizeof(action_usr2));
    action_usr2.sa_handler = sipp_sigusr2;
    sigaction(SIGUSR2, &action_usr2, NULL);
  }

  screen_set_exename((char *)"sipp");
  
  pid = getpid();
  memset(local_ip, 0, 40);
  memset(media_ip,0, 40);
  memset(media_ip_escaped,0, 42);
  
  /* Load compression pluggin if available */
  comp_load();
  
  /* Command line parsing */
  
  for(argi = 1; argi < argc; argi++) {

    int processed = 0;

    if((!strcmp(argv[argi], "-h"    )) ||
       (!strcmp(argv[argi], "--h"   )) || 
       (!strcmp(argv[argi], "--help")) || 
       (!strcmp(argv[argi], "-help" ))    ) {
      if(((argi+1) < argc) && (!strcmp(argv[argi+1], "stat"))) {
        help_stats();
      } else {
        help();
      }
      exit(EXIT_OTHER);
    }

    if(!strcmp(argv[argi], "-p")) {
      if((++argi) < argc) {
        user_port = atol(argv[argi]);
        processed = 1;
      } else {
        ERROR_P1("Missing argument for param '%s'.\nUse 'sipp -h' for details",
                 argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-mp")) {
      if((++argi) < argc) {
        media_port = atol(argv[argi]);
	processed = 1;
      } else {
        ERROR_P1("Missing argument for param '%s'.\nUse 'sipp -h' for details",
                 argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-rtp_echo")) {
      processed = 1;
      rtp_echo_enabled = true;
    }

    if(!strcmp(argv[argi], "-mi")) {
      if((++argi) < argc) {
        int dummy_port;
        processed = 1;
        strcpy(media_ip, argv[argi]);
        get_host_and_port(media_ip, media_ip, &dummy_port);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-mb")) {
      if((++argi) < argc) {
        processed = 1;
        media_bufsize = (size_t)atol(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-t")) {
      if((++argi) < argc) {
        processed = 1;
        if(!strcmp(argv[argi], "u1")) {
          transport = T_UDP;
          multisocket = 0;
          peripsocket = 0;
        } else if(!strcmp(argv[argi], "un")) {
          transport = T_UDP;
          multisocket = 1;
          peripsocket = 0;
        } else if(!strcmp(argv[argi], "ui")) {
          transport = T_UDP;
          multisocket = 1;
          peripsocket = 1;
          socket_close = false;
        } else if(!strcmp(argv[argi], "t1")) {
          transport = T_TCP;
          multisocket = 0;
        } else if(!strcmp(argv[argi], "tn")) {
          transport = T_TCP;
          multisocket = 1;
#ifdef _USE_OPENSSL
        } else if(!strcmp(argv[argi], "l1")) {
          transport = T_TLS;
          multisocket = 0;
          if ( init_OpenSSL() != 1) {
             printf("OpenSSL Initialization problem\n");
             exit ( -1);
          } 
        } else if (!strcmp(argv[argi], "ln")) {       
          transport = T_TLS;
          multisocket = 1;
          if ( init_OpenSSL() != 1) {
             printf("OpenSSL Initialization problem\n");
             exit ( -1);
          }
#endif
        } else if(!strcmp(argv[argi], "c1")) {
          if(strlen(comp_error)) {
            ERROR_P1("No " COMP_PLUGGIN " pluggin available:\n%s", comp_error);
          }
          transport = T_UDP;
          multisocket = 0;
          compression = 1;
        } else if(!strcmp(argv[argi], "cn")) {
          if(strlen(comp_error)) {
            ERROR_P1("No " COMP_PLUGGIN " pluggin available:\n%s", comp_error);
          }
          transport = T_UDP;
          multisocket = 1;
          compression = 1;
        } else {
          ERROR_P1("Invalid argument for -t param : '%s'.\n"
                   "Use 'sipp -h' for details",  argv[argi]);
        }          
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-nr")) {
      processed = 1;
      retrans_enabled = 0;
    }

    if(!strcmp(argv[argi], "-max_retrans")) {
      if((++argi) < argc) {
        processed = 1;
        if (atoi(argv[argi]) > 0) {
          max_udp_retrans = atoi(argv[argi]);
        }
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-nd")) {
      processed = 1;
      default_behavior = 0;
    }

    if(!strcmp(argv[argi], "-trace_msg")) {
      useMessagef = 1 ;
      processed = 1;
    }

    if(!strcmp(argv[argi], "-trace_screen")) {
      useScreenf = 1 ;
      processed = 1;
    }

    if(!strcmp(argv[argi], "-trace_err")) {
      processed = 1;
      print_all_responses = 1;
    }

    if(!strcmp(argv[argi], "-trace_timeout")) {
      useTimeoutf = 1 ;
      processed = 1;
    }

    if(!strcmp(argv[argi], "-trace_stat")) {
      processed  = 1;
      dumpInFile = 1;
    }

    if(!strcmp(argv[argi], "-trace_rtt")) {
       processed  = 1;
       dumpInRtt = 1;
    }

    if(!strcmp(argv[argi], "-rtt_freq")) {
       if((++argi) < argc) {
          processed = 1;
	  report_freq_dumpRtt = atol(argv[argi]) ;
        } else {
         ERROR_P1("Missing argument for param '%s'.\n"
	          "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-max_socket")) {
      if((++argi) < argc) {
        processed = 1;
        max_multi_socket = atoi(argv[argi]);
	maxSocketPresent = true ;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-base_cseq")) { /* Base for [cseq] */
      if((++argi) < argc) {
        processed = 1;
        base_cseq = atoi(argv[argi])-1; /* gets incremented before first use */
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details\n",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-cid_str")) { /* Call ID string */
      if((++argi) < argc) {
        processed = 1;
        call_id_string = argv[argi];
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details\n",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-auth_uri")) { /* Forced authentication URI */
      if((++argi) < argc) {
        processed = 1;
        auth_uri = argv[argi];
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details\n",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-trace_logs")) {
      processed  = 1;
      useLogf = 1;
    }

    if(!strcmp(argv[argi], "-stf")) {
      if((++argi) < argc) {
        processed = 1;
        argiFileName = argi;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-inf")) {
      if((++argi) < argc) {
        processed = 1;
        argiInputFile = argi;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-d")) {
      if((++argi) < argc) {
        processed = 1;
        duration = atol(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-i")) {
      if((++argi) < argc) {
        processed = 1;
        int dummy_port;
        strcpy(local_ip, argv[argi]);
        get_host_and_port(local_ip, local_ip, &dummy_port);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }
    
    if(!strcmp(argv[argi], "-m")) {
      if((++argi) < argc) {
        processed = 1;
        stop_after  = atol(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-f")) {
      if((++argi) < argc) {
        processed = 1;
        report_freq  = atol(argv[argi]) * 1000;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-fd")) {
      if((++argi) < argc) {
        processed = 1;
        report_freq_dumpLog = atol(argv[argi]) * 1000;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-l")) {
      if((++argi) < argc) {
        processed = 1;
        open_calls_allowed = atol(argv[argi]);
        open_calls_user_setting = 1;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-bg")) {
      processed = 1;
      backgroundMode = true;
    }

    if(!strcmp(argv[argi], "-v")) {
#ifdef _USE_OPENSSL
#ifdef PCAPPLAY
      printf("\n Sipp v1.1-TLS-PCAP, version %ld, built %s, %s.\n\n", SIPP_VERSION, __DATE__, __TIME__); 
#else
      printf("\n Sipp v1.1-TLS, version %ld, built %s, %s.\n\n", SIPP_VERSION, __DATE__, __TIME__); 
#endif
#else
#ifdef PCAPPLAY
      printf("\n Sipp v1.1-PCAP, version %ld, built %s, %s.\n\n", SIPP_VERSION, __DATE__, __TIME__); 
#else
      printf("\n Sipp v1.1, version %ld, built %s, %s.\n\n", SIPP_VERSION, __DATE__, __TIME__); 
#endif
#endif
      printf
        (" This program is free software; you can redistribute it and/or\n"
         " modify it under the terms of the GNU General Public License as\n"
         " published by the Free Software Foundation; either version 2 of\n"
         " the License, or (at your option) any later version.\n"
         "\n"
         " This program is distributed in the hope that it will be useful,\n"
         " but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
         " MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
         " GNU General Public License for more details.\n"
         "\n"
         " You should have received a copy of the GNU General Public\n"
         " License along with this program; if not, write to the\n"
         " Free Software Foundation, Inc.,\n"
         " 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA\n"
         "\n"
         " Author: see source files.\n\n");
      
      exit(EXIT_OTHER);
    }
    
    if(!strcmp(argv[argi], "-r")) {
      if((++argi) < argc) {
        processed = 1;
        rate = atof(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-rp")) {
      if((++argi) < argc) {
        processed = 1;
        rate_period_s = atof(argv[argi]) / 1000 ;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    
    if(!strcmp(argv[argi], "-s")) {
      if((++argi) < argc) {
        processed = 1;
        service = argv[argi];
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }
    
    if(!strcmp(argv[argi], "-timer_resol")) {
      if((++argi) < argc) {
        processed = 1;
        timer_resolution = atoi(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-recv_timeout")) {
      if((++argi) < argc) {
        processed = 1;
        defl_recv_timeout = atol(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-timeout")) {
      if((++argi) < argc) {
        processed = 1;
        global_timeout = atol(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-max_recv_loops")) {
      if((++argi) < argc) {
        processed = 1;
        if (atoi(argv[argi]) > 0) {
          max_recv_loops = atoi(argv[argi]);
        }
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }


    if(!strcmp(argv[argi], "-up_nb")) {
      if((++argi) < argc) {
        processed = 1;
        if (atoi(argv[argi]) > 0) {
          update_nb = atoi(argv[argi]);
        }
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

#ifdef _USE_OPENSSL
    if(!strcmp(argv[argi], "-ap")) {
      if((++argi) < argc) {
        auth_password = argv[argi];
	    processed = 1;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-tls_cert")) {
       if((++argi) < argc) {
         processed = 1;
         tls_cert_name = argv[argi];
        } else {
          ERROR_P1("Missing argument for param '%s'.\n"
                   "Use 'sipp -h' for details",  argv[argi-1]);
       }
     }

    if(!strcmp(argv[argi], "-tls_key")) {
      if((++argi) < argc) {
         processed = 1;
         tls_key_name = argv[argi];
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-tls_crl")) {
      if((++argi) < argc) {
         processed = 1;
         tls_crl_name = argv[argi];
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

#endif

    if(!strcmp(argv[argi], "-sf")) {
      if((++argi) < argc) {
        processed = 1;
        load_scenario(argv[argi], 0);
        scenario_file = new char [strlen(argv[argi])+1] ;
        sprintf(scenario_file,"%s", argv[argi]);
        CStat::instance()->setFileName(argv[argi], (char*)".csv");
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    // Remote sending address different from the received messages
    if(!strcmp(argv[argi], "-rsa")) {
      if((++argi) < argc) {
	char *remote_s_address ;
        int   remote_s_p;
        int   temp_remote_s_p;

        processed = 1;
        temp_remote_s_p = 0;
	remote_s_address = argv[argi] ;
        get_host_and_port(remote_s_address, remote_s_address, &temp_remote_s_p);
        if (temp_remote_s_p != 0) {
          remote_s_p = temp_remote_s_p;
        }
        struct addrinfo   hints;
        struct addrinfo * local_addr;

        printf("Resolving remote sending address %s...\n", remote_s_address);
        
        memset((char*)&hints, 0, sizeof(hints));
        hints.ai_flags  = AI_PASSIVE;
        hints.ai_family = PF_UNSPEC;

        /* FIXME: add DNS SRV support using liburli? */
        if (getaddrinfo(remote_s_address,
                        NULL,
                        &hints,
                        &local_addr) != 0) {
	    ERROR_P1("Unknown remote host '%s'.\n"
		     "Use 'sipp -h' for details", remote_s_address);
	  }

        memcpy(&remote_sending_sockaddr,
               local_addr->ai_addr,
               SOCK_ADDR_SIZE(
                 _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));

        if (remote_sending_sockaddr.ss_family == AF_INET) {
          (_RCAST(struct sockaddr_in *, &remote_sending_sockaddr))->sin_port =
            htons((short)remote_s_p);
        } else {
          (_RCAST(struct sockaddr_in6 *, &remote_sending_sockaddr))->sin6_port =
            htons((short)remote_s_p);
	}
        use_remote_sending_addr = 1 ;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    
    if(!strcmp(argv[argi], "-sn")) {
      if((++argi) < argc) {
        processed = 1;
        if(!strcmp(argv[argi], "uac")) {
          CStat::instance()->setFileName((char*)"uac", (char*)".csv");
          load_scenario(0, 0);
        } else if(!strcmp(argv[argi], "uas")) {
          CStat::instance()->setFileName((char*)"uas", (char*)".csv");
          load_scenario(0, 1);
        } else if(!strcmp(argv[argi], "regexp")) {
          CStat::instance()->setFileName((char*)"regexp", (char*)".csv");
          load_scenario(0, 2);
        } else if(!strcmp(argv[argi], "3pcc-C-A")) {
          CStat::instance()->setFileName((char*)"3pcc-C-A", (char*)".csv");
          load_scenario(0, 3);
        } else if(!strcmp(argv[argi], "3pcc-C-B")) {
          CStat::instance()->setFileName((char*)"3pcc-C-B", (char*)".csv");
          load_scenario(0, 4);
        } else if(!strcmp(argv[argi], "3pcc-A")) {
          CStat::instance()->setFileName((char*)"3pcc-A", (char*)".csv");
          load_scenario(0, 5);
        } else if(!strcmp(argv[argi], "3pcc-B")) {
          CStat::instance()->setFileName((char*)"3pcc-B", (char*)".csv");
          load_scenario(0, 6);
        } else if(!strcmp(argv[argi], "branchc")) {
          CStat::instance()->setFileName((char*)"branchc", (char*)".csv");
          load_scenario(0, 7);
        } else if(!strcmp(argv[argi], "branchs")) {
          CStat::instance()->setFileName((char*)"branchs", (char*)".csv");
          load_scenario(0, 8);
#ifdef PCAPPLAY
        } else if(!strcmp(argv[argi], "uac_pcap")) {
          CStat::instance()->setFileName((char*)"uac_pcap", (char*)".csv");
          load_scenario(0, 9);
#endif
        } else {
          ERROR_P1("Invalid default scenario name '%s'.\n", argv[argi]);
        }
        scenario_file = new char [strlen(argv[argi])+1] ;
        sprintf(scenario_file,"%s", argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-sd")) {
      if((++argi) < argc) {
        processed = 1;
        if(!strcmp(argv[argi], "uac")) {
          fprintf(stdout, "%s", default_scenario[0]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "uas")) {
          fprintf(stdout, "%s", default_scenario[1]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "regexp")) {
          fprintf(stdout, "%s", default_scenario[2]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "3pcc-C-A")) {
          fprintf(stdout, "%s", default_scenario[3]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "3pcc-C-B")) {
          fprintf(stdout, "%s", default_scenario[4]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "3pcc-A")) {
          fprintf(stdout, "%s", default_scenario[5]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "3pcc-B")) {
          fprintf(stdout, "%s", default_scenario[6]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "branchc")) {
          fprintf(stdout, "%s", default_scenario[7]);
          exit(EXIT_OTHER);
        } else if(!strcmp(argv[argi], "branchs")) {
          fprintf(stdout, "%s", default_scenario[8]);
          exit(EXIT_OTHER);
#ifdef PCAPPLAY
        } else if(!strcmp(argv[argi], "uac_pcap")) {
          fprintf(stdout, "%s", default_scenario[9]);
          exit(EXIT_OTHER);
#endif
        } else {
          ERROR_P1("Invalid default scenario name '%s'.\n", argv[argi]);
        }
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-max_reconnect")) {
      if((++argi) < argc) {
        processed = 1;
        max_reconnections = atof(argv[argi]);
        reset_number = max_reconnections;
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-aa")) {
      processed = 1;
      auto_answer = true;
    }

#ifdef __3PCC__
    if(!strcmp(argv[argi], "-3pcc")) {
      if((++argi) < argc) {
        processed = 1;
        twinSippMode = true;
        strcpy(twinSippHost, argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }
#endif

    if(!strcmp(argv[argi], "-ip_field")) {
      if((++argi) < argc) {
        processed = 1;
        peripfield = atoi(argv[argi]);
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-bind_local")) {
      processed = 1;
      bind_local = 1;
    }

    if(!strcmp(argv[argi], "-tdmmap")) {
      if((++argi) < argc) {
        processed = 1;
        int i1, i2, i3, i4, i5, i6, i7;

        if (sscanf(argv[argi], "{%d-%d}{%d}{%d-%d}{%d-%d}", &i1, &i2, &i3, &i4, &i5, &i6, &i7) == 7) {
          use_tdmmap = true;
          tdm_map_a = i2 - i1;
          tdm_map_x = i1;
          tdm_map_h = i3;
          tdm_map_b = i5 - i4;
          tdm_map_y = i4;
          tdm_map_c = i7 - i6;
          tdm_map_z = i6;
        } else {
          ERROR("Parameter -tdmmap must be of form {%%d-%%d}{%%d}{%%d-%%d}{%%d-%%d}");
        }
      } else {
        ERROR_P1("Missing argument for param '%s'.\n"
                 "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    if(!strcmp(argv[argi], "-users")) {
      if((++argi) < argc) {
	char *endptr;
	processed = 1;
	users = open_calls_allowed = strtol(argv[argi], &endptr, 0);
	open_calls_user_setting = 1;
	if (*endptr) {
	  ERROR_P2("Invalid integer '%d' for param '%s'.\n"
	      "Use 'sipp -h' for details",  argv[argi], argv[argi-1]);
	}
      } else {
	ERROR_P1("Missing argument for param '%s'.\n"
	    "Use 'sipp -h' for details",  argv[argi-1]);
      }
    }

    /* --------------------------------------------- */
    /* !!! This must be the last parameter processed */
    if(processed == 0 && *argv[argi] == '-') {
      if((++argi) < argc) {
        if (generic_count+1 >= sizeof(generic)/sizeof(generic[0])) {
          ERROR_P1("Too many generic parameters %d",generic_count+1);
        }
        processed = 1;
        generic[generic_count++] = &argv[argi-1];
        generic[generic_count] = NULL;
      } else {
        ERROR_P1("Missing argument for param '%s'."
                 "Use 'sipp -h' for details\n",  argv[argi-1]);
      }
    }
    /* --------------------------------------------- */

    if(!processed) {
      if((argv[argi])[0] != '-') {
        strcpy(remote_host, argv[argi]);
      } else {
        help();
        ERROR_P1("Invalid argument: '%s'.\n"
                 "Use 'sipp -h' for details", argv[argi]);
      }
    }
  }
  
  if (peripsocket) {
    if (!argiInputFile) {
      ERROR("You must use the -inf option when using -t ui.\n"
               "Use 'sipp -h' for details");
    }
  }

  /* trace file setting */
  if (scenario_file == NULL) {
    scenario_file = new char [ 5 ] ;
    sprintf(scenario_file, "%s", "sipp");
  } else {
    scenario_file = remove_pattern (scenario_file, (char*)".xml");
  }

  if( backgroundMode == false ) {
    if (print_all_responses) {
      char L_file_name [MAX_PATH];
      sprintf (L_file_name, "%s_%d_errors.log", scenario_file, getpid());
      screen_init(L_file_name, print_last_stats);
    } else {
      screen_init(NULL, print_last_stats);
    }
  }

#ifdef _USE_OPENSSL
    if ((transport == T_TLS) && (FI_init_ssl_context() != SSL_INIT_NORMAL))
    {
      ERROR("FI_init_ssl_context() failed");
    }
#endif

  if (useMessagef == 1) {
    char L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_messages.log", scenario_file, getpid());
    messagef = fopen(L_file_name, "w");
    if(!messagef) {
      ERROR_P1("Unable to create '%s'", L_file_name);
    }
  }
  
  if (useScreenf == 1) {
    char L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_screen.log", scenario_file, getpid());
    screenf = fopen(L_file_name, "w");
    if(!screenf) {
      ERROR_P1("Unable to create '%s'", L_file_name);
    }
  }

  if (useTimeoutf == 1) {
    char L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_timeout.log", scenario_file, getpid());
    timeoutf = fopen(L_file_name, "w");
    if(!timeoutf) {
      ERROR_P1("Unable to create '%s'", L_file_name);
    }
  }
  
  if (useLogf == 1) {
    char L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_logs.log", scenario_file, getpid());
    logfile = fopen(L_file_name, "w");
    if(!logfile) {
      ERROR_P1("Unable to create '%s'", L_file_name);
    }
  }

  if (dumpInRtt == 1) {
     CStat::instance()->initRtt((char*)scenario_file, (char*)".csv",
                                report_freq_dumpRtt);
  }

  if ((maxSocketPresent) && (max_multi_socket > FD_SETSIZE) ) {
     L_maxSocketPresent = 1;
  }

  /* Initialization:  boost open file limit to the max (AgM)*/
  {
    struct rlimit rlimit;
    
    if (getrlimit (RLIMIT_NOFILE, &rlimit) < 0) {
      ERROR_NO("getrlimit error");
    }

    if (rlimit.rlim_max >
#ifndef __CYGWIN
       ((L_maxSocketPresent) ?  max_multi_socket : FD_SETSIZE)
#else
       FD_SETSIZE
#endif
       ) {
      fprintf (stderr, "Warning: open file limit > FD_SETSIZE; "
               "limiting max. # of open files to FD_SETSIZE = %d\n",
               FD_SETSIZE);

      rlimit.rlim_max =
#ifndef __CYGWIN
          (L_maxSocketPresent) ?  max_multi_socket+min_socket : FD_SETSIZE ;
#else

	  FD_SETSIZE;
#endif
    }
    
    rlimit.rlim_cur = rlimit.rlim_max;
    if (setrlimit (RLIMIT_NOFILE, &rlimit) < 0) {
      ERROR_P1("Unable to increase the open file limit to FD_SETSIZE = %d",
               FD_SETSIZE);
    }
  }
  
  /* Load default scenario in case nothing was loaded */
  if(!scenario_len) {
    load_scenario(0, 0);
    CStat::instance()->setFileName((char*)"uac", (char*)".csv");
    sprintf(scenario_file,"uac");
  }
  
  if(argiFileName) {
    CStat::instance()->setFileName(argv[argiFileName]);
  }

  if(argiInputFile) {
    call::readInputFileContents(argv[argiInputFile]);
  }
  
  /* In which mode the tool is launched ? */
  computeSippMode();

  /* checking if we need to launch the tool in background mode */ 
  if(backgroundMode == true)
    {
      pid_t l_pid;
      switch(l_pid = fork())
        {
        case -1:
          // error when forking !
          ERROR_NO("Forking error");
          exit(EXIT_FATAL_ERROR);
        case 0:
          // child process - poursuing the execution
          break;
        default:
          // parent process - killing the parent - the child get the parent pid
          printf("Background mode - PID=[%d]\n", l_pid);
          exit(EXIT_OTHER);
        }
    }
	 
  /* Setting the rate and its dependant params (open_calls_allowed) */
  set_rate(rate);
	 
  if (toolMode == MODE_SERVER) {
    reset_number = 0;
  }
   
  open_connections();
   
  /* Defaults for media sockets */
  if (media_port <= 0) {
    media_port = 6000;
  }
  if (media_ip[0] == '\0') {
      strcpy(media_ip, local_ip);
    }
  if (media_ip_escaped[0] == '\0') {
    strcpy(media_ip_escaped, local_ip);
  }
  if (local_ip_is_ipv6) {
    media_ip_is_ipv6 = true;
  } else {
    media_ip_is_ipv6 = false;
  }

  /* Always create and Bind RTP socket */
  /* to avoid ICMP                     */
  if (1) {
    /* retrieve RTP local addr */
    struct addrinfo   hints;
    struct addrinfo * local_addr;

    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;

    media_ip_is_ipv6 = false;

    /* Resolving local IP */
    if (getaddrinfo(media_ip,
                    NULL,
                    &hints,
                    &local_addr) != 0) {
      ERROR_P1("Unknown RTP address '%s'.\n"
               "Use 'sipp -h' for details", media_ip);
    }

    memcpy(&media_sockaddr,
           local_addr->ai_addr,
           SOCK_ADDR_SIZE(
             _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

    if (media_sockaddr.ss_family == AF_INET) {
     (_RCAST(struct sockaddr_in *,&media_sockaddr))->sin_port =
       htons((short)media_port);
     strcpy(media_ip_escaped, media_ip);
    } else {
      (_RCAST(struct sockaddr_in6 *,&media_sockaddr))->sin6_port =
        htons((short)media_port);
      media_ip_is_ipv6 = true;
      strcpy(media_ip_escaped, media_ip);
    }

    if((media_socket = socket(media_ip_is_ipv6 ? AF_INET6 : AF_INET,
                              SOCK_DGRAM, 0)) == -1) {
      char msg[512];
      sprintf(msg, "Unable to get the audio RTP socket (IP=%s, port=%d)", media_ip, media_port);
      ERROR_NO(msg);
    }
    /* create a second socket for video */
    if((media_socket_video = socket(media_ip_is_ipv6 ? AF_INET6 : AF_INET,
                                    SOCK_DGRAM, 0)) == -1) {
      char msg[512];
      sprintf(msg, "Unable to get the video RTP socket (IP=%s, port=%d)", media_ip, media_port+2);
      ERROR_NO(msg);
    }

    if(bind(media_socket, 
            (sockaddr *)(void *)&media_sockaddr,
            SOCK_ADDR_SIZE(&media_sockaddr))) {
      char msg[512];
      sprintf(msg, "Unable to bind audio RTP socket (IP=%s, port=%d)", media_ip, media_port);
      ERROR_NO(msg);
    }
    
    /*---------------------------------------------------------
       Bind the second socket to media_port+2 
       (+1 is reserved for RTCP) 
    ----------------------------------------------------------*/

    if (media_sockaddr.ss_family == AF_INET) {
     (_RCAST(struct sockaddr_in *,&media_sockaddr))->sin_port =
       htons((short)media_port+2);
     strcpy(media_ip_escaped, media_ip);
    } else {
      (_RCAST(struct sockaddr_in6 *,&media_sockaddr))->sin6_port =
        htons((short)media_port+2);
      media_ip_is_ipv6 = true;
      strcpy(media_ip_escaped, media_ip);
    }

    if(bind(media_socket_video, 
            (sockaddr *)(void *)&media_sockaddr,
            SOCK_ADDR_SIZE(&media_sockaddr))) {
      char msg[512];
      sprintf(msg, "Unable to bind video RTP socket (IP=%s, port=%d)", media_ip, media_port+2);
      ERROR_NO(msg);
    }
    /* Second socket bound */
  }

  /* Creating the remote control socket thread */
  if (pthread_create
      (&pthread_id,
       NULL,
       (void *(*)(void *)) ctrl_thread,
       (void*)NULL) 
      == -1) {
    ERROR_NO("Unable to create remote control socket thread");
  }

  if( backgroundMode == false ) {
    /* Creating the keyb thread */
    if (pthread_create
        (&pthread_id,
         NULL,
         (void *(*)(void *)) keyb_thread,
         (void*)NULL) 
        == -1) {
      ERROR_NO("Unable to create recv thread");
    }
  }

  if ((media_socket > 0) && (rtp_echo_enabled)) {
    if (pthread_create
        (&pthread2_id,
         NULL,
         (void *(*)(void *)) rtp_echo_thread,
         (void*)&media_socket) 
        == -1) {
      ERROR_NO("Unable to create RTP echo thread");
    }
  }


  /* Creating second RTP echo thread for video */
  if ((media_socket_video > 0) && (rtp_echo_enabled)) {
    if (pthread_create
        (&pthread3_id,
         NULL,
         (void *(*)(void *)) rtp_echo_thread,
         (void*)&media_socket_video) 
        == -1) {
      ERROR_NO("Unable to create second RTP echo thread");
      }
    } 

  traffic_thread(is_ipv6);

  if (scenario_file != NULL) {
    delete [] scenario_file ;
    scenario_file = NULL ;
  }

}

int reset_connections() {

int status=0;

  start_calls = 1;
  reset_number--;

  if (reset_number > 0) {
    status = close_calls();
    if (status==0) {
      status = close_connections();
      if (status==0) {
        sleep(1);
        status = open_connections();
        start_calls = 0;
        pollset_reset();
        WARNING("Re-connection for connections")  
      }
    }
  } else {
    ERROR_NO("Max number of reconnections reached");
  }
  
  return status;
}

int close_calls() {
  int status=0;
  call_map * calls = get_calls();
  call_map::iterator call_it;
  call * call_ptr = NULL;

  while (calls->begin() != calls->end()) {
    call_ptr = (calls->begin() != calls->end()) ? (calls->begin())->second : NULL ;
    if(call_ptr) {
      calls->erase(calls->begin());
      if (call_ptr->running) {
	if (!remove_running_call(call_ptr)) {
	  ERROR("Internal error: A running call is not in the list.\n");
	}
      } else {
	remove_paused_call(call_ptr);
      }
      delete call_ptr; 
      open_calls--;
    }
  }
  return status;
}

int close_connections() {
  int status=0;
  
  if (toolMode != MODE_SERVER)   {
    shutdown(main_socket, SHUT_RDWR);
    close(main_socket); 
    main_socket = 0; 
  }
  return status;
}

int open_connections() {
  int status=0;
  int err; 
  local_port = 0;
  struct addrinfo * local_addr;
  
  if(!strlen(remote_host)) {
    if(toolMode != MODE_SERVER) {
      ERROR("Missing remote host parameter. This scenario requires it");
    }
  } else {
    int temp_remote_port;
    get_host_and_port(remote_host, remote_host, &temp_remote_port);
    if (temp_remote_port != 0) {
      remote_port = temp_remote_port;
    }
 
    /* Resolving the remote IP */
    {
      struct addrinfo   hints;

      fprintf(stderr,"Resolving remote host '%s'... ", remote_host);

      memset((char*)&hints, 0, sizeof(hints));
      hints.ai_flags  = AI_PASSIVE;
      hints.ai_family = PF_UNSPEC;

      /* FIXME: add DNS SRV support using liburli? */
      if (getaddrinfo(remote_host,
                      NULL,
                      &hints,
                      &local_addr) != 0) {
        ERROR_P1("Unknown remote host '%s'.\n"
                 "Use 'sipp -h' for details", remote_host);
      }

      memset(&remote_sockaddr, 0, sizeof( remote_sockaddr ));
      memcpy(&remote_sockaddr,
             local_addr->ai_addr,
             SOCK_ADDR_SIZE(
               _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

      strcpy(remote_ip, get_inet_address(&remote_sockaddr));
      if (remote_sockaddr.ss_family == AF_INET) {
        (_RCAST(struct sockaddr_in *, &remote_sockaddr))->sin_port =
          htons((short)remote_port);
        strcpy(remote_ip_escaped, remote_ip); 
      } else {
        (_RCAST(struct sockaddr_in6 *, &remote_sockaddr))->sin6_port =
          htons((short)remote_port);
        sprintf(remote_ip_escaped, "[%s]", remote_ip); 
      }
      fprintf(stderr,"Done.\n");
    }
   }

  if(gethostname(hostname,64) != 0) {
    ERROR_NO("Can't get local hostname in 'gethostname(hostname,64)'");
  }
  
  {
    char            * local_host = NULL;
    struct addrinfo   hints;

    if (!strlen(local_ip)) {
      local_host = (char *)hostname;
    } else {
      local_host = (char *)local_ip;
    }

    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;

    /* Resolving local IP */
      if (getaddrinfo(local_host,
                      NULL,
                      &hints, 	 
                      &local_addr) != 0) { 	 
         ERROR_P2("Can't get local IP address in getaddrinfo, local_host='%s', local_ip='%s'", 	 
           local_host, 	 
           local_ip); 	 
       } 	 
       // store local addr info for rsa option
       getaddrinfo(local_host, NULL, &hints, &local_addr_storage);
       
       memset(&local_sockaddr,0,sizeof(struct sockaddr_storage)); 	 
       local_sockaddr.ss_family = local_addr->ai_addr->sa_family; 	 
       
       if (!strlen(local_ip)) { 	 
         strcpy(local_ip, 	 
                get_inet_address( 	 
                _RCAST(struct sockaddr_storage *, local_addr->ai_addr))); 	 
       } else { 	 
         if (!(local_sockaddr.ss_family == AF_INET6)) { 	 
           memcpy(&local_sockaddr, 	 
                  local_addr->ai_addr, 	 
                  SOCK_ADDR_SIZE( 	 
                   _RCAST(struct sockaddr_storage *,local_addr->ai_addr))); 	 
         } 	 
       } 	 
       if (local_sockaddr.ss_family == AF_INET6) { 	 
         local_ip_is_ipv6 = true; 	 
         sprintf(local_ip_escaped, "[%s]", local_ip); 	 
       } else { 	 
         strcpy(local_ip_escaped, local_ip); 	 
       }
   } 
  
  /* Creating and binding the local socket */
  if((main_socket = socket(local_ip_is_ipv6 ? AF_INET6 : AF_INET,
                           (transport == T_UDP) ? SOCK_DGRAM : SOCK_STREAM,
                           0)) == -1) {
    ERROR_NO("Unable to get the local socket");
  }
  

  /* Trying to bind local port */
  char peripaddr[256];
  if(!user_port) {
    unsigned short l_port;
    for(l_port = DEFAULT_PORT;
        l_port < (DEFAULT_PORT + 60);
        l_port++) {
        
        // Bind socket to local_ip
          if (bind_local || peripsocket) {
            struct addrinfo * local_addr;
            struct addrinfo   hints;
            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = PF_UNSPEC;
  
            if (peripsocket) {
            // On some machines it fails to bind to the self computed local
            // IP address.
            // For the socket per IP mode, bind the main socket to the
            // first IP address specified in the inject file.
              if (toolMode == MODE_SERVER) {
                call::getIpFieldFromInputFile(peripfield, 0, peripaddr);
              } else {
                call::getIpFieldFromInputFile(0, 0, peripaddr);
              }
              if (getaddrinfo(peripaddr,
                              NULL,
                              &hints,
                              &local_addr) != 0) {
                ERROR_P1("Unknown host '%s'.\n"
                       "Use 'sipp -h' for details", peripaddr);
              }
            } else {
              if (getaddrinfo(local_ip,
                              NULL,
                              &hints,
                              &local_addr) != 0) {
                ERROR_P1("Unknown host '%s'.\n"
                       "Use 'sipp -h' for details", peripaddr);
              }
            }
            memcpy(&local_sockaddr,
                   local_addr->ai_addr,
                   SOCK_ADDR_SIZE(
                     _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
          }
          if (local_ip_is_ipv6) {
            (_RCAST(struct sockaddr_in6 *, &local_sockaddr))->sin6_port
                = htons((short)l_port);
          } else {
            (_RCAST(struct sockaddr_in *, &local_sockaddr))->sin_port
                = htons((short)l_port);
          }
         
          if(!bind(main_socket,
                 (sockaddr *)(void *)&local_sockaddr,
                 SOCK_ADDR_SIZE(&local_sockaddr))) {
                 local_port = l_port;
            break;
          }
    }
  }
  
  if(!local_port) {
    /* Not already binded, use user_port of 0 to leave
     * the system choose a port. */

    if (bind_local || peripsocket) {
      struct addrinfo * local_addr;
      struct addrinfo   hints;
      memset((char*)&hints, 0, sizeof(hints));
      hints.ai_flags  = AI_PASSIVE;
      hints.ai_family = PF_UNSPEC;
       
      if (peripsocket) {
        // On some machines it fails to bind to the self computed local
        // IP address.
        // For the socket per IP mode, bind the main socket to the
        // first IP address specified in the inject file.
        if (toolMode == MODE_SERVER) {
          call::getIpFieldFromInputFile(peripfield, 0, peripaddr);
        } else {
          call::getIpFieldFromInputFile(0, 0, peripaddr);
        }
        if (getaddrinfo(peripaddr,
                         NULL,
                         &hints,
                         &local_addr) != 0) {
           ERROR_P1("Unknown host '%s'.\n"
                    "Use 'sipp -h' for details", peripaddr);
        }
      } else {
        if (getaddrinfo(local_ip,
                        NULL,
                        &hints,
                        &local_addr) != 0) {
           ERROR_P1("Unknown host '%s'.\n"
                   "Use 'sipp -h' for details", peripaddr);
        }
      }
      memcpy(&local_sockaddr,
             local_addr->ai_addr,
             SOCK_ADDR_SIZE(
               _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
    }

    if (local_ip_is_ipv6) {
      (_RCAST(struct sockaddr_in6 *, &local_sockaddr))->sin6_port
          = htons((short)user_port);        
    } else {
      (_RCAST(struct sockaddr_in *, &local_sockaddr))->sin_port
          = htons((short)user_port); 
    }
    if(bind(main_socket, 
            (sockaddr *)(void *)&local_sockaddr,
            SOCK_ADDR_SIZE(&local_sockaddr))) {
      ERROR_NO("Unable to bind main socket");
    }
  }
  
  if (peripsocket) {
    // Add the main socket to the socket per subscriber map
    map_perip_fd[peripaddr] = main_socket;
  }
    
  /* Recover system port */
  {
    sipp_socklen_t len = SOCK_ADDR_SIZE(&local_sockaddr);
    getsockname(main_socket,
                (sockaddr *)(void *)&local_sockaddr,
                &len);
    if (local_ip_is_ipv6) {
      local_port =
        ntohs((short)
          (_RCAST(struct sockaddr_in6 *,&local_sockaddr))->sin6_port);
    } else {
      local_port =
        ntohs((short)
          (_RCAST(struct sockaddr_in *,&local_sockaddr))->sin_port);
    }

  }
  sipp_customize_socket(main_socket);

  // Create additional server sockets when running in socket per
  // IP address mode.
  if (peripsocket && toolMode == MODE_SERVER) {
    struct sockaddr_storage server_sockaddr;
    struct addrinfo * local_addr;
    struct addrinfo   hints;
    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;

    char peripaddr[256];
    int sock;
    for (int i = 0; i < fileContents.size(); i++) {
      call::getIpFieldFromInputFile(0, i, peripaddr);
      map<string, int>::iterator j;
      j = map_perip_fd.find(peripaddr);
      
      if (j == map_perip_fd.end()) {
        if((sock = socket(is_ipv6 ? AF_INET6 : AF_INET,
                           (transport == T_UDP) ? SOCK_DGRAM : SOCK_STREAM,
                           0)) == -1) {
          ERROR_NO("Unable to get server socket");
        }
        

        if (getaddrinfo(peripaddr,
                        NULL,
                        &hints,
                        &local_addr) != 0) {
            ERROR_P1("Unknown remote host '%s'.\n"
                     "Use 'sipp -h' for details", peripaddr);
          }

        memcpy(&server_sockaddr,
              local_addr->ai_addr,
              SOCK_ADDR_SIZE(
                 _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));

        if (is_ipv6) {
          (_RCAST(struct sockaddr_in6 *, &server_sockaddr))->sin6_port
              = htons((short)local_port);
        } else {
          (_RCAST(struct sockaddr_in *, &server_sockaddr))->sin_port
              = htons((short)local_port);
        }
        
        if(bind(sock, 
                (sockaddr *)(void *)&server_sockaddr,
                SOCK_ADDR_SIZE(&server_sockaddr))) {
          ERROR_NO("Unable to bind server socket");
        }

        map_perip_fd[peripaddr] = sock;
        sipp_customize_socket(sock);
        pollset_add(0, sock);
      }
    }
  }

#ifdef _USE_OPENSSL
  if((!multisocket) && (transport == T_TCP || transport == T_TLS) &&
#else
  if((!multisocket) && (transport == T_TCP) &&
#endif
   (toolMode != MODE_SERVER)) {

    if((tcp_multiplex = socket(local_ip_is_ipv6 ? AF_INET6 : AF_INET,
                               SOCK_STREAM,
                               0))== -1) {
      ERROR_NO("Unable to get a TCP socket");
    }

    /*
    struct sockaddr_storage *L_dest = &remote_sockaddr;

    if (use_remote_sending_addr) {
        L_dest = &remote_sending_sockaddr ;
    }
               (struct sockaddr *)(void *)L_dest,
    */

    /* OJA FIXME: is it correct? */
    if (use_remote_sending_addr) {
        remote_sockaddr = remote_sending_sockaddr ;
    }
    
    if(connect(tcp_multiplex,
               (struct sockaddr *)(void *)&remote_sockaddr,
               SOCK_ADDR_SIZE(&remote_sockaddr))) {
      
      if(errno == EINVAL){
        /* This occurs sometime on HPUX but is not a true INVAL */
        ERROR_NO("Unable to connect a TCP socket, remote peer error.\n"
              "Use 'sipp -h' for details");
      } else {
        ERROR_NO("Unable to connect a TCP socket.\n"
                 "Use 'sipp -h' for details");
      }
    }

#ifdef _USE_OPENSSL
    if ( transport == T_TLS ) {
      if ( (bio = BIO_new_socket(tcp_multiplex,BIO_NOCLOSE)) == NULL) {
        ERROR("Unable to create BIO object:Problem with BIO_new_socket()\n");
      }
    
      if (!(ssl_tcp_multiplex = SSL_new(sip_trp_ssl_ctx_client))){
        ERROR("Unable to create SSL object : Problem with SSL_new() \n");
      }
    
      SSL_set_bio(ssl_tcp_multiplex,bio,bio);
      if ( (err = SSL_connect(ssl_tcp_multiplex)) < 0 ) {
        ERROR("Error in SSL connection \n");
      }

      ssl_list[tcp_multiplex] = ssl_tcp_multiplex;
    }
#endif

    sipp_customize_socket(tcp_multiplex);
  }


#ifdef _USE_OPENSSL
  if(transport == T_TCP || transport == T_TLS) {
#else
  if(transport == T_TCP) {
#endif
    if(listen(main_socket, 100)) {
      ERROR_NO("Unable to listen main socket");
    }
  }

#ifdef __3PCC__
  /* Trying to connect to Twin Sipp in 3PCC mode */
  if(twinSippMode) {
    if(toolMode == MODE_3PCC_CONTROLLER_A || toolMode == MODE_3PCC_A_PASSIVE) {
      if(strstr(twinSippHost, ":")) {
              twinSippPort = atol(strstr(twinSippHost, ":")+1);
              *(strstr(twinSippHost, ":")) = 0;
            }

          /* Resolving the twin IP */
            printf("Resolving twin address : %s...\n", twinSippHost);
      struct addrinfo   hints;
      struct addrinfo * local_addr;
      memset((char*)&hints, 0, sizeof(hints));
      hints.ai_flags  = AI_PASSIVE;
      hints.ai_family = PF_UNSPEC;
      is_ipv6 = false;
      /* Resolving twin IP */
      if (getaddrinfo(twinSippHost,
                      NULL,
                      &hints,
                      &local_addr) != 0) {
              ERROR_P1("Unknown twin host '%s'.\n"
                       "Use 'sipp -h' for details", twinSippHost);
            }

      memcpy(&twinSipp_sockaddr,
             local_addr->ai_addr,
             SOCK_ADDR_SIZE(
               _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

      if (twinSipp_sockaddr.ss_family == AF_INET) {
       (_RCAST(struct sockaddr_in *,&twinSipp_sockaddr))->sin_port =
         htons((short)twinSippPort);
      } else {
        (_RCAST(struct sockaddr_in6 *,&twinSipp_sockaddr))->sin6_port =
          htons((short)twinSippPort);
        is_ipv6 = true;
      }
      strcpy(twinSippIp, get_inet_address(&twinSipp_sockaddr));
      if((twinSippSocket = socket(is_ipv6 ? AF_INET6 : AF_INET,
          SOCK_STREAM, 0))== -1) {
              ERROR_NO("Unable to get a TCP socket in 3PCC controller A mode");
            }
    
          if(connect(twinSippSocket,
                     (struct sockaddr *)(void *)&twinSipp_sockaddr,
                 SOCK_ADDR_SIZE(&twinSipp_sockaddr))) {
        if(errno == EINVAL) {
                  /* This occurs sometime on HPUX but is not a true INVAL */
                  ERROR_NO("Unable to connect a TCP socket in 3PCC controller "
                        "A mode, remote peer error.\n"
                        "Use 'sipp -h' for details");
        } else {
                  ERROR_NO("Unable to connect a TCP socket in 3PCC controller "
                           "A mode.\n"
                           "Use 'sipp -h' for details");
                }
            }

          sipp_customize_socket(twinSippSocket);
    } else if(toolMode == MODE_3PCC_CONTROLLER_B) {
      if(strstr(twinSippHost, ":")) {
              twinSippPort = atol(strstr(twinSippHost, ":")+1);
              *(strstr(twinSippHost, ":")) = 0;
            }

          /* Resolving the listener IP */
            printf("Resolving listener address : %s...\n", twinSippHost);
            struct addrinfo   hints;
            struct addrinfo * local_addr;
            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = PF_UNSPEC;
            is_ipv6 = false;
            
            /* Resolving twin IP */
            if (getaddrinfo(twinSippHost,
                           NULL,
                           &hints,
                           &local_addr) != 0) {
               ERROR_P1("Unknown twin host '%s'.\n"
                        "Use 'sipp -h' for details", twinSippHost);
             }
             memcpy(&twinSipp_sockaddr,
                    local_addr->ai_addr,
                    SOCK_ADDR_SIZE(
                      _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));
      
             if (twinSipp_sockaddr.ss_family == AF_INET) {
              (_RCAST(struct sockaddr_in *,&twinSipp_sockaddr))->sin_port =
                htons((short)twinSippPort);
             } else {
               (_RCAST(struct sockaddr_in6 *,&twinSipp_sockaddr))->sin6_port =
                 htons((short)twinSippPort);
               is_ipv6 = true;
             }
             strcpy(twinSippIp, get_inet_address(&twinSipp_sockaddr));
      
             if((localTwinSippSocket = socket(is_ipv6 ? AF_INET6 : AF_INET,
                 SOCK_STREAM, 0))== -1) {
                ERROR_NO("Unable to get a TCP socket in 3PCC controller B mode");
              }

           memset(&localTwin_sockaddr, 0, sizeof(struct sockaddr_storage));
           if (!is_ipv6) {
            localTwin_sockaddr.ss_family = AF_INET;
            (_RCAST(struct sockaddr_in *,&localTwin_sockaddr))->sin_port =
              htons((short)twinSippPort);
           } else {
             localTwin_sockaddr.ss_family = AF_INET6;
             (_RCAST(struct sockaddr_in6 *,&localTwin_sockaddr))->sin6_port =
               htons((short)twinSippPort);
           }
           
           // add socket option to allow the use of it without the TCP timeout 
           // This allows to re-start the B controller without timeout after its exit
           int reuse = 1;
           setsockopt(localTwinSippSocket,SOL_SOCKET,SO_REUSEADDR,(int *)&reuse,sizeof(reuse));

           if(bind(localTwinSippSocket, 
                  (sockaddr *)(void *)&localTwin_sockaddr,
                   SOCK_ADDR_SIZE(&localTwin_sockaddr))) {
              ERROR_NO("Unable to bind twin sipp socket in "
                    "3PCC_CONTROLLER_B mode");
            }

          if(listen(localTwinSippSocket, 100))
            ERROR_NO("Unable to listen twin sipp socket in "
                     "3PCC_CONTROLLER_B mode");
          sipp_customize_socket(localTwinSippSocket);
    } else {
        ERROR("TwinSipp Mode enabled but toolMode is different "
              "from 3PCC_CONTROLLER_B and 3PCC_CONTROLLER_A\n");
    }
  } /* end if(twinSippMode) */
#endif

  return status;

}

