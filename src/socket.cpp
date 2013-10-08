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
 *           Francois Draperi (for dynamic_id)
 *           From Hewlett Packard Company.
 *           F. Tarek Rogers
 *           Peter Higginson
 *           Vincent Luba
 *           Shriram Natarajan
 *           Guillaume Teissier from FTR&D
 *           Clement Chen
 *           Wolfgang Beck
 *           Charles P Wright from IBM Research
 *           Martin Van Leeuwen
 *           Andy Aicken
 *	     Michael Hirschbichler
 */

#include <stdlib.h>
#include <unistd.h>
#include "sipp.hpp"
#include "socket.hpp"
#include "logger.hpp"

extern bool do_hide;
extern bool show_index;

struct sipp_socket *ctrl_socket = NULL;
struct sipp_socket *stdin_socket = NULL;

static int stdin_mode;

/******************** Recv Poll Processing *********************/

int pollnfds;
#ifdef HAVE_EPOLL
int epollfd;
struct epoll_event   epollfiles[SIPP_MAXFDS];
struct epoll_event*  epollevents;
#else
struct pollfd        pollfiles[SIPP_MAXFDS];
#endif
struct sipp_socket  *sockets[SIPP_MAXFDS];

int pending_messages = 0;

map<string, struct sipp_socket *>     map_perip_fd;

void process_set(char *what)
{
    char *rest = strchr(what, ' ');
    if (rest) {
        *rest++ = '\0';
        trim(rest);
    } else {
        WARNING("The set command requires two arguments (attribute and value)");
        return;
    }

    if (!strcmp(what, "rate")) {
        char *end;
        double drest = strtod(rest, &end);

        if (users >= 0) {
            WARNING("Rates can not be set in a user-based benchmark.");
        } else if (*end) {
            WARNING("Invalid rate value: \"%s\"", rest);
        } else {
            opentask::set_rate(drest);
        }
    } else if (!strcmp(what, "rate-scale")) {
        char *end;
        double drest = strtod(rest, &end);
        if (*end) {
            WARNING("Invalid rate-scale value: \"%s\"", rest);
        } else {
            rate_scale = drest;
        }
    } else if (!strcmp(what, "users")) {
        char *end;
        int urest = strtol(rest, &end, 0);

        if (users < 0) {
            WARNING("Users can not be changed at run time for a rate-based benchmark.");
        } else if (*end) {
            WARNING("Invalid users value: \"%s\"", rest);
        } else if (urest < 0) {
            WARNING("Invalid users value: \"%s\"", rest);
        } else {
            opentask::set_users(urest);
        }
    } else if (!strcmp(what, "limit")) {
        char *end;
        unsigned long lrest = strtoul(rest, &end, 0);
        if (users >= 0) {
            WARNING("Can not set call limit for a user-based benchmark.");
        } else if (*end) {
            WARNING("Invalid limit value: \"%s\"", rest);
        } else {
            open_calls_allowed = lrest;
            open_calls_user_setting = 1;
        }
    } else if (!strcmp(what, "display")) {
        if (!strcmp(rest, "main")) {
            display_scenario = main_scenario;
        } else if (!strcmp(rest, "ooc")) {
            display_scenario = ooc_scenario;
        } else {
            WARNING("Unknown display scenario: %s", rest);
        }
    } else if (!strcmp(what, "hide")) {
        if (!strcmp(rest, "true")) {
            do_hide = true;
        } else if (!strcmp(rest, "false")) {
            do_hide = false;
        } else {
            WARNING("Invalid bool: %s", rest);
        }
    } else if (!strcmp(what, "index")) {
        if (!strcmp(rest, "true")) {
            show_index = true;
        } else if (!strcmp(rest, "false")) {
            show_index = false;
        } else {
            WARNING("Invalid bool: %s", rest);
        }
    } else {
        WARNING("Unknown set attribute: %s", what);
    }
}

void process_trace(char *what)
{
    bool on = false;
    char *rest = strchr(what, ' ');
    if (rest) {
        *rest++ = '\0';
        trim(rest);
    } else {
        WARNING("The trace command requires two arguments (log and [on|off])");
        return;
    }

    if (!strcmp(rest, "on")) {
        on = true;
    } else if (!strcmp(rest, "off")) {
        on = false;
    } else if (!strcmp(rest, "true")) {
        on = true;
    } else if (!strcmp(rest, "false")) {
        on = false;
    } else {
        WARNING("The trace command's second argument must be on or off.");
        return;
    }

    if (!strcmp(what, "error")) {
        if (on == !!print_all_responses) {
            return;
        }
        if (on) {
            print_all_responses = 1;
        } else {
            print_all_responses = 0;
            log_off(&error_lfi);
        }
    } else if (!strcmp(what, "logs")) {
        if (on == !!log_lfi.fptr) {
            return;
        }
        if (on) {
            useLogf = 1;
            rotate_logfile();
        } else {
            useLogf = 0;
            log_off(&log_lfi);
        }
    } else if (!strcmp(what, "messages")) {
        if (on == !!message_lfi.fptr) {
            return;
        }
        if (on) {
            useMessagef = 1;
            rotate_logfile();
        } else {
            useMessagef = 0;
            log_off(&message_lfi);
        }
    } else if (!strcmp(what, "shortmessages")) {
        if (on == !!shortmessage_lfi.fptr) {
            return;
        }

        if (on) {
            useShortMessagef = 1;
            rotate_shortmessagef();
        } else {
            useShortMessagef = 0;
            log_off(&shortmessage_lfi);
        }
    } else {
        WARNING("Unknown log file: %s", what);
    }
}

void process_dump(char *what)
{
    if (!strcmp(what, "tasks")) {
        dump_tasks();
    } else if (!strcmp(what, "variables")) {
        display_scenario->allocVars->dump();
    } else {
        WARNING("Unknown dump type: %s", what);
    }
}

void process_reset(char *what)
{
    if (!strcmp(what, "stats")) {
        main_scenario->stats->computeStat(CStat::E_RESET_C_COUNTERS);
    } else {
        WARNING("Unknown reset type: %s", what);
    }
}

bool process_command(char *command)
{
    trim(command);

    char *rest = strchr(command, ' ');
    if (rest) {
        *rest++ = '\0';
        trim(rest);
    }

    if (!strcmp(command, "set")) {
        process_set(rest);
    } else if (!strcmp(command, "trace")) {
        process_trace(rest);
    } else if (!strcmp(command, "dump")) {
        process_dump(rest);
    } else if (!strcmp(command, "reset")) {
        process_reset(rest);
    } else {
        WARNING("Unrecognized command: \"%s\"", command);
    }

    return false;
}

int command_mode = 0;
char *command_buffer = NULL;

extern char * get_call_id(char *msg);
extern bool sipMsgCheck (const char *P_msg, struct sipp_socket *socket);

#ifdef _USE_OPENSSL
SSL_CTX  *sip_trp_ssl_ctx = NULL; /* For SSL cserver context */
SSL_CTX  *sip_trp_ssl_ctx_client = NULL; /* For SSL cserver context */
SSL_CTX  *twinSipp_sip_trp_ssl_ctx_client = NULL; /* For SSL cserver context */

#define CALL_BACK_USER_DATA "ksgr"

int passwd_call_back_routine(char  *buf , int size , int flag, void *passwd)
{

    /* We need the flag parameter as this is a callback with defined arguments, but
     * we don't use it. Cast to void to avoid warnings. */
    (void)flag;

    strncpy(buf, (char *)(passwd), size);
    buf[size - 1] = '\0';
    return(strlen(buf));
}

/****** SSL error handling                         *************/
const char *sip_tls_error_string(SSL *ssl, int size)
{
    int err;
    err=SSL_get_error(ssl, size);
    switch(err) {
    case SSL_ERROR_NONE:
        return "No error";
    case SSL_ERROR_WANT_WRITE:
        return "SSL_read returned SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_READ:
        return "SSL_read returned SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_X509_LOOKUP:
        return "SSL_read returned SSL_ERROR_WANT_X509_LOOKUP";
        break;
    case SSL_ERROR_SYSCALL:
        if(size<0) { /* not EOF */
            return strerror(errno);
        } else { /* EOF */
            return "SSL socket closed on SSL_read";
        }
    }
    return "Unknown SSL Error.";
}

#endif

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

bool process_key(int c)
{
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
        currentRepartitionToDisplay = (c - '6') + 2;
        print_statistics(0);
        break;

    case '+':
        if (users >= 0) {
            opentask::set_users((int)(users + 1 * rate_scale));
        } else {
            opentask::set_rate(rate + 1 * rate_scale);
        }
        print_statistics(0);
        break;

    case '-':
        if (users >= 0) {
            opentask::set_users((int)(users - 1 * rate_scale));
        } else {
            opentask::set_rate(rate - 1 * rate_scale);
        }
        print_statistics(0);
        break;

    case '*':
        if (users >= 0) {
            opentask::set_users((int)(users + 10 * rate_scale));
        } else {
            opentask::set_rate(rate + 10 * rate_scale);
        }
        print_statistics(0);
        break;

    case '/':
        if (users >= 0) {
            opentask::set_users((int)(users - 10 * rate_scale));
        } else {
            opentask::set_rate(rate - 10 * rate_scale);
        }
        print_statistics(0);
        break;

    case 'p':
        if(paused) {
            opentask::set_paused(false);
        } else {
            opentask::set_paused(true);
        }
        print_statistics(0);
        break;

    case 's':
        if (screenf) {
            print_screens();
        }
        break;

    case 'q':
        quitting+=10;
        print_statistics(0);
        break;

    case 'Q':
        /* We are going to break, so we never have a chance to press q twice. */
        quitting+=20;
        print_statistics(0);
        break;
    }
    return false;
}

int handle_ctrl_socket()
{
    unsigned char bufrcv [SIPP_MAX_MSG_SIZE];

    int ret = recv(ctrl_socket->ss_fd,bufrcv,sizeof(bufrcv) - 1,0);
    if (ret <= 0) {
        return ret;
    }

    if (bufrcv[0] == 'c') {
        /* No 'c', but we need one for '\0'. */
        char *command = (char *)malloc(ret);
        if (!command) {
            ERROR("Out of memory allocated command buffer.");
        }
        memcpy(command, bufrcv + 1, ret - 1);
        command[ret - 1] = '\0';
        process_command(command);
        free(command);
    } else {
        process_key(bufrcv[0]);
    }
    return 0;
}

void setup_ctrl_socket()
{
    int port, firstport;
    int try_counter = 60;
    struct sockaddr_storage ctl_sa;

    int sock = socket(AF_INET,SOCK_DGRAM,0);
    if (sock == -1) {
        ERROR_NO("Unable to create remote control socket!");
    }

    if (control_port) {
        port = control_port;
        /* If the user specified the control port, then we must assume they know
         * what they want, and should not cycle. */
        try_counter = 1;
    } else {
        /* Allow 60 control sockets on the same system */
        /* (several SIPp instances)                   */
        port = DEFAULT_CTRL_SOCKET_PORT;
    }
    firstport = port;

    memset(&ctl_sa,0,sizeof(struct sockaddr_storage));
    if (control_ip[0]) {
        struct addrinfo hints;
        struct addrinfo *addrinfo;

        memset((char*)&hints, 0, sizeof(hints));
        hints.ai_flags  = AI_PASSIVE;
        hints.ai_family = PF_UNSPEC;

        if (getaddrinfo(control_ip, NULL, &hints, &addrinfo) != 0) {
            ERROR("Unknown control address '%s'.\n"
                  "Use 'sipp -h' for details", control_ip);
        }

        memcpy(&ctl_sa, addrinfo->ai_addr, SOCK_ADDR_SIZE(_RCAST(struct sockaddr_storage *,addrinfo->ai_addr)));
        freeaddrinfo(addrinfo);
    } else {
        ((struct sockaddr_in *)&ctl_sa)->sin_family = AF_INET;
        ((struct sockaddr_in *)&ctl_sa)->sin_addr.s_addr = INADDR_ANY;
    }

    while (try_counter) {
        ((struct sockaddr_in *)&ctl_sa)->sin_port = htons(port);
        if (!bind(sock,(struct sockaddr *)&ctl_sa,sizeof(struct sockaddr_in))) {
            /* Bind successful */
            break;
        }
        try_counter--;
        port++;
    }

    if (try_counter == 0) {
        if (control_port) {
            ERROR_NO("Unable to bind remote control socket to UDP port %d",
                     control_port);
        } else {
            WARNING("Unable to bind remote control socket (tried UDP ports %d-%d): %s",
                    firstport, port - 1, strerror(errno));
        }
        return;
    }

    ctrl_socket = sipp_allocate_socket(0, T_UDP, sock, 0);
    if (!ctrl_socket) {
        ERROR_NO("Could not setup control socket!\n");
    }
}

static void reset_stdin() {
  fcntl(fileno(stdin), F_SETFL, stdin_mode);
}

void setup_stdin_socket()
{
    stdin_mode = fcntl(fileno(stdin), F_GETFL);
    fcntl(fileno(stdin), F_SETFL, stdin_mode | O_NONBLOCK);
    atexit(reset_stdin);
    stdin_socket = sipp_allocate_socket(0, T_UDP, fileno(stdin), 0);
    if (!stdin_socket) {
        ERROR_NO("Could not setup keyboard (stdin) socket!\n");
    }
}

#define SIPP_ENDL "\r\n"
void handle_stdin_socket()
{
    int c;
    int chars = 0;

    if (feof(stdin)) {
        sipp_close_socket(stdin_socket);
        stdin_socket = NULL;
        return;
    }

    while (((c = screen_readkey()) != -1)) {
        chars++;
        if (command_mode) {
            if (c == '\n') {
                bool quit = process_command(command_buffer);
                if (quit) {
                    return;
                }
                command_buffer[0] = '\0';
                command_mode = 0;
                printf(SIPP_ENDL);
            }
#ifndef __SUNOS
            else if (c == KEY_BACKSPACE || c == KEY_DC)
#else
            else if (c == 14)
#endif
            {
                int command_len = strlen(command_buffer);
                if (command_len > 0) {
                    command_buffer[command_len--] = '\0';
                }
            } else {
                int command_len = strlen(command_buffer);
                char *realloc_ptr = (char *)realloc(command_buffer, command_len + 2);
                if (realloc_ptr) {
                    command_buffer = realloc_ptr;
                } else {
                    free(command_buffer);
                    ERROR("Out of memory");
                    return;
                }
                command_buffer[command_len++] = c;
                command_buffer[command_len] = '\0';
                putchar(c);
                fflush(stdout);
            }
        } else if (c == 'c') {
            command_mode = 1;
            char *realloc_ptr = (char *)realloc(command_buffer, 1);
            if (realloc_ptr) {
                command_buffer = realloc_ptr;
            } else {
                free(command_buffer);
                ERROR("Out of memory");
                return;
            }
            command_buffer[0] = '\0';
            printf("Command: ");
            fflush(stdout);
        } else {
            process_key(c);
        }
    }
    if (chars == 0) {
        /* We did not read any characters, even though we should have. */
        sipp_close_socket(stdin_socket);
        stdin_socket = NULL;
    }
}

/****************************** Network Interface *******************/

/* Our message detection states: */
#define CFM_NORMAL 0 /* No CR Found, searchign for \r\n\r\n. */
#define CFM_CONTROL 1 /* Searching for 27 */
#define CFM_CR 2 /* CR Found, Searching for \n\r\n */
#define CFM_CRLF 3 /* CRLF Found, Searching for \r\n */
#define CFM_CRLFCR 4 /* CRLFCR Found, Searching for \n */
#define CFM_CRLFCRLF 5 /* We've found the end of the headers! */

void merge_socketbufs(struct socketbuf *socketbuf)
{
    struct socketbuf *next = socketbuf->next;
    int newsize;
    char *newbuf;

    if (!next) {
        return;
    }

    if (next->offset) {
        ERROR("Internal error: can not merge a socketbuf with a non-zero offset.");
    }

    if (socketbuf->offset) {
        memmove(socketbuf->buf, socketbuf->buf + socketbuf->offset, socketbuf->len - socketbuf->offset);
        socketbuf->len -= socketbuf->offset;
        socketbuf->offset = 0;
    }

    newsize = socketbuf->len + next->len;

    newbuf = (char *)realloc(socketbuf->buf, newsize);
    if (!newbuf) {
        ERROR("Could not allocate memory to merge socket buffers!");
    }
    memcpy(newbuf + socketbuf->len, next->buf, next->len);
    socketbuf->buf = newbuf;
    socketbuf->len = newsize;
    socketbuf->next = next->next;
    free_socketbuf(next);
}

/* Check for a message in the socket and return the length of the first
 * message.  If this is UDP, the only check is if we have buffers.  If this is
 * TCP or TLS we need to parse out the content-length. */
static int check_for_message(struct sipp_socket *socket)
{
    struct socketbuf *socketbuf = socket->ss_in;
    int state = socket->ss_control ? CFM_CONTROL : CFM_NORMAL;
    const char *l;

    if (!socketbuf)
        return 0;

    if (socket->ss_transport == T_UDP || socket->ss_transport == T_SCTP) {
        return socketbuf->len;
    }

    int len = 0;

    while (socketbuf->offset + len < socketbuf->len) {
        char c = socketbuf->buf[socketbuf->offset + len];

        switch(state) {
        case CFM_CONTROL:
            /* For CMD Message the escape char is the end of message */
            if (c == 27) {
                return len + 1; /* The plus one includes the control character. */
            }
            break;
        case CFM_NORMAL:
            if (c == '\r') {
                state = CFM_CR;
            }
            break;
        case CFM_CR:
            if (c == '\n') {
                state = CFM_CRLF;
            } else {
                state = CFM_NORMAL;
            }
            break;
        case CFM_CRLF:
            if (c == '\r') {
                state = CFM_CRLFCR;
            } else {
                state = CFM_NORMAL;
            }
            break;
        case CFM_CRLFCR:
            if (c == '\n') {
                state = CFM_CRLFCRLF;
            } else {
                state = CFM_NORMAL;
            }
            break;
        }

        /* Head off failing because the buffer does not contain the whole header. */
        if (socketbuf->offset + len == socketbuf->len - 1) {
            merge_socketbufs(socketbuf);
        }

        if (state == CFM_CRLFCRLF) {
            break;
        }

        len++;
    }

    /* We did not find the end-of-header marker. */
    if (state != CFM_CRLFCRLF) {
        return 0;
    }

    /* Find the content-length header. */
    if ((l = strncasestr(socketbuf->buf + socketbuf->offset, "\r\nContent-Length:", len))) {
        l += strlen("\r\nContent-Length:");
    } else if ((l = strncasestr(socketbuf->buf + socketbuf->offset, "\r\nl:", len))) {
        l += strlen("\r\nl:");
    } else {
        /* There is no header, so the content-length is zero. */
        return len + 1;
    }

    /* Skip spaces. */
    while(isspace(*l)) {
        if (*l == '\r' || *l == '\n') {
            /* We ran into an end-of-line, so there is no content-length. */
            return len + 1;
        }
        l++;
    }

    /* Do the integer conversion, we only allow '\r' or spaces after the integer. */
    char *endptr;
    int content_length = strtol(l, &endptr, 10);
    if (*endptr != '\r' && !isspace(*endptr)) {
        content_length = 0;
    }

    /* Now that we know how large this message is, we make sure we have the whole thing. */
    do {
        /* It is in this buffer. */
        if (socketbuf->offset + len + content_length < socketbuf->len) {
            return len + content_length + 1;
        }
        if (socketbuf->next == NULL) {
            /* There is no buffer to merge, so we fail. */
            return 0;
        }
        /* We merge ourself with the next buffer. */
        merge_socketbufs(socketbuf);
    } while (1);
}

#ifdef USE_SCTP
static int handleSCTPNotify(struct sipp_socket* socket,char* buffer)
{
    union sctp_notification *notifMsg;

    notifMsg = (union sctp_notification *)buffer;

    TRACE_MSG("SCTP Notification: %d\n",
              ntohs(notifMsg->sn_header.sn_type));
    if (notifMsg->sn_header.sn_type == SCTP_ASSOC_CHANGE) {
        TRACE_MSG("SCTP_ASSOC_CHANGE\n");
        if (notifMsg->sn_assoc_change.sac_state == SCTP_COMM_UP) {
            TRACE_MSG("SCTP_COMM_UP\n");
            socket->sctpstate = SCTP_UP;
            sipp_sctp_peer_params(socket);

            /* Send SCTP message right after association is up */
            socket->ss_congested = false;
            flush_socket(socket);
            return -2;
        } else {
            TRACE_MSG("else: %d\n",notifMsg->sn_assoc_change.sac_state);
            return 0;
        }
    } else if (notifMsg->sn_header.sn_type == SCTP_SHUTDOWN_EVENT) {
        TRACE_MSG("SCTP_SHUTDOWN_EVENT\n");
        return 0;
    }
    return -2;
}

void set_multihome_addr(struct sipp_socket* socket,int port)
{
    if (strlen(multihome_ip)>0) {
        struct addrinfo * multi_addr;
        struct addrinfo   hints;
        memset((char*)&hints, 0, sizeof(hints));
        hints.ai_flags  = AI_PASSIVE;
        hints.ai_family = PF_UNSPEC;

        if (getaddrinfo(multihome_ip, NULL, &hints, &multi_addr) != 0) {
            ERROR("Can't get multihome IP address in getaddrinfo, multihome_ip='%s'",multihome_ip);
        }

        struct sockaddr_storage secondaryaddress;
        memset(&secondaryaddress, 0, sizeof(secondaryaddress));

        memcpy(&secondaryaddress, multi_addr->ai_addr, SOCK_ADDR_SIZE(_RCAST(struct sockaddr_storage *,multi_addr->ai_addr)));
        freeaddrinfo(multi_addr);

        if (port>0) {
            if (secondaryaddress.ss_family==AF_INET) ((struct sockaddr_in*)&secondaryaddress)->sin_port=htons(port);
            else if (secondaryaddress.ss_family==AF_INET6) ((struct sockaddr_in6*)&secondaryaddress)->sin6_port=htons(port);
        }

        int ret = sctp_bindx(socket->ss_fd, (struct sockaddr *) &secondaryaddress,
                             1, SCTP_BINDX_ADD_ADDR);
        if (ret < 0) {
            WARNING("Can't bind to multihome address, errno='%d'", errno);
        }
    }
}
#endif

/* Pull up to tcp_readsize data bytes out of the socket into our local buffer. */
int empty_socket(struct sipp_socket *socket)
{

    int readsize=0;
    if (socket->ss_transport == T_UDP || socket->ss_transport == T_SCTP) {
        readsize = SIPP_MAX_MSG_SIZE;
    } else {
        readsize = tcp_readsize;
    }

    struct socketbuf *socketbuf;
    char *buffer;
    int ret = -1;
    /* Where should we start sending packets to, ideally we should begin to parse
     * the Via, Contact, and Route headers.  But for now SIPp always sends to the
     * host specified on the command line; or for UAS mode to the address that
     * sent the last message. */
    sipp_socklen_t addrlen = sizeof(struct sockaddr_storage);

    buffer = (char *)malloc(readsize);
    if (!buffer) {
        ERROR("Could not allocate memory for read!");
    }
    socketbuf = alloc_socketbuf(buffer, readsize, NO_COPY, NULL);

    switch(socket->ss_transport) {
    case T_TCP:
    case T_UDP:
        ret = recvfrom(socket->ss_fd, buffer, readsize, 0, (struct sockaddr *)&socketbuf->addr,  &addrlen);
        break;
    case T_TLS:
#ifdef _USE_OPENSSL
        ret = SSL_read(socket->ss_ssl, buffer, readsize);
        /* XXX: Check for clean shutdown. */
#else
        ERROR("TLS support is not enabled!");
#endif
        break;
    case T_SCTP:
#ifdef USE_SCTP
        struct sctp_sndrcvinfo recvinfo;
        memset(&recvinfo, 0, sizeof(recvinfo));
        int msg_flags = 0;

        ret = sctp_recvmsg(socket->ss_fd, (void*)buffer, readsize,
                           (struct sockaddr *) &socketbuf->addr, &addrlen, &recvinfo, &msg_flags);

        if (MSG_NOTIFICATION & msg_flags) {
            errno = 0;
            handleSCTPNotify(socket, buffer);
            ret = -2;
        }
#else
        ERROR("SCTP support is not enabled!");
#endif
        break;
    }
    if (ret <= 0) {
        free_socketbuf(socketbuf);
        return ret;
    }

    socketbuf->len = ret;

    buffer_read(socket, socketbuf);

    /* Do we have a complete SIP message? */
    if (!socket->ss_msglen) {
        if (int msg_len = check_for_message(socket)) {
            socket->ss_msglen = msg_len;
            pending_messages++;
        }
    }

    return ret;
}

void sipp_socket_invalidate(struct sipp_socket *socket)
{
    int pollidx;

    if (socket->ss_invalid) {
        return;
    }

#ifdef _USE_OPENSSL
    if (SSL *ssl = socket->ss_ssl) {
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl);
    }
#endif

    /* In some error conditions, the socket FD has already been closed - if it hasn't, do so now. */
    if (socket->ss_fd != -1) {
#ifdef HAVE_EPOLL
        int rc = epoll_ctl(epollfd, EPOLL_CTL_DEL, socket->ss_fd, NULL);
        if (rc == -1) {
            WARNING_NO("Failed to delete FD from epoll");
        }
#endif
    shutdown(socket->ss_fd, SHUT_RDWR);

#ifdef USE_SCTP
    if (socket->ss_transport==T_SCTP && !gracefulclose) {
        struct linger ling= {1,0};
        if (setsockopt (socket->ss_fd, SOL_SOCKET, SO_LINGER, &ling, sizeof (ling)) < 0) {
            WARNING("Unable to set SO_LINGER option for SCTP close");
        }
    }
#endif

    sipp_abort_connection(socket->ss_fd);
    socket->ss_fd = -1;
  }

    if((pollidx = socket->ss_pollidx) >= pollnfds) {
        ERROR("Pollset error: index %d is greater than number of fds %d!", pollidx, pollnfds);
    }

    socket->ss_invalid = true;
    socket->ss_pollidx = -1;

    /* Adds call sockets in the array */
    assert(pollnfds > 0);

    pollnfds--;
#ifdef HAVE_EPOLL
    if (pollidx < pollnfds) {
        epollfiles[pollidx] = epollfiles[pollnfds];
        epollfiles[pollidx].data.u32 = pollidx;
        if (sockets[pollnfds]->ss_fd != -1) {
            int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, sockets[pollnfds]->ss_fd, &epollfiles[pollidx]);
            if (rc == -1) {
                WARNING_NO("Failed to update FD within epoll");
            }
        }
    }
#else 
    pollfiles[pollidx] = pollfiles[pollnfds];
#endif
    sockets[pollidx] = sockets[pollnfds];
    sockets[pollidx]->ss_pollidx = pollidx;
    sockets[pollnfds] = NULL;

    if (socket->ss_msglen) {
        pending_messages--;
    }

#ifdef USE_SCTP
    if (socket->ss_transport == T_SCTP) {
        socket->sctpstate=SCTP_DOWN;
    }
#endif
}

void sipp_abort_connection(int fd) {
    /* Disable linger - we'll send a RST when we close. */
    struct linger flush;
    flush.l_onoff = 1;
    flush.l_linger = 0;
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &flush, sizeof(flush));

    /* Mark the socket as non-blocking.  It's not clear whether this is required but can't hurt. */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Actually close the socket. */
    close(fd);
}

void sipp_close_socket (struct sipp_socket *socket)
{
    int count = --socket->ss_count;

    if (count > 0) {
        return;
    }

    sipp_socket_invalidate(socket);
    sockets_pending_reset.erase(socket);
    free(socket);
}

ssize_t read_message(struct sipp_socket *socket, char *buf, size_t len, struct sockaddr_storage *src)
{
    size_t avail;

    if (!socket->ss_msglen)
        return 0;
    if (socket->ss_msglen > len)
        ERROR("There is a message waiting in sockfd(%d) that is bigger (%d bytes) than the read size.",
              socket->ss_fd, socket->ss_msglen);

    len = socket->ss_msglen;

    avail = socket->ss_in->len - socket->ss_in->offset;
    if (avail > len) {
        avail = len;
    }

    memcpy(buf, socket->ss_in->buf + socket->ss_in->offset, avail);
    memcpy(src, &socket->ss_in->addr, SOCK_ADDR_SIZE(&socket->ss_in->addr));

    /* Update our buffer and return value. */
    buf[avail] = '\0';
    /* For CMD Message the escape char is the end of message */
    if((socket->ss_control) && buf[avail-1] == 27 ) buf[avail-1] = '\0';

    socket->ss_in->offset += avail;

    /* Have we emptied the buffer? */
    if (socket->ss_in->offset == socket->ss_in->len) {
        struct socketbuf *next = socket->ss_in->next;
        free_socketbuf(socket->ss_in);
        socket->ss_in = next;
    }

    if (int msg_len = check_for_message(socket)) {
        socket->ss_msglen = msg_len;
    } else {
        socket->ss_msglen = 0;
        pending_messages--;
    }

    return avail;
}

void process_message(struct sipp_socket *socket, char *msg, ssize_t msg_size, struct sockaddr_storage *src)
{
    // TRACE_MSG(" msg_size %d and pollset_index is %d \n", msg_size, pollset_index));
    if(msg_size <= 0) {
        return;
    }
    if (sipMsgCheck(msg, socket) == false) {
        if ((msg_size != 4) ||
            (memcmp(msg, "\r\n\r\n", 4) != 0)) {
            WARNING("non SIP message discarded: \"%.*s\"", msg_size, msg);
        }
        return;
    }

    char *call_id = get_call_id(msg);
    if (call_id[0] == '\0') {
        WARNING("SIP message without Call-ID discarded");
        return;
    }
    listener *listener_ptr = get_listener(call_id);
    struct timeval currentTime;
    GET_TIME (&currentTime);

    if (useShortMessagef == 1) {
        TRACE_SHORTMSG("%s\tR\t%s\tCSeq:%s\t%s\n",
                       CStat::formatTime(&currentTime),call_id, get_header_content(msg,"CSeq:"), get_first_line(msg));
    }

    if (useMessagef == 1) {
        TRACE_MSG("----------------------------------------------- %s\n"
                  "%s %smessage received [%d] bytes :\n\n%s\n",
                  CStat::formatTime(&currentTime, true),
                  TRANSPORT_TO_STRING(socket->ss_transport),
                  socket->ss_control ? "control " : "",
                  msg_size, msg);
    }

    if(!listener_ptr) {
        if(thirdPartyMode == MODE_3PCC_CONTROLLER_B || thirdPartyMode == MODE_3PCC_A_PASSIVE
                || thirdPartyMode == MODE_MASTER_PASSIVE || thirdPartyMode == MODE_SLAVE) {
            // Adding a new OUTGOING call !
            main_scenario->stats->computeStat(CStat::E_CREATE_OUTGOING_CALL);
            call *new_ptr = new call(call_id, local_ip_is_ipv6, 0, use_remote_sending_addr ? &remote_sending_sockaddr : &remote_sockaddr);
            if (!new_ptr) {
                ERROR("Out of memory allocating a call!");
            }

            outbound_congestion = false;
            if((socket != main_socket) &&
                    (socket != tcp_multiplex) &&
                    (socket != localTwinSippSocket) &&
                    (socket != twinSippSocket) &&
                    (!is_a_local_socket(socket))) {
                new_ptr->associate_socket(socket);
                socket->ss_count++;
            } else {
                /* We need to hook this call up to a real *call* socket. */
                if (!multisocket) {
                    switch(transport) {
                    case T_UDP:
                        new_ptr->associate_socket(main_socket);
                        main_socket->ss_count++;
                        break;
                    case T_TCP:
                    case T_SCTP:
                    case T_TLS:
                        new_ptr->associate_socket(tcp_multiplex);
                        tcp_multiplex->ss_count++;
                        break;
                    }
                }
            }
            listener_ptr = new_ptr;
        } else if(creationMode == MODE_SERVER) {
            if (quitting >= 1) {
                CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                TRACE_MSG("Discarded message for new calls while quitting\n");
                return;
            }

            // Adding a new INCOMING call !
            main_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
            listener_ptr = new call(call_id, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src);
            if (!listener_ptr) {
                ERROR("Out of memory allocating a call!");
            }
        } else { // mode != from SERVER and 3PCC Controller B
            // This is a message that is not relating to any known call
            if (ooc_scenario) {
                if(!get_reply_code(msg)) {
                    char *msg_start = strdup(msg);
                    char *msg_start_end = msg_start;
                    while (!isspace(*msg_start_end) && (*msg_start_end != '\0')) {
                        msg_start_end++;
                    }
                    *msg_start_end = '\0';
                    ooc_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
                    WARNING("Received out-of-call %s message, using the out-of-call scenario", msg_start);
                    free(msg_start);
                    /* This should have the real address that the message came from. */
                    call *call_ptr = new call(ooc_scenario, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src, call_id, 0 /* no user. */, socket->ss_ipv6, true, false);
                    if (!call_ptr) {
                        ERROR("Out of memory allocating a call!");
                    }
                    CStat::globalStat(CStat::E_AUTO_ANSWERED);
                    call_ptr->process_incoming(msg, src);
                } else {
                    /* We received a response not relating to any known call */
                    /* Do nothing, even if in auto answer mode */
                    CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                }
            } else if (auto_answer &&
                       ((strstr(msg, "NOTIFY") == msg)  ||
                        (strstr(msg, "INFO")   == msg)  ||
                        (strstr(msg, "UPDATE") == msg))) {
                // If auto answer mode, try to answer the incoming message
                // with automaticResponseMode
                // call is discarded before exiting the block
                if(!get_reply_code(msg)) {
                    aa_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
                    /* This should have the real address that the message came from. */
                    call *call_ptr = new call(aa_scenario, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src, call_id, 0 /* no user. */, socket->ss_ipv6, true, false);
                    if (!call_ptr) {
                        ERROR("Out of memory allocating a call!");
                    }
                    CStat::globalStat(CStat::E_AUTO_ANSWERED);
                    call_ptr->process_incoming(msg, src);
                } else {
                    fprintf(stderr, "%s", msg);
                    /* We received a response not relating to any known call */
                    /* Do nothing, even if in auto answer mode */
                    CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                }
            } else {
                CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                WARNING("Discarding message which can't be mapped to a known SIPp call:\n%s", msg);
            }
        }
    }

    /* If the call was not created above, we just drop this message. */
    if (!listener_ptr) {
        return;
    }

    if((socket == localTwinSippSocket) || (socket == twinSippSocket) || (is_a_local_socket(socket))) {
        listener_ptr -> process_twinSippCom(msg);
    } else {
        listener_ptr -> process_incoming(msg, src);
    }
}

struct sipp_socket *sipp_allocate_socket(bool use_ipv6, int transport, int fd, int accepting) {
    struct sipp_socket *ret = (struct sipp_socket *)malloc(sizeof(struct sipp_socket));
    if (!ret) {
        ERROR("Could not allocate a sipp_socket structure.");
    }
    memset(ret, 0, sizeof(struct sipp_socket));

    ret->ss_transport = transport;
    ret->ss_control = false;
    ret->ss_ipv6 = use_ipv6;
    ret->ss_fd = fd;
    ret->ss_comp_state = NULL;
    ret->ss_count = 1;
    ret->ss_changed_dest = false;

    /* Initialize all sockets with our destination address. */
    memcpy(&ret->ss_remote_sockaddr, &remote_sockaddr, sizeof(ret->ss_remote_sockaddr));

#ifdef _USE_OPENSSL
    ret->ss_ssl = NULL;

    if ( transport == T_TLS ) {
        if ((ret->ss_bio = BIO_new_socket(fd,BIO_NOCLOSE)) == NULL) {
            ERROR("Unable to create BIO object:Problem with BIO_new_socket()\n");
        }

        if (!(ret->ss_ssl = SSL_new(accepting ? sip_trp_ssl_ctx : sip_trp_ssl_ctx_client))) {
            ERROR("Unable to create SSL object : Problem with SSL_new() \n");
        }

        SSL_set_bio(ret->ss_ssl,ret->ss_bio,ret->ss_bio);
    }
#endif

    ret->ss_in = NULL;
    ret->ss_out = NULL;
    ret->ss_msglen = 0;
    ret->ss_congested = false;
    ret->ss_invalid = false;

    /* Store this socket in the tables. */
    ret->ss_pollidx = pollnfds++;
    sockets[ret->ss_pollidx] = ret;
#ifdef HAVE_EPOLL
    epollfiles[ret->ss_pollidx].data.u32 = ret->ss_pollidx;
    epollfiles[ret->ss_pollidx].events   = EPOLLIN;
    int rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, ret->ss_fd, &epollfiles[ret->ss_pollidx]);
    if (rc == -1) {
        ERROR_NO("Failed to add FD to epoll");
    }
#else
     pollfiles[ret->ss_pollidx].fd      = ret->ss_fd;
     pollfiles[ret->ss_pollidx].events  = POLLIN | POLLERR;
     pollfiles[ret->ss_pollidx].revents = 0;
#endif

    return ret;
}

static struct sipp_socket *sipp_allocate_socket(bool use_ipv6, int transport, int fd) {
    return sipp_allocate_socket(use_ipv6, transport, fd, 0);
}

int socket_fd(bool use_ipv6, int transport)
{
    int socket_type = -1;
    int protocol=0;
    int fd;

    switch(transport) {
    case T_UDP:
        socket_type = SOCK_DGRAM;
        protocol=IPPROTO_UDP;
        break;
    case T_SCTP:
#ifndef USE_SCTP
        ERROR("You do not have SCTP support enabled!\n");
#else
        socket_type = SOCK_STREAM;
        protocol=IPPROTO_SCTP;
#endif
        break;
    case T_TLS:
#ifndef _USE_OPENSSL
        ERROR("You do not have TLS support enabled!\n");
#endif
    case T_TCP:
        socket_type = SOCK_STREAM;
        break;
    }

    if((fd = socket(use_ipv6 ? AF_INET6 : AF_INET, socket_type, protocol))== -1) {
        ERROR("Unable to get a %s socket (3)", TRANSPORT_TO_STRING(transport));
    }

    return fd;
}

struct sipp_socket *new_sipp_socket(bool use_ipv6, int transport) {
    struct sipp_socket *ret;
    int fd = socket_fd(use_ipv6, transport);

#if defined(__SUNOS)
    if (fd < 256) {
        int newfd = fcntl(fd, F_DUPFD, 256);
        if (newfd <= 0) {
            // Typically, (24)(Too many open files) is the error here
            WARNING("Unable to get a different %s socket, errno=%d(%s)",
                    TRANSPORT_TO_STRING(transport), errno, strerror(errno));

            // Keep the original socket fd.
            newfd = fd;
        } else {
            close(fd);
        }
        fd = newfd;
    }
#endif

    ret  = sipp_allocate_socket(use_ipv6, transport, fd);
    if (!ret) {
        close(fd);
        ERROR("Could not allocate new socket structure!");
    }
    return ret;
}

struct sipp_socket *new_sipp_call_socket(bool use_ipv6, int transport, bool *existing) {
    struct sipp_socket *sock = NULL;
    static int next_socket;
    if (pollnfds >= max_multi_socket) {  // we must take the main socket into account
        /* Find an existing socket that matches transport and ipv6 parameters. */
        int first = next_socket;
        do {
            int test_socket = next_socket;
            next_socket = (next_socket + 1) % pollnfds;

            if (sockets[test_socket]->ss_call_socket) {
                /* Here we need to check that the address is the default. */
                if (sockets[test_socket]->ss_ipv6 != use_ipv6) {
                    continue;
                }
                if (sockets[test_socket]->ss_transport != transport) {
                    continue;
                }
                if (sockets[test_socket]->ss_changed_dest) {
                    continue;
                }

                sock = sockets[test_socket];
                sock->ss_count++;
                *existing = true;
                break;
            }
        } while (next_socket != first);
        if (next_socket == first) {
            ERROR("Could not find an existing call socket to re-use!");
        }
    } else {
        sock = new_sipp_socket(use_ipv6, transport);
        sock->ss_call_socket = true;
        *existing = false;
    }
    return sock;
}

struct sipp_socket *sipp_accept_socket(struct sipp_socket *accept_socket) {
    struct sipp_socket *ret;
    struct sockaddr_storage remote_sockaddr;
    int fd;
    sipp_socklen_t addrlen = sizeof(remote_sockaddr);

    if((fd = accept(accept_socket->ss_fd, (struct sockaddr *)&remote_sockaddr, &addrlen))== -1) {
        ERROR("Unable to accept on a %s socket: %s", TRANSPORT_TO_STRING(transport), strerror(errno));
    }

#if defined(__SUNOS)
    if (fd < 256) {
        int newfd = fcntl(fd, F_DUPFD, 256);
        if (newfd <= 0) {
            // Typically, (24)(Too many open files) is the error here
            WARNING("Unable to get a different %s socket, errno=%d(%s)",
                    TRANSPORT_TO_STRING(transport), errno, strerror(errno));

            // Keep the original socket fd.
            newfd = fd;
        } else {
            close(fd);
        }
        fd = newfd;
    }
#endif


    ret  = sipp_allocate_socket(accept_socket->ss_ipv6, accept_socket->ss_transport, fd, 1);
    if (!ret) {
        close(fd);
        ERROR_NO("Could not allocate new socket!");
    }

    memcpy(&ret->ss_remote_sockaddr, &remote_sockaddr, sizeof(ret->ss_remote_sockaddr));
    /* We should connect back to the address which connected to us if we
     * experience a TCP failure. */
    memcpy(&ret->ss_dest, &remote_sockaddr, sizeof(ret->ss_remote_sockaddr));

    if (ret->ss_transport == T_TLS) {
#ifdef _USE_OPENSSL
        int err;
        if ((err = SSL_accept(ret->ss_ssl)) < 0) {
            ERROR("Error in SSL_accept: %s\n", sip_tls_error_string(accept_socket->ss_ssl, err));
        }
#else
        ERROR("You need to compile SIPp with TLS support");
#endif
    }

    return ret;
}

int sipp_bind_socket(struct sipp_socket *socket, struct sockaddr_storage *saddr, int *port)
{
    int ret;
    int len;


#ifdef USE_SCTP
    if (transport==T_SCTP && multisocket==1 && *port==-1) {
        if (socket->ss_ipv6) {
            (_RCAST(struct sockaddr_in6 *, saddr))->sin6_port=0;
        } else {
            (_RCAST(struct sockaddr_in *, saddr))->sin_port=0;
        }
    }
#endif

    if (socket->ss_ipv6) {
        len = sizeof(struct sockaddr_in6);
    } else {
        len = sizeof(struct sockaddr_in);
    }

    if((ret = bind(socket->ss_fd, (sockaddr *)saddr, len))) {
        return ret;
    }

    if (!port) {
        return 0;
    }

    if ((ret = getsockname(socket->ss_fd, (sockaddr *)saddr, (sipp_socklen_t *) &len))) {
        return ret;
    }

    if (socket->ss_ipv6) {
        *port = ntohs((short)((_RCAST(struct sockaddr_in6 *, saddr))->sin6_port));
    } else {
        *port = ntohs((short)((_RCAST(struct sockaddr_in *, saddr))->sin_port));
    }

#ifdef USE_SCTP
    bool isany=false;

    if (socket->ss_ipv6) {
        if (memcmp(&(_RCAST(struct sockaddr_in6 *, saddr)->sin6_addr),&in6addr_any,sizeof(in6_addr))==0) isany=true;
    } else {
        isany= (_RCAST(struct sockaddr_in *, saddr)->sin_addr.s_addr==INADDR_ANY);
    }

    if (transport==T_SCTP && !isany) set_multihome_addr(socket,*port);
#endif

    return 0;
}

int sipp_do_connect_socket(struct sipp_socket *socket)
{
    int ret;

    assert(socket->ss_transport == T_TCP || socket->ss_transport == T_TLS || socket->ss_transport == T_SCTP);

#ifdef USE_SCTP
    if (socket->ss_transport==T_SCTP) {
        int port=-1;
        sipp_bind_socket(socket, &local_sockaddr, &port);
    }
#endif

    int flags = fcntl(socket->ss_fd, F_GETFL, 0);
    fcntl(socket->ss_fd, F_SETFL, flags | O_NONBLOCK);

    errno = 0;
    ret = connect(socket->ss_fd, (struct sockaddr *)&socket->ss_dest, SOCK_ADDR_SIZE(&socket->ss_dest));
    if (ret < 0) {
        if (errno == EINPROGRESS) {
            /* Block this socket until the connect completes - this is very similar to entering congestion, but we don't want to increment congestion statistics. */
            enter_congestion(socket, 0);
            nb_net_cong--;
        } else {
            return ret;
        }
    }

    fcntl(socket->ss_fd, F_SETFL, flags);

    if (socket->ss_transport == T_TLS) {
#ifdef _USE_OPENSSL
        int err;
        if ((err = SSL_connect(socket->ss_ssl)) < 0) {
            ERROR("Error in SSL connection: %s\n", sip_tls_error_string(socket->ss_ssl, err));
        }
#else
        ERROR("You need to compile SIPp with TLS support");
#endif
    }

#ifdef USE_SCTP
    if (socket->ss_transport == T_SCTP) {
        socket->sctpstate = SCTP_CONNECTING;
    }
#endif

    return 0;
}

int sipp_connect_socket(struct sipp_socket *socket, struct sockaddr_storage *dest)
{
    memcpy(&socket->ss_dest, dest, SOCK_ADDR_SIZE(dest));
    return sipp_do_connect_socket(socket);
}

int sipp_reconnect_socket(struct sipp_socket *socket)
{
    if ((!socket->ss_invalid) &&
        (socket->ss_fd != -1)) {
        WARNING("When reconnecting socket, already have file descriptor %d", socket->ss_fd);
        sipp_abort_connection(socket->ss_fd);
        socket->ss_fd = -1;
    }
 
    socket->ss_fd = socket_fd(socket->ss_ipv6, socket->ss_transport);
    if (socket->ss_fd == -1) {
        ERROR_NO("Could not obtain new socket: ");
    }

    if (socket->ss_invalid) {
#ifdef _USE_OPENSSL
        socket->ss_ssl = NULL;

        if ( transport == T_TLS ) {
            if ((socket->ss_bio = BIO_new_socket(socket->ss_fd,BIO_NOCLOSE)) == NULL) {
                ERROR("Unable to create BIO object:Problem with BIO_new_socket()\n");
            }

            if (!(socket->ss_ssl = SSL_new(sip_trp_ssl_ctx_client))) {
                ERROR("Unable to create SSL object : Problem with SSL_new() \n");
            }

            SSL_set_bio(socket->ss_ssl,socket->ss_bio,socket->ss_bio);
        }
#endif

        /* Store this socket in the tables. */
        socket->ss_pollidx = pollnfds++;
        sockets[socket->ss_pollidx] = socket;
#ifdef HAVE_EPOLL
        epollfiles[socket->ss_pollidx].data.u32 = socket->ss_pollidx;
        epollfiles[socket->ss_pollidx].events   = EPOLLIN;
#else
        pollfiles[socket->ss_pollidx].fd      = socket->ss_fd;
        pollfiles[socket->ss_pollidx].events  = POLLIN | POLLERR;
        pollfiles[socket->ss_pollidx].revents = 0;
#endif

        socket->ss_invalid = false;
    }

#ifdef HAVE_EPOLL
    int rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, socket->ss_fd, &epollfiles[socket->ss_pollidx]);
    if (rc == -1) {
        ERROR_NO("Failed to add FD to epoll");
    }
#endif
    return sipp_do_connect_socket(socket);
}


/*************************** I/O functions ***************************/

/* Allocate a socket buffer. */
struct socketbuf *alloc_socketbuf(char *buffer, size_t size, int copy, struct sockaddr_storage *dest)
{
    struct socketbuf *socketbuf;

    socketbuf = (struct socketbuf *)malloc(sizeof(struct socketbuf));
    if (!socketbuf) {
        ERROR("Could not allocate socket buffer!\n");
    }
    memset(socketbuf, 0, sizeof(struct socketbuf));
    if (copy) {
        socketbuf->buf = (char *)malloc(size);
        if (!socketbuf->buf) {
            ERROR("Could not allocate socket buffer data!\n");
        }
        memcpy(socketbuf->buf, buffer, size);
    } else {
        socketbuf->buf = buffer;
    }
    socketbuf->len = size;
    socketbuf->offset = 0;
    if (dest) {
        memcpy(&socketbuf->addr, dest, SOCK_ADDR_SIZE(dest));
    }
    socketbuf->next = NULL;

    return socketbuf;
}

/* Free a poll buffer. */
void free_socketbuf(struct socketbuf *socketbuf)
{
    free(socketbuf->buf);
    free(socketbuf);
}

size_t decompress_if_needed(int sock, char *buff,  size_t len, void **st)
{
    if(compression && len) {
        if (useMessagef == 1) {
            struct timeval currentTime;
            GET_TIME (&currentTime);
            TRACE_MSG("----------------------------------------------- %s\n"
                      "Compressed message received, header :\n"
                      "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
                      "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
                      CStat::formatTime(&currentTime, true),
                      buff[0] , buff[1] , buff[2] , buff[3],
                      buff[4] , buff[5] , buff[6] , buff[7],
                      buff[8] , buff[9] , buff[10], buff[11],
                      buff[12], buff[13], buff[14], buff[15]);
        }

        int rc = comp_uncompress(st,
                                 buff,
                                 (unsigned int *) &len);

        switch(rc) {
        case COMP_OK:
            TRACE_MSG("Compressed message decompressed properly.\n");
            break;

        case COMP_REPLY:
            TRACE_MSG("Compressed message KO, sending a reply (resynch).\n");
            sendto(sock,
                   buff,
                   len,
                   0,
                   (sockaddr *)(void *)&remote_sockaddr,
                   SOCK_ADDR_SIZE(&remote_sockaddr));
            resynch_send++;
            return 0;

        case COMP_DISCARD:
            TRACE_MSG("Compressed message discarded by pluggin.\n");
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

#ifdef USE_SCTP
void sipp_sctp_peer_params(struct sipp_socket *socket)
{
    if (heartbeat > 0 || pathmaxret > 0) {
        struct sctp_paddrparams peerparam;
        memset(&peerparam, 0, sizeof(peerparam));

        sockaddr* addresses;
        int addresscount = sctp_getpaddrs(socket->ss_fd, 0, &addresses);
        if (addresscount < 1) WARNING("sctp_getpaddrs, errno=%d", errno);

        for (int i = 0; i < addresscount; i++) {
            memset(&peerparam.spp_address, 0, sizeof(peerparam.spp_address));
            struct sockaddr_storage* peeraddress = (struct sockaddr_storage*) &addresses[i];
            memcpy(&peerparam.spp_address, peeraddress, SOCK_ADDR_SIZE(peeraddress));

            peerparam.spp_hbinterval = heartbeat;
            peerparam.spp_pathmaxrxt = pathmaxret;
            if (heartbeat > 0) peerparam.spp_flags = SPP_HB_ENABLE;

            if (pmtu > 0) {
                peerparam.spp_pathmtu = pmtu;
                peerparam.spp_flags |= SPP_PMTUD_DISABLE;
            }

            if (setsockopt(socket->ss_fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                           &peerparam, sizeof(peerparam)) == -1) {
                sctp_freepaddrs(addresses);
                WARNING("setsockopt(SCTP_PEER_ADDR_PARAMS) failed, errno=%d", errno);
            }
        }
        sctp_freepaddrs(addresses);
    }
}
#endif

void sipp_customize_socket(struct sipp_socket *socket)
{
    unsigned int buffsize = buff_size;

    /* Allows fast TCP reuse of the socket */
    if (socket->ss_transport == T_TCP || socket->ss_transport == T_TLS ||
            socket->ss_transport == T_SCTP) {
        int sock_opt = 1;

        if (setsockopt(socket->ss_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt,
                       sizeof (sock_opt)) == -1) {
            ERROR_NO("setsockopt(SO_REUSEADDR) failed");
        }

#ifdef USE_SCTP
        if (socket->ss_transport == T_SCTP) {
            struct sctp_event_subscribe event;
            memset(&event, 0, sizeof(event));
            event.sctp_data_io_event = 1;
            event.sctp_association_event = 1;
            event.sctp_shutdown_event = 1;
            if (setsockopt(socket->ss_fd,IPPROTO_SCTP, SCTP_EVENTS, &event,
                           sizeof(event)) == -1) {
                ERROR_NO("setsockopt(SCTP_EVENTS) failed, errno=%d",errno);
            }

            if (assocmaxret > 0) {
                struct sctp_assocparams associnfo;
                memset(&associnfo, 0, sizeof(associnfo));
                associnfo.sasoc_asocmaxrxt = assocmaxret;
                if (setsockopt(socket->ss_fd, IPPROTO_SCTP, SCTP_ASSOCINFO, &associnfo,
                               sizeof(associnfo)) == -1) {
                    WARNING("setsockopt(SCTP_ASSOCINFO) failed, errno=%d", errno);
                }
            }

            if (setsockopt(socket->ss_fd, IPPROTO_SCTP, SCTP_NODELAY,
                           (void *)&sock_opt, sizeof (sock_opt)) == -1) {
                WARNING("setsockopt(SCTP_NODELAY) failed, errno=%d", errno);
            }
        }
#endif

#ifndef SOL_TCP
#define SOL_TCP 6
#endif
        if (socket->ss_transport != T_SCTP) {
            if (setsockopt(socket->ss_fd, SOL_TCP, TCP_NODELAY, (void *)&sock_opt,
                           sizeof (sock_opt)) == -1) {
                {
                    ERROR_NO("setsockopt(TCP_NODELAY) failed");
                }
            }
        }

        {
            struct linger linger;

            linger.l_onoff = 1;
            linger.l_linger = 1;
            if (setsockopt (socket->ss_fd, SOL_SOCKET, SO_LINGER,
                            &linger, sizeof (linger)) < 0) {
                ERROR_NO("Unable to set SO_LINGER option");
            }
        }
    }

    /* Increase buffer sizes for this sockets */
    if(setsockopt(socket->ss_fd,
                  SOL_SOCKET,
                  SO_SNDBUF,
                  &buffsize,
                  sizeof(buffsize))) {
        ERROR_NO("Unable to set socket sndbuf");
    }

    buffsize = buff_size;
    if(setsockopt(socket->ss_fd,
                  SOL_SOCKET,
                  SO_RCVBUF,
                  &buffsize,
                  sizeof(buffsize))) {
        ERROR_NO("Unable to set socket rcvbuf");
    }
}

/* This socket is congested, mark it as such and add it to the poll files. */
int enter_congestion(struct sipp_socket *socket, int again)
{
    if (!socket->ss_congested) {
      nb_net_cong++;
    }
    socket->ss_congested = true;

    TRACE_MSG("Problem %s on socket  %d and poll_idx  is %d \n",
              again == EWOULDBLOCK ? "EWOULDBLOCK" : "EAGAIN",
              socket->ss_fd, socket->ss_pollidx);
#ifdef HAVE_EPOLL
    epollfiles[socket->ss_pollidx].events |= EPOLLOUT;
    int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, socket->ss_fd, &epollfiles[socket->ss_pollidx]);
    if (rc == -1) {
        WARNING_NO("Failed to set EPOLLOUT");
    }
#else
     pollfiles[socket->ss_pollidx].events |= POLLOUT;
#endif
 
#ifdef USE_SCTP
    if (!(socket->ss_transport == T_SCTP &&
            socket->sctpstate == SCTP_CONNECTING))
#endif
    return -1;
}

static int write_error(struct sipp_socket *socket, int ret)
{
    const char *errstring = strerror(errno);

#ifndef EAGAIN
    int again = (errno == EWOULDBLOCK) ? errno : 0;
#else
    int again = ((errno == EAGAIN) || (errno == EWOULDBLOCK)) ? errno : 0;

    /* Scrub away EAGAIN from the rest of the code. */
    if (errno == EAGAIN) {
        errno = EWOULDBLOCK;
    }
#endif

    if(again) {
        return enter_congestion(socket, again);
    }

    if ((socket->ss_transport == T_TCP || socket->ss_transport == T_SCTP)
            && errno == EPIPE) {
        nb_net_send_errors++;
        sipp_abort_connection(socket->ss_fd);
        socket->ss_fd = -1;
        sockets_pending_reset.insert(socket);
        if (reconnect_allowed()) {
            WARNING("Broken pipe on TCP connection, remote peer "
                    "probably closed the socket");
        } else {
            ERROR("Broken pipe on TCP connection, remote peer "
                  "probably closed the socket");
        }
        return -1;
    }

#ifdef _USE_OPENSSL
    if (socket->ss_transport == T_TLS) {
        errstring = sip_tls_error_string(socket->ss_ssl, ret);
    }
#endif

    WARNING("Unable to send %s message: %s", TRANSPORT_TO_STRING(socket->ss_transport), errstring);
    nb_net_send_errors++;
    return -1;
}

int read_error(struct sipp_socket *socket, int ret)
{
    const char *errstring = strerror(errno);
#ifdef _USE_OPENSSL
    if (socket->ss_transport == T_TLS) {
        errstring = sip_tls_error_string(socket->ss_ssl, ret);
    }
#endif

    assert(ret <= 0);

#ifdef EAGAIN
    /* Scrub away EAGAIN from the rest of the code. */
    if (errno == EAGAIN) {
        errno = EWOULDBLOCK;
    }
#endif

    /* We have only non-blocking reads, so this should not occur. */
    if (ret < 0) {
        assert(errno != EAGAIN);
    }

    if (socket->ss_transport == T_TCP || socket->ss_transport == T_TLS) {
        if (ret == 0) {
            /* The remote side closed the connection. */
            if(socket->ss_control) {
                if(localTwinSippSocket) sipp_close_socket(localTwinSippSocket);
                if (extendedTwinSippMode) {
                    close_peer_sockets();
                    close_local_sockets();
                    free_peer_addr_map();
                    WARNING("One of the twin instances has ended -> exiting");
                    quitting += 20;
                } else if(twinSippMode) {
                    if(twinSippSocket) sipp_close_socket(twinSippSocket);
                    if(thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
                        WARNING("3PCC controller A has ended -> exiting");
                        quitting += 20;
                    } else {
                        quitting = 1;
                    }
                }
            } else {
                /* The socket was closed "cleanly", but we may have calls that need to
                 * be destroyed.  Also, if these calls are not complete, and attempt to
                 * send again we may "ressurect" the socket by reconnecting it.*/
                sipp_socket_invalidate(socket);
                if (reset_close) {
                    close_calls(socket);
                }
            }
            return 0;
        }

        sipp_abort_connection(socket->ss_fd);
        socket->ss_fd = -1;
        sockets_pending_reset.insert(socket);

        nb_net_recv_errors++;
        if (reconnect_allowed()) {
            WARNING("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
        } else {
            ERROR("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
        }
        return -1;
    }

    WARNING("Unable to receive %s message: %s", TRANSPORT_TO_STRING(socket->ss_transport), errstring);
    nb_net_recv_errors++;
    return -1;
}

void buffer_write(struct sipp_socket *socket, const char *buffer, size_t len, struct sockaddr_storage *dest)
{
    struct socketbuf *buf = socket->ss_out;

    if (!buf) {
        socket->ss_out = alloc_socketbuf(const_cast<char*>(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
        TRACE_MSG("Added first buffered message to socket %d\n", socket->ss_fd);
        return;
    }

    while(buf->next) {
        buf = buf->next;
    }

    buf->next = alloc_socketbuf(const_cast<char*>(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
    TRACE_MSG("Appended buffered message to socket %d\n", socket->ss_fd);
}

void buffer_read(struct sipp_socket *socket, struct socketbuf *newbuf)
{
    struct socketbuf *buf = socket->ss_in;
    struct socketbuf *prev = buf;

    if (!buf) {
        socket->ss_in = newbuf;
        return;
    }

    while(buf->next) {
        prev = buf;
        buf = buf->next;
    }

    prev->next = newbuf;
}

#ifdef _USE_OPENSSL

/****** Certificate Verification Callback FACILITY *************/
int sip_tls_verify_callback(int ok , X509_STORE_CTX *store)
{
    char data[512];

    if (!ok) {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);

        X509_NAME_oneline(X509_get_issuer_name(cert),
                          data,512);
        WARNING("TLS verification error for issuer: '%s'", data);
        X509_NAME_oneline(X509_get_subject_name(cert),
                          data,512);
        WARNING("TLS verification error for subject: '%s'", data);
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
ssl_init_status FI_init_ssl_context (void)
{
    sip_trp_ssl_ctx = SSL_CTX_new( TLSv1_method() );
    if ( sip_trp_ssl_ctx == NULL ) {
        ERROR("FI_init_ssl_context: SSL_CTX_new with TLSv1_method failed");
        return SSL_INIT_ERROR;
    }

    sip_trp_ssl_ctx_client = SSL_CTX_new( TLSv1_method() );
    if ( sip_trp_ssl_ctx_client == NULL) {
        ERROR("FI_init_ssl_context: SSL_CTX_new with TLSv1_method failed");
        return SSL_INIT_ERROR;
    }

    /*  Load the trusted CA's */
    SSL_CTX_load_verify_locations(sip_trp_ssl_ctx, tls_cert_name, NULL);
    SSL_CTX_load_verify_locations(sip_trp_ssl_ctx_client, tls_cert_name, NULL);

    /*  CRL load from application specified only if specified on the command line */
    if (strlen(tls_crl_name) != 0) {
        if(sip_tls_load_crls(sip_trp_ssl_ctx,tls_crl_name) == -1) {
            ERROR("FI_init_ssl_context: Unable to load CRL file (%s)", tls_crl_name);
            return SSL_INIT_ERROR;
        }

        if(sip_tls_load_crls(sip_trp_ssl_ctx_client,tls_crl_name) == -1) {
            ERROR("FI_init_ssl_context: Unable to load CRL (client) file (%s)", tls_crl_name);
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

    /* We need the flags parameter as this is a callback with defined arguments,
     * but we don't use it. Cast to void to avoid warnings. */
    (void)flags;

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
#if defined(MSG_DONTWAIT) && !defined(__SUNOS)
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

#ifdef USE_SCTP
int send_sctp_nowait(int s, const void *msg, int len, int flags)
{
    struct sctp_sndrcvinfo sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.sinfo_flags = SCTP_UNORDERED; // according to RFC4168 5.1
    sinfo.sinfo_stream = 0;

#if defined(MSG_DONTWAIT) && !defined(__SUNOS)
    return sctp_send(s, msg, len, &sinfo, flags | MSG_DONTWAIT);
#else
    int fd_flags = fcntl(s, F_GETFL, NULL);
    int initial_fd_flags;
    int rc;

    initial_fd_flags = fd_flags;
    fd_flags |= O_NONBLOCK;
    fcntl(s, F_SETFL , fd_flags);

    rc = sctp_send(s, msg, len, &sinfo, flags);

    fcntl(s, F_SETFL, initial_fd_flags);

    return rc;
#endif
}
#endif

static ssize_t socket_write_primitive(struct sipp_socket *socket, const char *buffer, size_t len, struct sockaddr_storage *dest)
{
    ssize_t rc;

    /* Refuse to write to invalid sockets. */
    if (socket->ss_invalid) {
        WARNING("Returning EPIPE on invalid socket: %p (%d)\n", socket, socket->ss_fd);
        errno = EPIPE;
        return -1;
    }

    /* Always check congestion before sending. */
    if (socket->ss_congested) {
        errno = EWOULDBLOCK;
        return -1;
    }

    switch(socket->ss_transport) {
    case T_TLS:
#ifdef _USE_OPENSSL
        rc = send_nowait_tls(socket->ss_ssl, buffer, len, 0);
#else
        errno = EOPNOTSUPP;
        rc = -1;
#endif
        break;
    case T_SCTP:
#ifdef USE_SCTP
    {
        TRACE_MSG("socket_write_primitive %d\n", socket->sctpstate);
        if (socket->sctpstate == SCTP_DOWN) {
            errno = EPIPE;
            return -1;
        } else if (socket->sctpstate == SCTP_CONNECTING) {
            errno = EWOULDBLOCK;
            return -1;
        }
        rc = send_sctp_nowait(socket->ss_fd, buffer, len, 0);
    }
#else
    errno = EOPNOTSUPP;
    rc = -1;
#endif
    break;
    case T_TCP:
        rc = send_nowait(socket->ss_fd, buffer, len, 0);
        break;
    case T_UDP:
        if(compression) {
            static char comp_msg[SIPP_MAX_MSG_SIZE];
            strcpy(comp_msg, buffer);
            if(comp_compress(&socket->ss_comp_state,
                             comp_msg,
                             (unsigned int *) &len) != COMP_OK) {
                ERROR("Compression pluggin error");
            }
            buffer = (char *)comp_msg;

            TRACE_MSG("---\nCompressed message len: %d\n", len);
        }

        rc = sendto(socket->ss_fd, buffer, len, 0, (struct sockaddr *)dest, SOCK_ADDR_SIZE(dest));

        break;
    default:
        ERROR("Internal error, unknown transport type %d\n", socket->ss_transport);
    }

    return rc;
}

/* Flush any output buffers for this socket. */
int flush_socket(struct sipp_socket *socket)
{
    struct socketbuf *buf;
    int ret;

    while ((buf = socket->ss_out)) {
        ssize_t size = buf->len - buf->offset;
        ret = socket_write_primitive(socket, buf->buf + buf->offset, size, &buf->addr);
        TRACE_MSG("Wrote %d of %d bytes in an output buffer.\n", ret, size);
        if (ret == size) {
            /* Everything is great, throw away this buffer. */
            socket->ss_out = buf->next;
            free_socketbuf(buf);
        } else if (ret <= 0) {
            /* Handle connection closes and errors. */
            return write_error(socket, ret);
        } else {
            /* We have written more of the partial buffer. */
            buf->offset += ret;
            errno = EWOULDBLOCK;
            enter_congestion(socket, EWOULDBLOCK);
            return -1;
        }
    }

    return 0;
}

/* Write data to a socket. */
int write_socket(struct sipp_socket *socket, const char *buffer, ssize_t len, int flags, struct sockaddr_storage *dest)
{
    int rc;
    if ( socket == NULL ) {
        //FIX coredump when trying to send data but no master yet ... ( for example after unexpected mesdsage)
        return 0;
    }

    if (socket->ss_out) {
        rc = flush_socket(socket);
        TRACE_MSG("Attempted socket flush returned %d\r\n", rc);
        if (rc < 0) {
            if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
                buffer_write(socket, buffer, len, dest);
                return len;
            } else {
                return rc;
            }
        }
    }

    rc = socket_write_primitive(socket, buffer, len, dest);
    struct timeval currentTime;
    GET_TIME (&currentTime);

    if (rc == len) {
        /* Everything is great. */
        if (useMessagef == 1) {
            TRACE_MSG("----------------------------------------------- %s\n"
                      "%s %smessage sent (%d bytes):\n\n%.*s\n",
                      CStat::formatTime(&currentTime, true),
                      TRANSPORT_TO_STRING(socket->ss_transport),
                      socket->ss_control ? "control " : "",
                      len, len, buffer);
        }

        if (useShortMessagef == 1) {
            char *msg = strdup(buffer);
            char *call_id = get_call_id(msg);
            TRACE_SHORTMSG("%s\tS\t%s\tCSeq:%s\t%s\n",
                           CStat::formatTime(&currentTime), call_id, get_header_content(msg,"CSeq:"), get_first_line(msg));
            free(msg);
        }

    } else if (rc <= 0) {
        if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
            buffer_write(socket, buffer, len, dest);
            enter_congestion(socket, errno);
            return len;
        }
        if (useMessagef == 1) {
            TRACE_MSG("----------------------------------------------- %s\n"
                      "Error sending %s message:\n\n%.*s\n",
                      CStat::formatTime(&currentTime, true),
                      TRANSPORT_TO_STRING(socket->ss_transport),
                      len, buffer);
        }
        return write_error(socket, errno);
    } else {
        /* We have a truncated message, which must be handled internally to the write function. */
        if (useMessagef == 1) {
            TRACE_MSG("----------------------------------------------- %s\n"
                      "Truncation sending %s message (%d of %d sent):\n\n%.*s\n",
                      CStat::formatTime(&currentTime, true),
                      TRANSPORT_TO_STRING(socket->ss_transport),
                      rc, len, len, buffer);
        }
        buffer_write(socket, buffer + rc, len - rc, dest);
        enter_congestion(socket, errno);
    }

    return rc;
}

bool reconnect_allowed()
{
    if (reset_number == -1) {
        return true;
    }
    return (reset_number > 0);
}

void reset_connection(struct sipp_socket *socket)
{
    if (!reconnect_allowed()) {
        ERROR_NO("Max number of reconnections reached");
    }

    if (reset_number != -1) {
        reset_number--;
    }

    if (reset_close) {
        WARNING("Closing calls, because of TCP reset or close!");
        close_calls(socket);
    }

    /* Sleep for some period of time before the reconnection. */
    usleep(1000 * reset_sleep);

    if (sipp_reconnect_socket(socket) < 0) {
        WARNING_NO("Could not reconnect TCP socket");
        close_calls(socket);
    } else {
        WARNING("Socket required a reconnection.");
    }
}

/* Close just those calls for a given socket (e.g., if the remote end closes
 * the connection. */
void close_calls(struct sipp_socket *socket)
{
    owner_list *owners = get_owners_for_socket(socket);
    owner_list::iterator owner_it;
    socketowner *owner_ptr = NULL;

    for (owner_it = owners->begin(); owner_it != owners->end(); owner_it++) {
        owner_ptr = *owner_it;
        if(owner_ptr) {
            owner_ptr->tcpClose();
        }
    }

    delete owners;
}

int open_connections()
{
    int status=0;
    local_port = 0;

    if(!strlen(remote_host)) {
        if((sendMode != MODE_SERVER)) {
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
            struct addrinfo * local_addr;

            fprintf(stderr,"Resolving remote host '%s'... ", remote_host);

            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = PF_UNSPEC;

            /* FIXME: add DNS SRV support using liburli? */
            if (getaddrinfo(remote_host,
                            NULL,
                            &hints,
                            &local_addr) != 0) {
                ERROR("Unknown remote host '%s'.\n"
                      "Use 'sipp -h' for details", remote_host);
            }

            memset(&remote_sockaddr, 0, sizeof( remote_sockaddr ));
            memcpy(&remote_sockaddr,
                   local_addr->ai_addr,
                   SOCK_ADDR_SIZE(
                       _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

            freeaddrinfo(local_addr);

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
        struct addrinfo * local_addr;
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
        if (getaddrinfo(local_host, NULL, &hints, &local_addr) != 0) {
            ERROR("Can't get local IP address in getaddrinfo, local_host='%s', local_ip='%s'",
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
            memcpy(&local_sockaddr,
                   local_addr->ai_addr,
                   SOCK_ADDR_SIZE(
                       _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));
        }
        freeaddrinfo(local_addr);

        if (local_sockaddr.ss_family == AF_INET6) {
            local_ip_is_ipv6 = true;
            sprintf(local_ip_escaped, "[%s]", local_ip);
        } else {
            strcpy(local_ip_escaped, local_ip);
        }
    }

    /* Creating and binding the local socket */
    if ((main_socket = new_sipp_socket(local_ip_is_ipv6, transport)) == NULL) {
        ERROR_NO("Unable to get the local socket");
    }

    sipp_customize_socket(main_socket);

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
                    inFiles[ip_file]->getField(0, peripfield, peripaddr, sizeof(peripaddr));
                    if (getaddrinfo(peripaddr,
                                    NULL,
                                    &hints,
                                    &local_addr) != 0) {
                        ERROR("Unknown host '%s'.\n"
                              "Use 'sipp -h' for details", peripaddr);
                    }
                } else {
                    if (getaddrinfo(local_ip,
                                    NULL,
                                    &hints,
                                    &local_addr) != 0) {
                        ERROR("Unknown host '%s'.\n"
                              "Use 'sipp -h' for details", peripaddr);
                    }
                }
                memcpy(&local_sockaddr,
                       local_addr->ai_addr,
                       SOCK_ADDR_SIZE(
                           _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
                freeaddrinfo(local_addr);
            }
            if (local_ip_is_ipv6) {
                (_RCAST(struct sockaddr_in6 *, &local_sockaddr))->sin6_port
                    = htons((short)l_port);
            } else {
                (_RCAST(struct sockaddr_in *, &local_sockaddr))->sin_port
                    = htons((short)l_port);
            }
            if(sipp_bind_socket(main_socket, &local_sockaddr, &local_port) == 0) {
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
                inFiles[ip_file]->getField(0, peripfield, peripaddr, sizeof(peripaddr));
                if (getaddrinfo(peripaddr,
                                NULL,
                                &hints,
                                &local_addr) != 0) {
                    ERROR("Unknown host '%s'.\n"
                          "Use 'sipp -h' for details", peripaddr);
                }
            } else {
                if (getaddrinfo(local_ip,
                                NULL,
                                &hints,
                                &local_addr) != 0) {
                    ERROR("Unknown host '%s'.\n"
                          "Use 'sipp -h' for details", peripaddr);
                }
            }
            memcpy(&local_sockaddr,
                   local_addr->ai_addr,
                   SOCK_ADDR_SIZE(
                       _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
            freeaddrinfo(local_addr);
        }

        if (local_ip_is_ipv6) {
            (_RCAST(struct sockaddr_in6 *, &local_sockaddr))->sin6_port
                = htons((short)user_port);
        } else {
            (_RCAST(struct sockaddr_in *, &local_sockaddr))->sin_port
                = htons((short)user_port);
        }
        if(sipp_bind_socket(main_socket, &local_sockaddr, &local_port)) {
            ERROR_NO("Unable to bind main socket");
        }
    }

    if (peripsocket) {
        // Add the main socket to the socket per subscriber map
        map_perip_fd[peripaddr] = main_socket;
    }

    // Create additional server sockets when running in socket per
    // IP address mode.
    if (peripsocket && sendMode == MODE_SERVER) {
        struct sockaddr_storage server_sockaddr;
        struct addrinfo * local_addr;
        struct addrinfo   hints;
        memset((char*)&hints, 0, sizeof(hints));
        hints.ai_flags  = AI_PASSIVE;
        hints.ai_family = PF_UNSPEC;

        char peripaddr[256];
        struct sipp_socket *sock;
        unsigned int lines = inFiles[ip_file]->numLines();
        for (unsigned int i = 0; i < lines; i++) {
            inFiles[ip_file]->getField(i, peripfield, peripaddr, sizeof(peripaddr));
            map<string, struct sipp_socket *>::iterator j;
            j = map_perip_fd.find(peripaddr);

            if (j == map_perip_fd.end()) {
                if((sock = new_sipp_socket(is_ipv6, transport)) == NULL) {
                    ERROR_NO("Unable to get server socket");
                }

                if (getaddrinfo(peripaddr,
                                NULL,
                                &hints,
                                &local_addr) != 0) {
                    ERROR("Unknown remote host '%s'.\n"
                          "Use 'sipp -h' for details", peripaddr);
                }

                memcpy(&server_sockaddr,
                       local_addr->ai_addr,
                       SOCK_ADDR_SIZE(
                           _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
                freeaddrinfo(local_addr);

                if (is_ipv6) {
                    (_RCAST(struct sockaddr_in6 *, &server_sockaddr))->sin6_port
                        = htons((short)local_port);
                } else {
                    (_RCAST(struct sockaddr_in *, &server_sockaddr))->sin_port
                        = htons((short)local_port);
                }

                sipp_customize_socket(sock);
                if(sipp_bind_socket(sock, &server_sockaddr, NULL)) {
                    ERROR_NO("Unable to bind server socket");
                }

                map_perip_fd[peripaddr] = sock;
            }
        }
    }

    if((!multisocket) && (transport == T_TCP || transport == T_TLS || transport == T_SCTP) &&
            (sendMode != MODE_SERVER)) {
        if((tcp_multiplex = new_sipp_socket(local_ip_is_ipv6, transport)) == NULL) {
            ERROR_NO("Unable to get a TCP socket");
        }

        /* OJA FIXME: is it correct? */
        if (use_remote_sending_addr) {
            remote_sockaddr = remote_sending_sockaddr ;
        }
        sipp_customize_socket(tcp_multiplex);

        if(sipp_connect_socket(tcp_multiplex, &remote_sockaddr)) {
            if(reset_number >0) {
                WARNING("Failed to reconnect\n");
                sipp_close_socket(main_socket);
                reset_number--;
                return 1;
            } else {
                if(errno == EINVAL) {
                    /* This occurs sometime on HPUX but is not a true INVAL */
                    ERROR_NO("Unable to connect a TCP socket, remote peer error.\n"
                             "Use 'sipp -h' for details");
                } else {
                    ERROR_NO("Unable to connect a TCP socket.\n"
                             "Use 'sipp -h' for details");
                }
            }
        }

    }


    if(transport == T_TCP || transport == T_TLS || transport == T_SCTP) {
        if(listen(main_socket->ss_fd, 100)) {
            ERROR_NO("Unable to listen main socket");
        }
    }

    /* Trying to connect to Twin Sipp in 3PCC mode */
    if(twinSippMode) {
        if(thirdPartyMode == MODE_3PCC_CONTROLLER_A || thirdPartyMode == MODE_3PCC_A_PASSIVE) {
            connect_to_peer(twinSippHost, twinSippPort, &twinSipp_sockaddr, twinSippIp, &twinSippSocket);
        } else if(thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
            connect_local_twin_socket(twinSippHost);
        } else {
            ERROR("TwinSipp Mode enabled but thirdPartyMode is different "
                  "from 3PCC_CONTROLLER_B and 3PCC_CONTROLLER_A\n");
        }
    } else if (extendedTwinSippMode) {
        if (thirdPartyMode == MODE_MASTER || thirdPartyMode == MODE_MASTER_PASSIVE) {
            strcpy(twinSippHost,get_peer_addr(master_name));
            get_host_and_port(twinSippHost, twinSippHost, &twinSippPort);
            connect_local_twin_socket(twinSippHost);
            connect_to_all_peers();
        } else if(thirdPartyMode == MODE_SLAVE) {
            strcpy(twinSippHost,get_peer_addr(slave_number));
            get_host_and_port(twinSippHost, twinSippHost, &twinSippPort);
            connect_local_twin_socket(twinSippHost);
        } else {
            ERROR("extendedTwinSipp Mode enabled but thirdPartyMode is different "
                  "from MASTER and SLAVE\n");
        }
    }

    return status;
}


void connect_to_peer(char *peer_host, int peer_port, struct sockaddr_storage *peer_sockaddr, char *peer_ip, struct sipp_socket **peer_socket)
{

    /* Resolving the  peer IP */
    printf("Resolving peer address : %s...\n",peer_host);
    struct addrinfo   hints;
    struct addrinfo * local_addr;
    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;
    is_ipv6 = false;
    /* Resolving twin IP */
    if (getaddrinfo(peer_host,
                    NULL,
                    &hints,
                    &local_addr) != 0) {

        ERROR("Unknown peer host '%s'.\n"
              "Use 'sipp -h' for details", peer_host);
    }

    memcpy(peer_sockaddr,
           local_addr->ai_addr,
           SOCK_ADDR_SIZE(
               _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

    freeaddrinfo(local_addr);

    if (peer_sockaddr->ss_family == AF_INET) {
        (_RCAST(struct sockaddr_in *,peer_sockaddr))->sin_port =
            htons((short)peer_port);
    } else {
        (_RCAST(struct sockaddr_in6 *,peer_sockaddr))->sin6_port =
            htons((short)peer_port);
        is_ipv6 = true;
    }
    strcpy(peer_ip, get_inet_address(peer_sockaddr));
    if((*peer_socket = new_sipp_socket(is_ipv6, T_TCP)) == NULL) {
        ERROR_NO("Unable to get a twin sipp TCP socket");
    }

    /* Mark this as a control socket. */
    (*peer_socket)->ss_control = 1;

    if(sipp_connect_socket(*peer_socket, peer_sockaddr)) {
        if(errno == EINVAL) {
            /* This occurs sometime on HPUX but is not a true INVAL */
            ERROR_NO("Unable to connect a twin sipp TCP socket\n "
                     ", remote peer error.\n"
                     "Use 'sipp -h' for details");
        } else {
            ERROR_NO("Unable to connect a twin sipp socket "
                     "\n"
                     "Use 'sipp -h' for details");
        }
    }

    sipp_customize_socket(*peer_socket);
}

struct sipp_socket **get_peer_socket(char * peer) {
    struct sipp_socket **peer_socket;
    T_peer_infos infos;
    peer_map::iterator peer_it;
    peer_it = peers.find(peer_map::key_type(peer));
    if(peer_it != peers.end()) {
        infos = peer_it->second;
        peer_socket = &(infos.peer_socket);
        return peer_socket;
    } else {
        ERROR("get_peer_socket: Peer %s not found\n", peer);
    }
    return NULL;
}

char * get_peer_addr(char * peer)
{
    char * addr;
    peer_addr_map::iterator peer_addr_it;
    peer_addr_it = peer_addrs.find(peer_addr_map::key_type(peer));
    if(peer_addr_it != peer_addrs.end()) {
        addr =  peer_addr_it->second;
        return addr;
    } else {
        ERROR("get_peer_addr: Peer %s not found\n", peer);
    }
    return NULL;
}

bool is_a_peer_socket(struct sipp_socket *peer_socket)
{
    peer_socket_map::iterator peer_socket_it;
    peer_socket_it = peer_sockets.find(peer_socket_map::key_type(peer_socket));
    if(peer_socket_it == peer_sockets.end()) {
        return false;
    } else {
        return true;
    }
}

void connect_local_twin_socket(char * twinSippHost)
{
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
        ERROR("Unknown twin host '%s'.\n"
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

    if((localTwinSippSocket = new_sipp_socket(is_ipv6, T_TCP)) == NULL) {
        ERROR_NO("Unable to get a listener TCP socket ");
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
    // This allows to re-start the controller B (or slave) without timeout after its exit
    int reuse = 1;
    setsockopt(localTwinSippSocket->ss_fd,SOL_SOCKET,SO_REUSEADDR,(int *)&reuse,sizeof(reuse));
    sipp_customize_socket(localTwinSippSocket);

    if(sipp_bind_socket(localTwinSippSocket, &localTwin_sockaddr, 0)) {
        ERROR_NO("Unable to bind twin sipp socket ");
    }

    if(listen(localTwinSippSocket->ss_fd, 100)) {
        ERROR_NO("Unable to listen twin sipp socket in ");
    }
}

void close_peer_sockets()
{
    peer_map::iterator peer_it;
    T_peer_infos infos;

    for(peer_it = peers.begin(); peer_it != peers.end(); peer_it++) {
        infos = peer_it->second;
        sipp_close_socket(infos.peer_socket);
        infos.peer_socket = NULL ;
        peers[std::string(peer_it->first)] = infos;
    }

    peers_connected = 0;
}

void close_local_sockets()
{
    for (int i = 0; i< local_nb; i++) {
        sipp_close_socket(local_sockets[i]);
        local_sockets[i] = NULL;
    }
}

void connect_to_all_peers()
{
    peer_map::iterator peer_it;
    T_peer_infos infos;
    for (peer_it = peers.begin(); peer_it != peers.end(); peer_it++) {
        infos = peer_it->second;
        get_host_and_port(infos.peer_host, infos.peer_host, &infos.peer_port);
        connect_to_peer(infos.peer_host, infos.peer_port,&(infos.peer_sockaddr), infos.peer_ip, &(infos.peer_socket));
        peer_sockets[infos.peer_socket] = peer_it->first;
        peers[std::string(peer_it->first)] = infos;
    }
    peers_connected = 1;
}

bool is_a_local_socket(struct sipp_socket *s)
{
    for (int i = 0; i< local_nb + 1; i++) {
        if(local_sockets[i] == s) return true;
    }
    return (false);
}

void free_peer_addr_map()
{
    peer_addr_map::iterator peer_addr_it;
    for (peer_addr_it = peer_addrs.begin(); peer_addr_it != peer_addrs.end(); peer_addr_it++) {
        free(peer_addr_it->second);
    }
}

/***************** Check of the message received ***************/

bool sipMsgCheck (const char *P_msg, struct sipp_socket *socket)
{
    const char C_sipHeader[] = "SIP/2.0" ;

    if (socket == twinSippSocket || socket == localTwinSippSocket ||
            is_a_peer_socket(socket) || is_a_local_socket(socket))
        return true;

    if (strstr(P_msg, C_sipHeader) !=  NULL) {
        return true ;
    }

    return false ;
}
