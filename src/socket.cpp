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
 *           Michael Hirschbichler
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "sipp.hpp"
#include "socket.hpp"
#include "logger.hpp"

extern bool do_hide;

SIPpSocket *ctrl_socket = nullptr;
SIPpSocket *stdin_socket = nullptr;

static int stdin_fileno = -1;
static int stdin_mode;

/******************** Recv Poll Processing *********************/

unsigned pollnfds;
#ifdef HAVE_EPOLL
int epollfd;
struct epoll_event   epollfiles[SIPP_MAXFDS];
struct epoll_event*  epollevents;
#else
struct pollfd        pollfiles[SIPP_MAXFDS];
#endif
SIPpSocket  *sockets[SIPP_MAXFDS];

int pending_messages = 0;

std::map<std::string, SIPpSocket *>     map_perip_fd;

static void connect_to_peer(
    char *peer_host, int peer_port, struct sockaddr_storage *peer_sockaddr,
    char *peer_ip, int peer_ip_size, SIPpSocket **peer_socket);

int gai_getsockaddr(struct sockaddr_storage* ss, const char* host,
                    const char *service, int flags, int family)
{
    const struct addrinfo hints = {flags, family,};
    struct addrinfo* res;

    int error = getaddrinfo(host, service, &hints, &res);
    if (error == 0) {
        memcpy(ss, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
    } else {
        WARNING("getaddrinfo failed: %s", gai_strerror(error));
    }

    return error;
}

int gai_getsockaddr(struct sockaddr_storage* ss, const char* host,
                    unsigned short port, int flags, int family)
{
    if (port) {
        char service[NI_MAXSERV + 1];
        snprintf(service, sizeof(service), "%d", port);
        return gai_getsockaddr(ss, host, service, flags, family);
    } else {
        return gai_getsockaddr(ss, host, nullptr, flags, family);
    }
}

void sockaddr_update_port(struct sockaddr_storage* ss, short port)
{
    switch (ss->ss_family) {
    case AF_INET:
        _RCAST(struct sockaddr_in*, ss)->sin_port = htons(port);
        break;
    case AF_INET6:
        _RCAST(struct sockaddr_in6*, ss)->sin6_port = htons(port);
        break;
    default:
        ERROR("Unsupported family type");
    }
}

static void process_set(char* what)
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
            CallGenerationTask::set_rate(drest);
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
            CallGenerationTask::set_users(urest);
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
        } else if (!strcmp(rest, "ooc") && ooc_scenario) {
            display_scenario = ooc_scenario;
        } else if (!strcmp(rest, "rx") && rx_scenario) {
            display_scenario = rx_scenario;
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
    } else {
        WARNING("Unknown set attribute: %s", what);
    }
}

static void process_trace(char* what)
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

static void process_dump(char* what)
{
    if (!strcmp(what, "tasks")) {
        dump_tasks();
    } else if (!strcmp(what, "variables")) {
        display_scenario->allocVars->dump();
    } else {
        WARNING("Unknown dump type: %s", what);
    }
}

static void process_reset(char* what)
{
    if (!strcmp(what, "stats")) {
        main_scenario->stats->computeStat(CStat::E_RESET_C_COUNTERS);
    } else {
        WARNING("Unknown reset type: %s", what);
    }
}

static bool process_command(char* command)
{
    trim(command);

    char *rest = strchr(command, ' ');
    if (rest) {
        *rest++ = '\0';
        trim(rest);
    }

    if (!rest) {
        WARNING("The %s command requires at least one argument", command);
    } else if (!strcmp(command, "set")) {
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
char *command_buffer = nullptr;

extern bool sipMsgCheck (const char *P_msg, SIPpSocket *socket);

static const char* get_trimmed_call_id(const char* msg)
{
    /* A call_id identifies a call and is generated by SIPp for each
     * new call.  In client mode, it is mandatory to use the value
     * generated by SIPp in the "Call-ID" header.  Otherwise, SIPp will
     * not recognise the answer to the message sent as being part of an
     * existing call.
     *
     * Note: [call_id] can be prepended with an arbitrary string using
     * '///'.
     * Example: Call-ID: ABCDEFGHIJ///[call_id]
     * - it will still be recognized by SIPp as part of the same call.
     */
    const char *call_id = get_call_id(msg);
    const char *slashes = strstr(call_id, "///");
    if ((!callidSlash) && slashes) {
        return slashes + 3;
    }
    return call_id;
}

static char* get_inet_address(const struct sockaddr_storage* addr, char* dst, int len)
{
    if (getnameinfo(_RCAST(struct sockaddr*, addr), socklen_from_addr(addr),
                    dst, len, nullptr, 0, NI_NUMERICHOST) != 0) {
        snprintf(dst, len, "addr not supported");
    }
    return dst;
}

static bool process_key(int c)
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
            CallGenerationTask::set_users((int)(users + 1 * rate_scale));
        } else {
            CallGenerationTask::set_rate(rate + 1 * rate_scale);
        }
        print_statistics(0);
        break;

    case '-':
        if (users >= 0) {
            CallGenerationTask::set_users((int)(users - 1 * rate_scale));
        } else {
            CallGenerationTask::set_rate(rate - 1 * rate_scale);
        }
        print_statistics(0);
        break;

    case '*':
        if (users >= 0) {
            CallGenerationTask::set_users((int)(users + 10 * rate_scale));
        } else {
            CallGenerationTask::set_rate(rate + 10 * rate_scale);
        }
        print_statistics(0);
        break;

    case '/':
        if (users >= 0) {
            CallGenerationTask::set_users((int)(users - 10 * rate_scale));
        } else {
            CallGenerationTask::set_rate(rate - 10 * rate_scale);
        }
        print_statistics(0);
        break;

    case 'p':
        if (paused) {
            CallGenerationTask::set_paused(false);
        } else {
            CallGenerationTask::set_paused(true);
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

    int ret = recv(ctrl_socket->ss_fd, bufrcv, sizeof(bufrcv) - 1, 0);
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

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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

    memset(&ctl_sa, 0, sizeof(struct sockaddr_storage));
    if (control_ip[0]) {
        if (gai_getsockaddr(&ctl_sa, control_ip, nullptr,
                            AI_PASSIVE, AF_UNSPEC) != 0) {
            ERROR("Unknown control address '%s'.\n"
                  "Use 'sipp -h' for details", control_ip);
        }
    } else {
        ((struct sockaddr_in *)&ctl_sa)->sin_family = AF_INET;
        ((struct sockaddr_in *)&ctl_sa)->sin_addr.s_addr = INADDR_ANY;
    }

    while (try_counter) {
        ((struct sockaddr_in *)&ctl_sa)->sin_port = htons(port);
        if (!::bind(sock, (struct sockaddr *)&ctl_sa, sizeof(struct sockaddr_in))) {
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

    ctrl_socket = new SIPpSocket(0, T_UDP, sock, 0);
}

void reset_stdin()
{
    fcntl(stdin_fileno, F_SETFL, stdin_mode);
}

void setup_stdin_socket()
{
    stdin_fileno = fileno(stdin);
    stdin_mode = fcntl(stdin_fileno, F_GETFL);
    atexit(reset_stdin);
    fcntl(stdin_fileno, F_SETFL, stdin_mode | O_NONBLOCK);

    stdin_socket = new SIPpSocket(0, T_TCP, stdin_fileno, 0);
}

#define SIPP_ENDL "\r\n"
void handle_stdin_socket()
{
    int c;
    int chars = 0;

    if (feof(stdin)) {
        stdin_socket->close();
        stdin_socket = nullptr;
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
            }
#ifndef __SUNOS
            else if (c == key_backspace || c == key_dc)
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
        } else {
            process_key(c);
        }
    }
    if (chars == 0) {
        /* We did not read any characters, even though we should have. */
        stdin_socket->close();
        stdin_socket = nullptr;
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

static void merge_socketbufs(struct socketbuf* socketbuf)
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
int SIPpSocket::check_for_message()
{
    struct socketbuf *socketbuf = ss_in;
    int state = ss_control ? CFM_CONTROL : CFM_NORMAL;
    const char *l;

    if (!socketbuf)
        return 0;

    if (ss_transport == T_UDP || ss_transport == T_SCTP) {
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

    char saved = socketbuf->buf[socketbuf->offset + len];
    socketbuf->buf[socketbuf->offset + len] = '\0';

    /* Find the content-length header. */
    if ((l = strcasestr(socketbuf->buf + socketbuf->offset, "\r\nContent-Length:"))) {
        l += strlen("\r\nContent-Length:");
    } else if ((l = strcasestr(socketbuf->buf + socketbuf->offset, "\r\nl:"))) {
        l += strlen("\r\nl:");
    }

    socketbuf->buf[socketbuf->offset + len] = saved;

    /* There is no header, so the content-length is zero. */
    if (!l)
        return len + 1;

    /* Skip spaces. */
    while (isspace(*l)) {
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
        if (socketbuf->next == nullptr) {
            /* There is no buffer to merge, so we fail. */
            return 0;
        }
        /* We merge ourself with the next buffer. */
        merge_socketbufs(socketbuf);
    } while (1);
}

#ifdef USE_SCTP
int SIPpSocket::handleSCTPNotify(char* buffer)
{
    union sctp_notification *notifMsg;

    notifMsg = (union sctp_notification *)buffer;

    TRACE_MSG("SCTP Notification: %d\n",
              ntohs(notifMsg->sn_header.sn_type));
    if (notifMsg->sn_header.sn_type == SCTP_ASSOC_CHANGE) {
        TRACE_MSG("SCTP_ASSOC_CHANGE\n");
        if (notifMsg->sn_assoc_change.sac_state == SCTP_COMM_UP) {
            TRACE_MSG("SCTP_COMM_UP\n");
            sctpstate = SCTP_UP;
            sipp_sctp_peer_params();

            /* Send SCTP message right after association is up */
            ss_congested = false;
            flush();
            return -2;
        } else {
            TRACE_MSG("else: %d\n", notifMsg->sn_assoc_change.sac_state);
            return 0;
        }
    } else if (notifMsg->sn_header.sn_type == SCTP_SHUTDOWN_EVENT) {
        TRACE_MSG("SCTP_SHUTDOWN_EVENT\n");
        return 0;
    }
    return -2;
}

void set_multihome_addr(SIPpSocket* socket, int port)
{
    if (strlen(multihome_ip)>0) {
        struct sockaddr_storage secondaryaddress;
        if (gai_getsockaddr(&secondaryaddress, multihome_ip, port,
                            AI_PASSIVE, AF_UNSPEC) != 0) {
            ERROR("Can't get multihome IP address in getaddrinfo, multihome_ip='%s'", multihome_ip);
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
int SIPpSocket::empty()
{

    int readsize=0;
    if (ss_transport == T_UDP || ss_transport == T_SCTP) {
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
    socketbuf = alloc_socketbuf(buffer, readsize, NO_COPY, nullptr);

    switch(ss_transport) {
    case T_TCP:
    case T_UDP:
        ret = recvfrom(ss_fd, buffer, readsize, 0, (struct sockaddr *)&socketbuf->addr,  &addrlen);
        break;
    case T_TLS:
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        ret = SSL_read(ss_ssl, buffer, readsize);
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

        ret = sctp_recvmsg(ss_fd, (void*)buffer, readsize,
                           (struct sockaddr *) &socketbuf->addr, &addrlen, &recvinfo, &msg_flags);

        if (MSG_NOTIFICATION & msg_flags) {
            errno = 0;
            handleSCTPNotify(buffer);
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

    buffer_read(socketbuf);

    /* Do we have a complete SIP message? */
    if (!ss_msglen) {
        if (int msg_len = check_for_message()) {
            ss_msglen = msg_len;
            pending_messages++;
        }
    }

    return ret;
}

void SIPpSocket::invalidate()
{
    unsigned pollidx;

    if (ss_invalid) {
        return;
    }

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    if (SSL *ssl = ss_ssl) {
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl);
    }
#endif

    /* In some error conditions, the socket FD has already been closed - if it hasn't, do so now. */
    if (ss_fd != -1) {
#ifdef HAVE_EPOLL
        int rc = epoll_ctl(epollfd, EPOLL_CTL_DEL, ss_fd, nullptr);
        if (rc == -1) {
            WARNING_NO("Failed to delete FD from epoll");
        }
#endif
    }
    if (ss_fd != -1 && ss_fd != stdin_fileno) {
        if (ss_transport != T_UDP) {
            if (shutdown(ss_fd, SHUT_RDWR) < 0) {
                WARNING_NO("Failed to shutdown socket %d", ss_fd);
            }
        }

#ifdef USE_SCTP
        if (ss_transport == T_SCTP && !gracefulclose) {
            struct linger ling = {1, 0};
            if (setsockopt(ss_fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)) < 0) {
                WARNING("Unable to set SO_LINGER option for SCTP close");
            }
        }
#endif

        if (::close(ss_fd) < 0) {
            WARNING_NO("Failed to close socket %d", ss_fd);
        }
    }

    if ((pollidx = ss_pollidx) >= pollnfds) {
        ERROR("Pollset error: index %d is greater than number of fds %d!", pollidx, pollnfds);
    }

    ss_fd = -1;
    ss_invalid = true;
    ss_pollidx = -1;

    /* Adds call sockets in the array */
    assert(pollnfds > 0);

    pollnfds--;
#ifdef HAVE_EPOLL
    if (pollidx < pollnfds) {
        epollfiles[pollidx] = epollfiles[pollnfds];
        epollfiles[pollidx].data.u32 = pollidx;
        if (sockets[pollnfds]->ss_fd != -1) {
            int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, sockets[pollnfds]->ss_fd, &epollfiles[pollidx]);
            if ((rc == -1) && (errno != EPERM)) {
                // Ignore "Operation not supported"  errors -
                // otherwise we get log spam when redirecting stdout
                // to /dev/null
                WARNING_NO("Failed to update FD within epoll");
            }
        }
    }
#else
    pollfiles[pollidx] = pollfiles[pollnfds];
#endif
    /* If unequal, move the last valid socket here. */
    if (pollidx != pollnfds) {
        sockets[pollidx] = sockets[pollnfds];
        sockets[pollidx]->ss_pollidx = pollidx;
    }
    sockets[pollnfds] = nullptr;

    if (ss_msglen) {
        pending_messages--;
    }

#ifdef USE_SCTP
    if (ss_transport == T_SCTP) {
        sctpstate = SCTP_DOWN;
    }
#endif
}

void SIPpSocket::abort() {
    /* Disable linger - we'll send a RST when we close. */
    struct linger flush;
    flush.l_onoff = 1;
    flush.l_linger = 0;
    setsockopt(ss_fd, SOL_SOCKET, SO_LINGER, &flush, sizeof(flush));

    /* Mark the socket as non-blocking.  It's not clear whether this is required but can't hurt. */
    int flags = fcntl(ss_fd, F_GETFL, 0);
    fcntl(ss_fd, F_SETFL, flags | O_NONBLOCK);

    int count = --ss_count;
    if (count == 0) {
        invalidate();
        sockets_pending_reset.erase(this);
        delete this;
    } else {
        ss_fd = -1;
    }
}

void SIPpSocket::close()
{
    int count = --ss_count;

    if (count == 0) {
        invalidate();
        sockets_pending_reset.erase(this);
        delete this;
    }
}

ssize_t SIPpSocket::read_message(char *buf, size_t len, struct sockaddr_storage *src)
{
    size_t avail;

    if (!ss_msglen)
        return 0;
    if (ss_msglen > len)
        ERROR("There is a message waiting in sockfd(%d) that is bigger (%zu bytes) than the read size.",
              ss_fd, ss_msglen);

    len = ss_msglen;

    avail = ss_in->len - ss_in->offset;
    if (avail > len) {
        avail = len;
    }

    memcpy(buf, ss_in->buf + ss_in->offset, avail);
    memcpy(src, &ss_in->addr, sizeof(ss_in->addr));

    /* Update our buffer and return value. */
    buf[avail] = '\0';
    /* For CMD Message the escape char is the end of message */
    if ((ss_control) && buf[avail-1] == 27)
        buf[avail-1] = '\0';

    ss_in->offset += avail;

    /* Have we emptied the buffer? */
    if (ss_in->offset == ss_in->len) {
        struct socketbuf *next = ss_in->next;
        free_socketbuf(ss_in);
        ss_in = next;
    }

    if (int msg_len = check_for_message()) {
        ss_msglen = msg_len;
    } else {
        ss_msglen = 0;
        pending_messages--;
    }

    return avail;
}

void process_message(SIPpSocket *socket, char *msg, ssize_t msg_size, struct sockaddr_storage *src)
{
    // TRACE_MSG(" msg_size %d and pollset_index is %d \n", msg_size, pollset_index));
    if (msg_size <= 0) {
        return;
    }
    if (sipMsgCheck(msg, socket) == false) {
        if (msg_size == 4 &&
                (memcmp(msg, "\r\n\r\n", 4) == 0 || memcmp(msg, "\x00\x00\x00\x00", 4) == 0)) {
            /* Common keepalives */;
        } else {
            WARNING("non SIP message discarded: \"%.*s\" (%zu)", (int)msg_size, msg, msg_size);
        }
        return;
    }

    const char *call_id = get_trimmed_call_id(msg);
    if (call_id[0] == '\0') {
        WARNING("SIP message without Call-ID discarded");
        return;
    }
    listener *listener_ptr = get_listener(call_id);
    struct timeval currentTime;
    GET_TIME (&currentTime);

    if (useShortMessagef == 1) {
        TRACE_SHORTMSG("%s\tR\t%s\tCSeq:%s\t%s\n",
                       CStat::formatTime(&currentTime), call_id, get_header_content(msg, "CSeq:"), get_first_line(msg));
    }

    if (useMessagef == 1) {
        TRACE_MSG("----------------------------------------------- %s\n"
                  "%s %smessage received [%zu] bytes :\n\n%s\n",
                  CStat::formatTime(&currentTime, true),
                  TRANSPORT_TO_STRING(socket->ss_transport),
                  socket->ss_control ? "control " : "",
                  msg_size, msg);
    }

    // got as message not relating to a known call
    if (!listener_ptr) {
        if (thirdPartyMode == MODE_3PCC_CONTROLLER_B || thirdPartyMode == MODE_3PCC_A_PASSIVE ||
                thirdPartyMode == MODE_MASTER_PASSIVE || thirdPartyMode == MODE_SLAVE) {
            // Adding a new OUTGOING call !
            main_scenario->stats->computeStat(CStat::E_CREATE_OUTGOING_CALL);
            call *new_ptr = new call(main_scenario, call_id, local_ip_is_ipv6, 0, use_remote_sending_addr ? &remote_sending_sockaddr : &remote_sockaddr);

            outbound_congestion = false;
            if ((socket != main_socket) &&
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
        } else if (creationMode == MODE_SERVER) {
            if (quitting >= 1) {
                CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                TRACE_MSG("Discarded message for new calls while quitting\n");
                return;
            }

            // Adding a new INCOMING call !
            main_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
            listener_ptr = new call(main_scenario, call_id, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src);
        } else if(creationMode == MODE_MIXED) {
            /* Ignore quitting for now ... as this is triggered when all tx calls are active
            if (quitting >= 1) {
                CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                TRACE_MSG("Discarded message for new calls while quitting\n");
                return;
            }
            */
            // Adding a new INCOMING call !
            rx_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
            listener_ptr = new call(rx_scenario, call_id, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src);
        } else { // mode != from SERVER and 3PCC Controller B
            // This is a message that is not relating to any known call
            if (ooc_scenario) {
                if (!get_reply_code(msg)) {
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
                    CStat::globalStat(CStat::E_AUTO_ANSWERED);
                    call_ptr->process_incoming(msg, src);
                } else {
                    /* We received a response not relating to any known call */
                    /* Do nothing, even if in auto answer mode */
                    CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                }
            } else if (auto_answer &&
                       ((strstr(msg, "INFO") == msg) ||
                        (strstr(msg, "NOTIFY") == msg) ||
                        (strstr(msg, "OPTIONS") == msg) ||
                        (strstr(msg, "UPDATE") == msg))) {
                // If auto answer mode, try to answer the incoming message
                // with automaticResponseMode
                // call is discarded before exiting the block
                if (!get_reply_code(msg)) {
                    aa_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
                    /* This should have the real address that the message came from. */
                    call *call_ptr = new call(aa_scenario, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src, call_id, 0 /* no user. */, socket->ss_ipv6, true, false);
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

    if ((socket == localTwinSippSocket) || (socket == twinSippSocket) || (is_a_local_socket(socket))) {
        listener_ptr -> process_twinSippCom(msg);
    } else {
        /* This is a message on a known call - process it */
        listener_ptr -> process_incoming(msg, src);
    }
}

SIPpSocket::SIPpSocket(bool use_ipv6, int transport, int fd, int accepting):
    ss_count(1),
    ss_ipv6(use_ipv6),
    ss_transport(transport),
    ss_control(false),
    ss_fd(fd),
    ss_bind_port(0),
    ss_comp_state(nullptr),
    ss_changed_dest(false),
    ss_congested(false),
    ss_invalid(false),
    ss_in(nullptr),
    ss_out(nullptr),
    ss_out_tail(nullptr),
    ss_msglen(0)
{
    /* Initialize all sockets with our destination address. */
    memcpy(&ss_dest, &remote_sockaddr, sizeof(ss_dest));

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    ss_ssl = nullptr;

    if (transport == T_TLS) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        if ((ss_bio = BIO_new_socket(fd, BIO_NOCLOSE)) == nullptr) {
            ERROR("Unable to create BIO object:Problem with BIO_new_socket()");
        }

        if (!(ss_ssl = (accepting ? SSL_new_server() : SSL_new_client()))) {
            ERROR("Unable to create SSL object : Problem with SSL_new()");
        }

        SSL_set_bio(ss_ssl, ss_bio, ss_bio);
    }
#endif
    /* Store this socket in the tables. */
    ss_pollidx = pollnfds++;
    sockets[ss_pollidx] = this;
#ifdef HAVE_EPOLL
    epollfiles[ss_pollidx].data.u32 = ss_pollidx;
    epollfiles[ss_pollidx].events   = EPOLLIN;
    int rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, ss_fd, &epollfiles[ss_pollidx]);
    if (rc == -1) {
        if (errno == EPERM) {
            // Attempted to use epoll on a file that does not support
            // it - this may happen legitimately when stdin/stdout is
            // redirected to /dev/null, so don't warn
        } else {
            ERROR_NO("Failed to add FD to epoll");
        }
    }
#else
    pollfiles[ss_pollidx].fd      = ss_fd;
    pollfiles[ss_pollidx].events  = POLLIN | POLLERR;
    pollfiles[ss_pollidx].revents = 0;
#endif
}

static SIPpSocket* sipp_allocate_socket(bool use_ipv6, int transport, int fd) {
    return new SIPpSocket(use_ipv6, transport, fd, 0);
}

static int socket_fd(bool use_ipv6, int transport)
{
    int socket_type = -1;
    int protocol = 0;
    int fd;

    switch(transport) {
    case T_UDP:
        socket_type = SOCK_DGRAM;
        protocol = IPPROTO_UDP;
        break;
    case T_SCTP:
#ifndef USE_SCTP
        ERROR("You do not have SCTP support enabled!");
#else
        socket_type = SOCK_STREAM;
        protocol = IPPROTO_SCTP;
#endif
        break;
    case T_TLS:
#ifndef USE_TLS
        ERROR("You do not have TLS support enabled!");
#endif
    case T_TCP:
        socket_type = SOCK_STREAM;
        protocol = IPPROTO_TCP;
        break;
    }

    if ((fd = socket(use_ipv6 ? AF_INET6 : AF_INET, socket_type, protocol))== -1) {
        ERROR_NO("Unable to get a %s socket (3)", TRANSPORT_TO_STRING(transport));
    }

    return fd;
}

SIPpSocket *new_sipp_socket(bool use_ipv6, int transport) {
    SIPpSocket *ret;
    int fd = socket_fd(use_ipv6, transport);

    ret = sipp_allocate_socket(use_ipv6, transport, fd);
    if (!ret) {
        close(fd);
        ERROR("Could not allocate new socket structure!");
    }
    return ret;
}

SIPpSocket* SIPpSocket::new_sipp_call_socket(bool use_ipv6, int transport, bool *existing) {
    SIPpSocket *sock = nullptr;
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

SIPpSocket* SIPpSocket::accept() {
    SIPpSocket *ret;
    struct sockaddr_storage remote_sockaddr;
    int fd;
    sipp_socklen_t addrlen = sizeof(remote_sockaddr);

    if ((fd = ::accept(ss_fd, (struct sockaddr *)&remote_sockaddr, &addrlen))== -1) {
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
            ::close(fd);
        }
        fd = newfd;
    }
#endif

    ret = new SIPpSocket(ss_ipv6, ss_transport, fd, 1);

    /* We should connect back to the address which connected to us if we
     * experience a TCP failure. */
    memcpy(&ret->ss_dest, &remote_sockaddr, sizeof(ret->ss_dest));

    if (ret->ss_transport == T_TLS) {
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        int rc;
        int i = 0;
        while ((rc = SSL_accept(ret->ss_ssl)) < 0) {
            int err = SSL_get_error(ret->ss_ssl, rc);
            if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
                    i < SIPP_SSL_MAX_RETRIES) {
                /* These errors are benign we just need to wait for the socket
                 * to be readable/writable again. */
                WARNING("SSL_accept failed with error: %s. Attempt %d. "
                        "Retrying...", SSL_error_string(err, rc), ++i);
                sipp_usleep(SIPP_SSL_RETRY_TIMEOUT);
                continue;
            }
            ERROR("Error in SSL_accept: %s",
                  SSL_error_string(err, rc));
            break;
        }
#else
        ERROR("You need to compile SIPp with TLS support");
#endif
    }
    return ret;
}

int sipp_bind_socket(SIPpSocket *socket, struct sockaddr_storage *saddr, int *port)
{
    int ret;
    int len;


#ifdef USE_SCTP
    if (transport == T_SCTP && multisocket == 1 && port && *port == -1) {
        sockaddr_update_port(saddr, 0);
    }
#endif

    if (socket->ss_ipv6) {
        len = sizeof(struct sockaddr_in6);
    } else {
        len = sizeof(struct sockaddr_in);
    }

    if ((ret = ::bind(socket->ss_fd, (sockaddr *)saddr, len))) {
        return ret;
    }

    if (!port) {
        return 0;
    }

    if ((ret = getsockname(socket->ss_fd, (sockaddr *)saddr, (sipp_socklen_t *) &len))) {
        return ret;
    }

    if (socket->ss_ipv6) {
        socket->ss_port = ntohs((short)((_RCAST(struct sockaddr_in6 *, saddr))->sin6_port));
    } else {
        socket->ss_port = ntohs((short)((_RCAST(struct sockaddr_in *, saddr))->sin_port));
    }
    *port = socket->ss_port;

#ifdef USE_SCTP
    if (transport == T_SCTP) {
        bool isany = false;
        if (socket->ss_ipv6) {
            if (memcmp(&(_RCAST(struct sockaddr_in6 *, saddr)->sin6_addr), &in6addr_any, sizeof(in6_addr)) == 0)
                isany = true;
        } else {
            isany = (_RCAST(struct sockaddr_in *, saddr)->sin_addr.s_addr == INADDR_ANY);
        }
        if (!isany) {
            set_multihome_addr(socket, *port);
        }
    }
#endif

    return 0;
}

void SIPpSocket::set_bind_port(int bind_port)
{
    ss_bind_port = bind_port;
}

int SIPpSocket::connect(struct sockaddr_storage* dest)
{
    if (dest)
    {
        memcpy(&ss_dest, dest, sizeof(*dest));
    }

    int ret;

    assert(ss_transport == T_TCP || ss_transport == T_TLS || ss_transport == T_SCTP);

    if (ss_transport == T_TCP || ss_transport == T_TLS) {
        struct sockaddr_storage with_optional_port;
        int port = -1;
        memcpy(&with_optional_port, &local_sockaddr, sizeof(struct sockaddr_storage));
        if (local_ip_is_ipv6) {
            (_RCAST(struct sockaddr_in6*, &with_optional_port))->sin6_port = htons(ss_bind_port);
        } else {
            (_RCAST(struct sockaddr_in*, &with_optional_port))->sin_port = htons(ss_bind_port);
        }
        sipp_bind_socket(this, &with_optional_port, &port);
#ifdef USE_SCTP
    } else if (ss_transport == T_SCTP) {
        int port = -1;
        sipp_bind_socket(this, &local_sockaddr, &port);
#endif
    }

    int flags = fcntl(ss_fd, F_GETFL, 0);
    fcntl(ss_fd, F_SETFL, flags | O_NONBLOCK);

    errno = 0;
    ret = ::connect(ss_fd, _RCAST(struct sockaddr *, &ss_dest), socklen_from_addr(&ss_dest));
    if (ret < 0) {
        if (errno == EINPROGRESS) {
            /* Block this socket until the connect completes - this is very similar to entering congestion, but we don't want to increment congestion statistics. */
            enter_congestion(0);
            nb_net_cong--;
        } else {
            return ret;
        }
    }

    fcntl(ss_fd, F_SETFL, flags);

    if (ss_transport == T_TLS) {
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        int rc;
        int i = 0;
        while ((rc = SSL_connect(ss_ssl)) < 0) {
            int err = SSL_get_error(ss_ssl, rc);
            if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
                    i < SIPP_SSL_MAX_RETRIES) {
                /* These errors are benign we just need to wait for the socket
                 * to be readable/writable again. */
                WARNING("SSL_connect failed with error: %s. Attempt %d. "
                        "Retrying...", SSL_error_string(err, rc), ++i);
                sipp_usleep(SIPP_SSL_RETRY_TIMEOUT);
                continue;
            }
            WARNING("Error in SSL connection: %s", SSL_error_string(err, rc));
            invalidate();
            return err;
        }
#else
        ERROR("You need to compile SIPp with TLS support");
#endif
    }

#ifdef USE_SCTP
    if (ss_transport == T_SCTP) {
        sctpstate = SCTP_CONNECTING;
    }
#endif

    return 0;
}


int SIPpSocket::reconnect()
{
    if ((!ss_invalid) &&
            (ss_fd != -1)) {
        WARNING("When reconnecting socket, already have file descriptor %d", ss_fd);
        abort();
    }

    ss_fd = socket_fd(ss_ipv6, ss_transport);
    if (ss_fd == -1) {
        ERROR_NO("Could not obtain new socket: ");
    }

    if (ss_invalid) {
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        ss_ssl = nullptr;

        if (transport == T_TLS) {
            if ((ss_bio = BIO_new_socket(ss_fd, BIO_NOCLOSE)) == nullptr) {
                ERROR("Unable to create BIO object:Problem with BIO_new_socket()");
            }

            if (!(ss_ssl = SSL_new_client())) {
                ERROR("Unable to create SSL object : Problem with SSL_new()");
            }

            SSL_set_bio(ss_ssl, ss_bio, ss_bio);
        }
#endif

        /* Store this socket in the tables. */
        ss_pollidx = pollnfds++;
        sockets[ss_pollidx] = this;
#ifdef HAVE_EPOLL
        epollfiles[ss_pollidx].data.u32 = ss_pollidx;
        epollfiles[ss_pollidx].events   = EPOLLIN;
#else
        pollfiles[ss_pollidx].fd      = ss_fd;
        pollfiles[ss_pollidx].events  = POLLIN | POLLERR;
        pollfiles[ss_pollidx].revents = 0;
#endif

        ss_invalid = false;
    }

#ifdef HAVE_EPOLL
    int rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, ss_fd, &epollfiles[ss_pollidx]);
    if (rc == -1) {
        ERROR_NO("Failed to add FD to epoll");
    }
#endif
    return connect();
}

#ifdef SO_BINDTODEVICE
int SIPpSocket::bind_to_device(const char* device_name) {
    if (setsockopt(this->ss_fd, SOL_SOCKET, SO_BINDTODEVICE,
                   device_name, strlen(device_name)) == -1) {
        ERROR_NO("setsockopt(SO_BINDTODEVICE) failed");
    }
    return 0;
}
#endif


/*************************** I/O functions ***************************/

/* Allocate a socket buffer. */
struct socketbuf *alloc_socketbuf(char *buffer, size_t size, int copy, struct sockaddr_storage *dest)
{
    struct socketbuf *socketbuf;

    socketbuf = (struct socketbuf *)malloc(sizeof(struct socketbuf));
    if (!socketbuf) {
        ERROR("Could not allocate socket buffer!");
    }
    memset(socketbuf, 0, sizeof(struct socketbuf));
    if (copy) {
        socketbuf->buf = (char *)malloc(size);
        if (!socketbuf->buf) {
            ERROR("Could not allocate socket buffer data!");
        }
        memcpy(socketbuf->buf, buffer, size);
    } else {
        socketbuf->buf = buffer;
    }
    socketbuf->len = size;
    socketbuf->offset = 0;
    if (dest) {
        memcpy(&socketbuf->addr, dest, sizeof(*dest));
    }
    socketbuf->next = nullptr;

    return socketbuf;
}

/* Free a poll buffer. */
void free_socketbuf(struct socketbuf *socketbuf)
{
    free(socketbuf->buf);
    free(socketbuf);
}

#ifdef USE_SCTP
void SIPpSocket::sipp_sctp_peer_params()
{
    if (heartbeat > 0 || pathmaxret > 0) {
        struct sctp_paddrparams peerparam;
        memset(&peerparam, 0, sizeof(peerparam));

        sockaddr* addresses;
#ifdef __SUNOS
        /* Sun takes a void** instead of a struct sockaddr** */
        int addresscount = sctp_getpaddrs(ss_fd, 0, (void**)&addresses);
#else
        int addresscount = sctp_getpaddrs(ss_fd, 0, &addresses);
#endif
        if (addresscount < 1) WARNING("sctp_getpaddrs, errno=%d", errno);

        for (int i = 0; i < addresscount; i++) {
            memset(&peerparam.spp_address, 0, sizeof(peerparam.spp_address));
            struct sockaddr_storage* peeraddress = (struct sockaddr_storage*) &addresses[i];
            memcpy(&peerparam.spp_address, peeraddress, sizeof(*peeraddress));

            peerparam.spp_hbinterval = heartbeat;
            peerparam.spp_pathmaxrxt = pathmaxret;
            if (heartbeat > 0) peerparam.spp_flags = SPP_HB_ENABLE;

            if (pmtu > 0) {
                peerparam.spp_pathmtu = pmtu;
                peerparam.spp_flags |= SPP_PMTUD_DISABLE;
            }

            if (setsockopt(ss_fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                           &peerparam, sizeof(peerparam)) == -1) {
                sctp_freepaddrs(addresses);
                WARNING("setsockopt(SCTP_PEER_ADDR_PARAMS) failed, errno=%d", errno);
            }
        }
        sctp_freepaddrs(addresses);
    }
}
#endif

void sipp_customize_socket(SIPpSocket *socket)
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
            if (setsockopt(socket->ss_fd, IPPROTO_SCTP, SCTP_EVENTS, &event,
                           sizeof(event)) == -1) {
                ERROR_NO("setsockopt(SCTP_EVENTS) failed, errno=%d", errno);
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
    if (setsockopt(socket->ss_fd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &buffsize,
                   sizeof(buffsize))) {
        ERROR_NO("Unable to set socket sndbuf");
    }

    buffsize = buff_size;
    if (setsockopt(socket->ss_fd,
                   SOL_SOCKET,
                   SO_RCVBUF,
                   &buffsize,
                   sizeof(buffsize))) {
        ERROR_NO("Unable to set socket rcvbuf");
    }
}

/* This socket is congested, mark it as such and add it to the poll files. */
int SIPpSocket::enter_congestion(int again)
{
    if (!ss_congested) {
        nb_net_cong++;
    }
    ss_congested = true;

    TRACE_MSG("Problem %s on socket  %d and poll_idx  is %d \n",
              again == EWOULDBLOCK ? "EWOULDBLOCK" : "EAGAIN",
              ss_fd, ss_pollidx);
#ifdef HAVE_EPOLL
    epollfiles[ss_pollidx].events |= EPOLLOUT;
    int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, ss_fd, &epollfiles[ss_pollidx]);
    if (rc == -1) {
        WARNING_NO("Failed to set EPOLLOUT");
    }
#else
    pollfiles[ss_pollidx].events |= POLLOUT;
#endif

#ifdef USE_SCTP
    if (ss_transport == T_SCTP && sctpstate == SCTP_CONNECTING)
        return 0;
#endif
    return -1;
}

int SIPpSocket::write_error(int ret)
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

    if (again) {
        return enter_congestion(again);
    }

    if ((ss_transport == T_TCP || ss_transport == T_SCTP)
            && errno == EPIPE) {
        nb_net_send_errors++;
        sockets_pending_reset.insert(this);
        abort();
        if (reconnect_allowed()) {
            WARNING("Broken pipe on TCP connection, remote peer "
                    "probably closed the socket");
        } else {
            ERROR("Broken pipe on TCP connection, remote peer "
                  "probably closed the socket");
        }
        return -1;
    }

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    if (ss_transport == T_TLS) {
        errstring = SSL_error_string(SSL_get_error(ss_ssl, ret), ret);
    }
#endif

    WARNING("Unable to send %s message: %s", TRANSPORT_TO_STRING(ss_transport), errstring);
    nb_net_send_errors++;
    return -1;
}

int SIPpSocket::read_error(int ret)
{
    const char *errstring = strerror(errno);
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    if (ss_transport == T_TLS) {
        int err = SSL_get_error(ss_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* This is benign - we just need to wait for the socket to be
             * readable/writable again, which will happen naturally as part
             * of the poll/epoll loop. */
            WARNING("SSL_read failed with error: %s. Retrying...",
                    SSL_error_string(err, ret));
            return 1;
        }
    }
#endif

    assert(ret <= 0);

#ifdef EAGAIN
    /* Scrub away EAGAIN from the rest of the code. */
    if (errno == EAGAIN) {
        errno = EWOULDBLOCK;
    }
#endif

    /* We have only non-blocking reads, so this should not occur. The OpenSSL
     * functions don't set errno, though, so this check doesn't make sense
     * for TLS sockets. */
    if (ret < 0 && ss_transport != T_TLS) {
        assert(errno != EAGAIN);
    }

    if (ss_transport == T_TCP || ss_transport == T_TLS) {
        if (ret == 0) {
            /* The remote side closed the connection. */
            if (ss_control) {
                if (localTwinSippSocket)
                    localTwinSippSocket->close();
                if (extendedTwinSippMode) {
                    close_peer_sockets();
                    close_local_sockets();
                    free_peer_addr_map();
                    WARNING("One of the twin instances has ended -> exiting");
                    quitting += 20;
                } else if (twinSippMode) {
                    if (twinSippSocket)
                        twinSippSocket->close();
                    if (thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
                        WARNING("3PCC controller A has ended -> exiting");
                        quitting += 20;
                    } else {
                        quitting = 1;
                    }
                }
            } else {
                /* The socket was closed "cleanly", but we may have calls that need to
                 * be destroyed.  Also, if these calls are not complete, and attempt to
                 * send again we may "resurrect" the socket by reconnecting it.*/
                invalidate();
                if (reset_close) {
                    close_calls();
                }
            }
            return 0;
        }

        sockets_pending_reset.insert(this);
        abort();

        nb_net_recv_errors++;
        if (reconnect_allowed()) {
            WARNING("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
        } else {
            ERROR("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
        }
        return -1;
    }

    WARNING("Unable to receive %s message: %s", TRANSPORT_TO_STRING(ss_transport), errstring);
    nb_net_recv_errors++;
    return -1;
}

void SIPpSocket::buffer_write(const char *buffer, size_t len, struct sockaddr_storage *dest)
{
    struct socketbuf *buf = ss_out;

    if (!buf) {
        ss_out = alloc_socketbuf(const_cast<char*>(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
        ss_out_tail = ss_out;
        TRACE_MSG("Added first buffered message to socket %d\n", ss_fd);
        return;
    }

    ss_out_tail->next = alloc_socketbuf(const_cast<char*>(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
    ss_out_tail = ss_out_tail->next;
    TRACE_MSG("Appended buffered message to socket %d\n", ss_fd);
}

void SIPpSocket::buffer_read(struct socketbuf *newbuf)
{
    struct socketbuf *buf = ss_in;
    struct socketbuf *prev = buf;

    if (!buf) {
        ss_in = newbuf;
        return;
    }

    while (buf->next) {
        prev = buf;
        buf = buf->next;
    }

    prev->next = newbuf;
}

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)

static int send_nowait_tls(SSL* ssl, const void* msg, int len, int /*flags*/)
{
    int initial_fd_flags;
    int rc;
    int fd;
    int fd_flags;
    int i = 0;
    if ((fd = SSL_get_fd(ssl)) == -1) {
        return -1;
    }
    fd_flags = fcntl(fd, F_GETFL, nullptr);
    initial_fd_flags = fd_flags;
    fd_flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, fd_flags);
    while ((rc = SSL_write(ssl, msg, len)) < 0) {
        int err = SSL_get_error(ssl, rc);
        if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
                i < SIPP_SSL_MAX_RETRIES) {
            /* These errors are benign we just need to wait for the socket
             * to be readable/writable again. */
            WARNING("SSL_write failed with error: %s. Attempt %d. "
                    "Retrying...", SSL_error_string(err, rc), ++i);
            sipp_usleep(SIPP_SSL_RETRY_TIMEOUT);
            continue;
        }
        return rc;
    }
    if (rc == 0) {
        return rc;
    }
    fcntl(fd, F_SETFL, initial_fd_flags);
    return rc;
}
#endif

static int send_nowait(int s, const void* msg, int len, int flags)
{
#if defined(MSG_DONTWAIT) && !defined(__SUNOS)
    return send(s, msg, len, flags | MSG_DONTWAIT);
#else
    int fd_flags = fcntl(s, F_GETFL , nullptr);
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
    int fd_flags = fcntl(s, F_GETFL, nullptr);
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

ssize_t SIPpSocket::write_primitive(const char* buffer, size_t len,
                                    struct sockaddr_storage* dest)
{
    ssize_t rc;

    /* Refuse to write to invalid sockets. */
    if (ss_invalid) {
        WARNING("Returning EPIPE on invalid socket: %p (%d)", _RCAST(void*, this), ss_fd);
        errno = EPIPE;
        return -1;
    }

    /* Always check congestion before sending. */
    if (ss_congested) {
        errno = EWOULDBLOCK;
        return -1;
    }

    switch(ss_transport) {
    case T_TLS:
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        rc = send_nowait_tls(ss_ssl, buffer, len, 0);
#else
        errno = EOPNOTSUPP;
        rc = -1;
#endif
        break;
    case T_SCTP:
#ifdef USE_SCTP
        TRACE_MSG("socket_write_primitive %d\n", sctpstate);
        if (sctpstate == SCTP_DOWN) {
            errno = EPIPE;
            return -1;
        } else if (sctpstate == SCTP_CONNECTING) {
            errno = EWOULDBLOCK;
            return -1;
        }
        rc = send_sctp_nowait(ss_fd, buffer, len, 0);
#else
        errno = EOPNOTSUPP;
        rc = -1;
#endif
        break;
    case T_TCP:
        rc = send_nowait(ss_fd, buffer, len, 0);
        break;

    case T_UDP:
        if (compression) {
            static char comp_msg[SIPP_MAX_MSG_SIZE];
            strncpy(comp_msg, buffer, sizeof(comp_msg) - 1);
            if (comp_compress(&ss_comp_state,
                              comp_msg,
                              (unsigned int *) &len) != COMP_OK) {
                ERROR("Compression plugin error");
            }
            buffer = (char *)comp_msg;

            TRACE_MSG("---\nCompressed message len: %zu\n", len);
        }

        rc = sendto(ss_fd, buffer, len, 0, _RCAST(struct sockaddr*, dest),
                    socklen_from_addr(dest));
        break;

    default:
        ERROR("Internal error, unknown transport type %d", ss_transport);
    }

    return rc;
}

/* Flush any output buffers for this socket. */
int SIPpSocket::flush()
{
    struct socketbuf *buf;
    int ret;

    while ((buf = ss_out)) {
        ssize_t size = buf->len - buf->offset;
        ret = write_primitive(buf->buf + buf->offset, size, &buf->addr);
        TRACE_MSG("Wrote %d of %zu bytes in an output buffer.\n", ret, size);
        if (ret == size) {
            /* Everything is great, throw away this buffer. */
            ss_out = buf->next;
            free_socketbuf(buf);
        } else if (ret <= 0) {
            /* Handle connection closes and errors. */
            return write_error(ret);
        } else {
            /* We have written more of the partial buffer. */
            buf->offset += ret;
            errno = EWOULDBLOCK;
            enter_congestion(EWOULDBLOCK);
            return -1;
        }
    }

    return 0;
}

/* Write data to a socket. */
int SIPpSocket::write(const char *buffer, ssize_t len, int flags, struct sockaddr_storage *dest)
{
    int rc;

    if (ss_out) {
        rc = flush();
        TRACE_MSG("Attempted socket flush returned %d\r\n", rc);
        if (rc < 0) {
            if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
                buffer_write(buffer, len, dest);
                return len;
            } else {
                return rc;
            }
        }
    }

    rc = write_primitive(buffer, len, dest);
    struct timeval currentTime;
    GET_TIME (&currentTime);

    if (rc == len) {
        /* Everything is great. */
        if (useMessagef == 1) {
            TRACE_MSG("----------------------------------------------- %s\n"
                      "%s %smessage sent (%zu bytes):\n\n%.*s\n",
                      CStat::formatTime(&currentTime, true),
                      TRANSPORT_TO_STRING(ss_transport),
                      ss_control ? "control " : "",
                      len, (int)len, buffer);
        }

        if (useShortMessagef == 1) {
            char *msg = strdup(buffer);
            const char *call_id = get_trimmed_call_id(msg);
            TRACE_SHORTMSG("%s\tS\t%s\tCSeq:%s\t%s\n",
                           CStat::formatTime(&currentTime), call_id, get_header_content(msg, "CSeq:"), get_first_line(msg));
            free(msg);
        }

    } else if (rc <= 0) {
        if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
            buffer_write(buffer, len, dest);
            enter_congestion(errno);
            return len;
        }
        if (useMessagef == 1) {
            TRACE_MSG("----------------------------------------------- %s\n"
                      "Error sending %s message:\n\n%.*s\n",
                      CStat::formatTime(&currentTime, true),
                      TRANSPORT_TO_STRING(ss_transport),
                      (int)len, buffer);
        }
        return write_error(errno);
    } else {
        /* We have a truncated message, which must be handled internally to the write function. */
        if (useMessagef == 1) {
            TRACE_MSG("----------------------------------------------- %s\n"
                      "Truncation sending %s message (%d of %zu sent):\n\n%.*s\n",
                      CStat::formatTime(&currentTime, true),
                      TRANSPORT_TO_STRING(ss_transport),
                      rc, len, (int)len, buffer);
        }
        buffer_write(buffer + rc, len - rc, dest);
        enter_congestion(errno);
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

void SIPpSocket::reset_connection()
{
    if (!reconnect_allowed()) {
        ERROR_NO("Max number of reconnections reached");
    }

    if (reset_number != -1) {
        reset_number--;
    }

    if (reset_close) {
        WARNING("Closing calls, because of TCP reset or close!");
        close_calls();
    }

    /* Sleep for some period of time before the reconnection. */
    usleep(1000 * reset_sleep);

    if (reconnect() < 0) {
        WARNING_NO("Could not reconnect TCP socket");
        close_calls();
    } else {
        WARNING("Socket required a reconnection.");
    }
}

/* Close just those calls for a given socket (e.g., if the remote end closes
 * the connection. */
void SIPpSocket::close_calls()
{
    owner_list *owners = get_owners_for_socket(this);
    owner_list::iterator owner_it;
    socketowner *owner_ptr = nullptr;

    for (owner_it = owners->begin(); owner_it != owners->end(); owner_it++) {
        owner_ptr = *owner_it;
        if (owner_ptr) {
            owner_ptr->tcpClose();
        }
    }

    delete owners;
}

int open_connections()
{
    int status=0;
    int family_hint = PF_UNSPEC;
    local_port = 0;

    if (!strlen(remote_host)) {
        if ((sendMode != MODE_SERVER)) {
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
            fprintf(stderr, "Resolving remote host '%s'... ", remote_host);
            struct addrinfo   hints;

            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = AF_UNSPEC;

#ifdef USE_LOCAL_IP_HINTS
            struct addrinfo * local_addr;
            int ret;
            if (strlen(local_ip)) {
                if ((ret = getaddrinfo(local_ip, nullptr, &hints, &local_addr)) != 0) {
                    ERROR("Can't get local IP address in getaddrinfo, "
                            "local_ip='%s', ret=%d", local_ip, ret);
                }

                /* Use local address hints when getting the remote */
                if (local_addr->ai_addr->sa_family == AF_INET6) {
                    local_ip_is_ipv6 = true;
                    hints.ai_family = AF_INET6;
                } else {
                    hints.ai_family = AF_INET;
                }
            }
#endif

            /* FIXME: add DNS SRV support using liburli? */
            if (gai_getsockaddr(&remote_sockaddr, remote_host, remote_port,
                                hints.ai_flags, hints.ai_family) != 0) {
                ERROR("Unknown remote host '%s'.\n"
                      "Use 'sipp -h' for details", remote_host);
            }

            get_inet_address(&remote_sockaddr, remote_ip, sizeof(remote_ip));
            family_hint = remote_sockaddr.ss_family;
            if (remote_sockaddr.ss_family == AF_INET) {
                strcpy(remote_ip_w_brackets, remote_ip);
            } else {
                sprintf(remote_ip_w_brackets, "[%.39s]", remote_ip);
            }
            fprintf(stderr, "Done.\n");
        }
    }

    {
        /* Yuck. Populate local_sockaddr with "our IP" first, and then
         * replace it with INADDR_ANY if we did not request a specific
         * IP to bind on. */
        bool bind_specific = false;
        memset(&local_sockaddr, 0, sizeof(struct sockaddr_storage));

        if (strlen(local_ip) || !strlen(remote_host)) {
            int ret;
            struct addrinfo * local_addr;
            struct addrinfo   hints;

            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = family_hint;

            if (strlen(local_ip)) {
                bind_specific = true;
            } else {
                /* Bind on gethostname() IP by default. This is actually
                 * buggy.  We should be able to bind on :: and decide on
                 * accept() what Contact IP we use.  Right now, if we do
                 * that, we'd send [::] in the contact and :: in the RTP
                 * as "our IP". */
                if (gethostname(local_ip, sizeof(local_ip)) != 0) {
                    ERROR_NO("Can't get local hostname");
                }
            }

            /* Resolving local IP */
            if ((ret = getaddrinfo(local_ip, nullptr, &hints, &local_addr)) != 0) {
              switch (ret) {
#ifdef EAI_ADDRFAMILY
                case EAI_ADDRFAMILY:
                    ERROR("Network family mismatch for local (%s) and remote (%s, %d) IP", local_ip, remote_ip, family_hint);
                    break;
#endif
                default:
                    ERROR("Can't get local IP address in getaddrinfo, "
                          "local_ip='%s', ret=%d", local_ip, ret);
              }
            }
            memcpy(&local_sockaddr, local_addr->ai_addr, local_addr->ai_addrlen);
            freeaddrinfo(local_addr);

            if (!bind_specific) {
                get_inet_address(&local_sockaddr, local_ip, sizeof(local_ip));
            }
        } else {
            /* Get temp socket on UDP to find out our local address */
            int tmpsock = -1;
            socklen_t len = sizeof(local_sockaddr);
            if ((tmpsock = socket(remote_sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) < 0 ||
                    ::connect(tmpsock, _RCAST(struct sockaddr*, &remote_sockaddr),
                              socklen_from_addr(&remote_sockaddr)) < 0 ||
                    getsockname(tmpsock, _RCAST(struct sockaddr*, &local_sockaddr), &len) < 0) {
                if (tmpsock >= 0) {
                    close(tmpsock);
                }
                ERROR_NO("Failed to find our local ip");
            }
            close(tmpsock);
            get_inet_address(&local_sockaddr, local_ip, sizeof(local_ip));
        }

        /* Store local addr info for rsa option */
        memcpy(&local_addr_storage, &local_sockaddr, sizeof(local_sockaddr));

        if (local_sockaddr.ss_family == AF_INET) {
            strcpy(local_ip_w_brackets, local_ip);
            if (!bind_specific) {
                _RCAST(struct sockaddr_in*, &local_sockaddr)->sin_addr.s_addr = INADDR_ANY;
            }
        } else {
            local_ip_is_ipv6 = true;
            sprintf(local_ip_w_brackets, "[%.39s]", local_ip);
            if (!bind_specific) {
                memcpy(&_RCAST(struct sockaddr_in6*, &local_sockaddr)->sin6_addr, &in6addr_any, sizeof(in6addr_any));
            }
        }
    }

    /* Creating and binding the local socket */
    if ((main_socket = new_sipp_socket(local_ip_is_ipv6, transport)) == nullptr) {
        ERROR_NO("Unable to get the local socket");
    }

    sipp_customize_socket(main_socket);

#ifdef SO_BINDTODEVICE
    /* Bind to the device if any. */
    if (bind_to_device_name) {
        main_socket->bind_to_device(bind_to_device_name);
    }
#endif

    /* Trying to bind local port */
    char peripaddr[256];
    if (!user_port) {
        unsigned short l_port;
        for (l_port = DEFAULT_PORT;
                l_port < (DEFAULT_PORT + 60);
                l_port++) {

            // Bind socket to local_ip
            if (bind_local || peripsocket) {
                if (peripsocket) {
                    // On some machines it fails to bind to the self computed local
                    // IP address.
                    // For the socket per IP mode, bind the main socket to the
                    // first IP address specified in the inject file.
                    inFiles[ip_file]->getField(0, peripfield, peripaddr, sizeof(peripaddr));
                    if (gai_getsockaddr(&local_sockaddr, peripaddr, nullptr,
                                        AI_PASSIVE, AF_UNSPEC) != 0) {
                        ERROR("Unknown host '%s'.\n"
                              "Use 'sipp -h' for details", peripaddr);
                    }
                } else {
                    if (gai_getsockaddr(&local_sockaddr, local_ip, nullptr,
                                        AI_PASSIVE, AF_UNSPEC) != 0) {
                        ERROR("Unknown host '%s'.\n"
                              "Use 'sipp -h' for details", peripaddr);
                    }
                }
            }
            sockaddr_update_port(&local_sockaddr, l_port);
            if (sipp_bind_socket(main_socket, &local_sockaddr, &local_port) == 0) {
                break;
            }
        }
    }

    if (!local_port) {
        /* Not already bound, use user_port of 0 to leave
         * the system choose a port. */

        if (bind_local || peripsocket) {
            if (peripsocket) {
                // On some machines it fails to bind to the self computed local
                // IP address.
                // For the socket per IP mode, bind the main socket to the
                // first IP address specified in the inject file.
                inFiles[ip_file]->getField(0, peripfield, peripaddr, sizeof(peripaddr));
                if (gai_getsockaddr(&local_sockaddr, peripaddr, nullptr,
                                    AI_PASSIVE, AF_UNSPEC) != 0) {
                    ERROR("Unknown host '%s'.\n"
                          "Use 'sipp -h' for details", peripaddr);
                }
            } else {
                if (gai_getsockaddr(&local_sockaddr, local_ip, nullptr,
                                    AI_PASSIVE, AF_UNSPEC) != 0) {
                    ERROR("Unknown host '%s'.\n"
                          "Use 'sipp -h' for details", peripaddr);
                }
            }
        }

        sockaddr_update_port(&local_sockaddr, user_port);
        if (sipp_bind_socket(main_socket, &local_sockaddr, &local_port)) {
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
        char peripaddr[256];
        SIPpSocket *sock;

        unsigned int lines = inFiles[ip_file]->numLines();
        for (unsigned int i = 0; i < lines; i++) {
            inFiles[ip_file]->getField(i, peripfield, peripaddr, sizeof(peripaddr));
            auto j = map_perip_fd.find(peripaddr);

            if (j == map_perip_fd.end()) {
                if (gai_getsockaddr(&server_sockaddr, peripaddr, local_port,
                                    AI_PASSIVE, AF_UNSPEC) != 0) {
                    ERROR("Unknown remote host '%s'.\n"
                          "Use 'sipp -h' for details", peripaddr);
                }

                bool is_ipv6 = (server_sockaddr.ss_family == AF_INET6);

                if ((sock = new_sipp_socket(is_ipv6, transport)) == nullptr) {
                    ERROR_NO("Unable to get server socket");
                }

                sipp_customize_socket(sock);
                if (sipp_bind_socket(sock, &server_sockaddr, nullptr)) {
                    ERROR_NO("Unable to bind server socket");
                }

                map_perip_fd[peripaddr] = sock;
            }
        }
    }

    if ((!multisocket) && (transport == T_TCP || transport == T_TLS || transport == T_SCTP) &&
            (sendMode != MODE_SERVER)) {
        if ((tcp_multiplex = new_sipp_socket(local_ip_is_ipv6, transport)) == nullptr) {
            ERROR_NO("Unable to get a TCP socket");
        }

        /* If there is a user-supplied local port and we use a single
         * socket, then bind to the specified port. */
        if (user_port) {
            tcp_multiplex->set_bind_port(local_port);
        }

        /* OJA FIXME: is it correct? */
        if (use_remote_sending_addr) {
            remote_sockaddr = remote_sending_sockaddr;
        }
        sipp_customize_socket(tcp_multiplex);

        /* This fixes local_port keyword value when transport are TCP|TLS and it's defined by user with "-p" */
        if (sipp_bind_socket(tcp_multiplex, &local_sockaddr, nullptr)) {
            ERROR_NO("Unable to bind TCP socket");
        }

        if (tcp_multiplex->connect(&remote_sockaddr)) {
            if (reset_number > 0) {
                WARNING("Failed to reconnect");
                main_socket->close();
                main_socket = nullptr;
                reset_number--;
                return 1;
            } else {
                if (errno == EINVAL) {
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


    if (transport == T_TCP || transport == T_TLS || transport == T_SCTP) {
        if (listen(main_socket->ss_fd, 100)) {
            ERROR_NO("Unable to listen main socket");
        }
    }

    /* Trying to connect to Twin Sipp in 3PCC mode */
    if (twinSippMode) {
        if (thirdPartyMode == MODE_3PCC_CONTROLLER_A || thirdPartyMode == MODE_3PCC_A_PASSIVE) {
            connect_to_peer(twinSippHost, twinSippPort, &twinSipp_sockaddr, twinSippIp, sizeof(twinSippIp), &twinSippSocket);
        } else if (thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
            connect_local_twin_socket(twinSippHost);
        } else {
            ERROR("TwinSipp Mode enabled but thirdPartyMode is different "
                  "from 3PCC_CONTROLLER_B and 3PCC_CONTROLLER_A\n");
        }
    } else if (extendedTwinSippMode) {
        if (thirdPartyMode == MODE_MASTER || thirdPartyMode == MODE_MASTER_PASSIVE) {
            strncpy(twinSippHost, get_peer_addr(master_name), sizeof(twinSippHost) - 1);
            get_host_and_port(twinSippHost, twinSippHost, &twinSippPort);
            connect_local_twin_socket(twinSippHost);
            connect_to_all_peers();
        } else if (thirdPartyMode == MODE_SLAVE) {
            strncpy(twinSippHost, get_peer_addr(slave_number), sizeof(twinSippHost) - 1);
            get_host_and_port(twinSippHost, twinSippHost, &twinSippPort);
            connect_local_twin_socket(twinSippHost);
        } else {
            ERROR("extendedTwinSipp Mode enabled but thirdPartyMode is different "
                  "from MASTER and SLAVE\n");
        }
    }

    return status;
}


static void connect_to_peer(
    char *peer_host, int peer_port, struct sockaddr_storage *peer_sockaddr,
    char *peer_ip, int peer_ip_size, SIPpSocket **peer_socket)
{
    /* Resolving the  peer IP */
    printf("Resolving peer address : %s...\n", peer_host);
    bool is_ipv6 = false;

    /* Resolving twin IP */
    if (gai_getsockaddr(peer_sockaddr, peer_host, peer_port,
                        AI_PASSIVE, AF_UNSPEC) != 0) {
        ERROR("Unknown peer host '%s'.\n"
              "Use 'sipp -h' for details", peer_host);
    }

    if (peer_sockaddr->ss_family == AF_INET6) {
        is_ipv6 = true;
    }

    get_inet_address(peer_sockaddr, peer_ip, peer_ip_size);

    if ((*peer_socket = new_sipp_socket(is_ipv6, T_TCP)) == nullptr) {
        ERROR_NO("Unable to get a twin sipp TCP socket");
    }

    /* Mark this as a control socket. */
    (*peer_socket)->ss_control = 1;

    if ((*peer_socket)->connect(peer_sockaddr)) {
        if (errno == EINVAL) {
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

SIPpSocket **get_peer_socket(char * peer) {
    peer_map::iterator peer_it;
    peer_it = peers.find(peer_map::key_type(peer));
    if (peer_it != peers.end()) {
        return &peer_it->second.peer_socket;
    } else {
        ERROR("get_peer_socket: Peer %s not found", peer);
    }
    return nullptr;
}

char * get_peer_addr(char * peer)
{
    char * addr;
    peer_addr_map::iterator peer_addr_it;
    peer_addr_it = peer_addrs.find(peer_addr_map::key_type(peer));
    if (peer_addr_it != peer_addrs.end()) {
        addr =  peer_addr_it->second;
        return addr;
    } else {
        ERROR("get_peer_addr: Peer %s not found", peer);
    }
    return nullptr;
}

bool is_a_peer_socket(SIPpSocket *peer_socket)
{
    peer_socket_map::iterator peer_socket_it;
    peer_socket_it = peer_sockets.find(peer_socket_map::key_type(peer_socket));
    if (peer_socket_it == peer_sockets.end()) {
        return false;
    } else {
        return true;
    }
}

void connect_local_twin_socket(char * twinSippHost)
{
    /* Resolving the listener IP */
    printf("Resolving listener address : %s...\n", twinSippHost);
    bool is_ipv6 = false;

    /* Resolving twin IP */
    if (gai_getsockaddr(&twinSipp_sockaddr, twinSippHost, twinSippPort,
                        AI_PASSIVE, AF_UNSPEC) != 0) {
        ERROR("Unknown twin host '%s'.\n"
              "Use 'sipp -h' for details", twinSippHost);
    }

    if (twinSipp_sockaddr.ss_family == AF_INET6) {
        is_ipv6 = true;
    }

    get_inet_address(&twinSipp_sockaddr, twinSippIp, sizeof(twinSippIp));

    if ((localTwinSippSocket = new_sipp_socket(is_ipv6, T_TCP)) == nullptr) {
        ERROR_NO("Unable to get a listener TCP socket ");
    }

    memset(&localTwin_sockaddr, 0, sizeof(struct sockaddr_storage));
    localTwin_sockaddr.ss_family = is_ipv6 ? AF_INET6 : AF_INET;
    sockaddr_update_port(&localTwin_sockaddr, twinSippPort);
    sipp_customize_socket(localTwinSippSocket);

    if (sipp_bind_socket(localTwinSippSocket, &localTwin_sockaddr, 0)) {
        ERROR_NO("Unable to bind twin sipp socket ");
    }

    if (listen(localTwinSippSocket->ss_fd, 100)) {
        ERROR_NO("Unable to listen twin sipp socket in ");
    }
}

void close_peer_sockets()
{
    peer_map::iterator peer_it, __end;
    for (peer_it = peers.begin(), __end = peers.end();
         peer_it != __end;
         ++peer_it) {
        T_peer_infos infos = peer_it->second;
        infos.peer_socket->close();
        infos.peer_socket = nullptr;
        peers[std::string(peer_it->first)] = infos;
    }

    peers_connected = 0;
}

void close_local_sockets()
{
    for (int i = 0; i< local_nb; i++) {
        local_sockets[i]->close();
        local_sockets[i] = nullptr;
    }
}

void connect_to_all_peers()
{
    peer_map::iterator peer_it;
    T_peer_infos infos;
    for (peer_it = peers.begin(); peer_it != peers.end(); peer_it++) {
        infos = peer_it->second;
        get_host_and_port(infos.peer_host, infos.peer_host, &infos.peer_port);
        connect_to_peer(infos.peer_host, infos.peer_port, &(infos.peer_sockaddr), infos.peer_ip, sizeof(infos.peer_ip), &(infos.peer_socket));
        peer_sockets[infos.peer_socket] = peer_it->first;
        peers[std::string(peer_it->first)] = infos;
    }
    peers_connected = 1;
}

bool is_a_local_socket(SIPpSocket *s)
{
    for (int i = 0; i< local_nb + 1; i++) {
        if (local_sockets[i] == s)
            return true;
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

void SIPpSocket::pollset_process(int wait)
{
    int rs; /* Number of times to execute recv().
            For TCP with 1 socket per call:
                no. of events returned by poll
            For UDP and TCP with 1 global socket:
                recv_count is a flag that stays up as
                long as there's data to read */

#ifndef HAVE_EPOLL
    /* What index should we try reading from? */
    static size_t read_index;

    int loops = max_recv_loops;

    // If not using epoll, we have a queue of pending messages to spin through.

    if (read_index >= pollnfds) {
        read_index = 0;
    }

    /* We need to process any messages that we have left over. */
    while (pending_messages && loops > 0) {
        update_clock_tick();
        if (sockets[read_index]->ss_msglen) {
            struct sockaddr_storage src;
            char msg[SIPP_MAX_MSG_SIZE];
            ssize_t len = sockets[read_index]->read_message(msg, sizeof(msg), &src);
            if (len > 0) {
                process_message(sockets[read_index], msg, len, &src);
            } else {
                assert(0);
            }
            loops--;
        }
        read_index = (read_index + 1) % pollnfds;
    }

    /* Don't read more data if we still have some left over. */
    if (pending_messages) {
        return;
    }
#endif
    /* Get socket events. */
#ifdef HAVE_EPOLL
    /* Ignore the wait parameter and always wait - when establishing TCP
     * connections, the alternative is that we tight-loop. */
    rs = epoll_wait(epollfd, epollevents, max_recv_loops, 1);
    // If we're receiving as many epollevents as possible, flag CPU congestion
    cpu_max = (rs > (max_recv_loops - 2));
#else
    rs = poll(pollfiles, pollnfds, wait ? 1 : 0);
#endif
    if (rs < 0 && errno == EINTR) {
        return;
    }

    /* We need to flush all sockets and pull data into all of our buffers. */
#ifdef HAVE_EPOLL
    for (int event_idx = 0; event_idx < rs; event_idx++) {
        int poll_idx = (int)epollevents[event_idx].data.u32;
#else
    for (size_t poll_idx = 0; rs > 0 && poll_idx < pollnfds; poll_idx++) {
#endif
        SIPpSocket *sock = sockets[poll_idx];
        int events = 0;
        int ret = 0;

        assert(sock);

#ifdef HAVE_EPOLL
        if (epollevents[event_idx].events & EPOLLOUT) {
#else
        if (pollfiles[poll_idx].revents & POLLOUT) {
#endif

#ifdef USE_SCTP
            if (transport == T_SCTP && sock->sctpstate != SCTP_UP);
            else
#endif
            {
                /* We can flush this socket. */
                TRACE_MSG("Exit problem event on socket %d \n", sock->ss_fd);
#ifdef HAVE_EPOLL
                epollfiles[poll_idx].events &= ~EPOLLOUT;
                int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, sock->ss_fd, &epollfiles[poll_idx]);
                if (rc == -1) {
                    ERROR_NO("Failed to clear EPOLLOUT");
                }
#else
                pollfiles[poll_idx].events &= ~POLLOUT;
#endif
                sock->ss_congested = false;

                sock->flush();
                events++;
            }
        }

#ifdef HAVE_EPOLL
        if (epollevents[event_idx].events & EPOLLIN) {
#else
        if (pollfiles[poll_idx].revents & POLLIN) {
#endif
            /* We can empty this socket. */
            if ((transport == T_TCP || transport == T_TLS || transport == T_SCTP) && sock == main_socket) {
                SIPpSocket *new_sock = sock->accept();
                if (!new_sock) {
                    ERROR_NO("Accepting new TCP connection");
                }
            } else if (sock == ctrl_socket) {
                handle_ctrl_socket();
            } else if (sock == stdin_socket) {
                handle_stdin_socket();
            } else if (sock == localTwinSippSocket) {
                if (thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
                    twinSippSocket = sock->accept();
                    if (!twinSippMode) {
                        ERROR_NO("Accepting new TCP connection on Twin SIPp Socket");
                    }
                    twinSippSocket->ss_control = 1;
                } else {
                    /* 3pcc extended mode: open a local socket
                       which will be used for reading the infos sent by this remote
                       twin sipp instance (slave or master) */
                    if (local_nb == MAX_LOCAL_TWIN_SOCKETS) {
                        ERROR("Max number of twin instances reached");
                    }

                    SIPpSocket *localSocket = sock->accept();
                    localSocket->ss_control = 1;
                    local_sockets[local_nb] = localSocket;
                    local_nb++;
                    if (!peers_connected) {
                        connect_to_all_peers();
                    }
                }
            } else {
                if ((ret = sock->empty()) <= 0) {
#ifdef USE_SCTP
                    if (sock->ss_transport == T_SCTP && ret == -2);
                    else
#endif
                    {
                        ret = sock->read_error(ret);
                        if (ret == 0) {
                            /* If read_error() then the poll_idx now belongs
                             * to the newest/last socket added to the sockets[].
                             * Need to re-do the same poll_idx for the "new" socket.
                             * We do this differently when using epoll. */
#ifdef HAVE_EPOLL
                            for (int event_idx2 = event_idx + 1; event_idx2 < rs; event_idx2++) {
                                if (epollevents[event_idx2].data.u32 == pollnfds) {
                                    epollevents[event_idx2].data.u32 = poll_idx;
                                }
                            }
#else
                            poll_idx--;
                            events++;
                            rs--;
#endif
                            continue;
                        }
                    }
                }
            }
            events++;
        }

        /* Here the logic diverges; if we're using epoll, we want to stay in the
         * for-each-socket loop and handle messages on that socket. If we're not using
         * epoll, we want to wait until after that loop, and spin through our
         * pending_messages queue again. */

#ifdef HAVE_EPOLL
        unsigned old_pollnfds = pollnfds;
        update_clock_tick();
        /* Keep processing messages until this socket is freed (changing the number of file descriptors) or we run out of messages. */
        while ((pollnfds == old_pollnfds) &&
                (sock->message_ready())) {
            char msg[SIPP_MAX_MSG_SIZE];
            struct sockaddr_storage src;
            ssize_t len;

            len = sock->read_message(msg, sizeof(msg), &src);
            if (len > 0) {
                process_message(sock, msg, len, &src);
            } else {
                assert(0);
            }
        }

        if (pollnfds != old_pollnfds) {
            /* Processing messages has changed the number of pollnfds, so update any remaining events */
            for (int event_idx2 = event_idx + 1; event_idx2 < rs; event_idx2++) {
                if (epollevents[event_idx2].data.u32 == pollnfds) {
                    epollevents[event_idx2].data.u32 = poll_idx;
                }
            }
        }
#else

        if (events) {
            rs--;
        }
        pollfiles[poll_idx].revents = 0;
#endif
    }

#ifndef HAVE_EPOLL
    if (read_index >= pollnfds) {
        read_index = 0;
    }

    /* We need to process any new messages that we read. */
    while (pending_messages && (loops > 0)) {
        update_clock_tick();

        if (sockets[read_index]->ss_msglen) {
            char msg[SIPP_MAX_MSG_SIZE];
            struct sockaddr_storage src;
            ssize_t len;

            len = sockets[read_index]->read_message(msg, sizeof(msg), &src);
            if (len > 0) {
                process_message(sockets[read_index], msg, len, &src);
            } else {
                assert(0);
            }
            loops--;
        }
        read_index = (read_index + 1) % pollnfds;
    }

    cpu_max = (loops <= 0);
#endif
}



/***************** Check of the message received ***************/

bool sipMsgCheck (const char *P_msg, SIPpSocket *socket)
{
    const char C_sipHeader[] = "SIP/2.0";

    if (socket == twinSippSocket || socket == localTwinSippSocket ||
            is_a_peer_socket(socket) || is_a_local_socket(socket))
        return true;

    if (strstr(P_msg, C_sipHeader) !=  nullptr) {
        return true;
    }

    return false;
}


#ifdef GTEST

#include "gtest/gtest.h"

TEST(get_trimmed_call_id, noslashes) {
    EXPECT_STREQ("abc", get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: abc\r\nCall-ID: def\r\n\r\n"));
}

TEST(get_trimmed_call_id, withslashes) {
    EXPECT_STREQ("abc2", get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: ///abc2\r\nCall-ID: def\r\n\r\n"));
    EXPECT_STREQ("abc3", get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: abc2///abc3\r\nCall-ID: def\r\n\r\n"));
    EXPECT_STREQ("abc4///abc5", get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: abc3///abc4///abc5\r\nCall-ID: def\r\n\r\n"));
}

#endif //GTEST
