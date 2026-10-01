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
#include <type_traits>

#include "config.h"
#include "sipp.hpp"
#include "socket.hpp"
#include "logger.hpp"
#include "poller.hpp"
#include "dns.hpp"
#include "websocket.hpp"

extern bool do_hide;

/* The WebSocket connections whose handshake is not done yet, for
 * -ws_handshake_timeout. */
static std::set<SIPpSocket*> ws_handshaking;

SIPpSocket *ctrl_socket = nullptr;
SIPpSocket *stdin_socket = nullptr;

static int stdin_fileno = -1;
static int stdin_mode;

/******************** Recv Poll Processing *********************/

unsigned pollnfds;
/* The call sockets in the pollset: what -max_socket limits. */
static unsigned call_sockets;
SIPpSocket  *sockets[SIPP_MAXFDS];

/* The descriptors of sockets[], each keyed by its SIPpSocket. */
static Poller poller;
/* The events of the pollset_process() pass under way: a socket that
 * leaves the poller during it leaves them too (see poll_remove()). */
static std::vector<PollerEvent> poll_events;
static int poll_nevents;

int pending_messages = 0;

std::map<std::string, SIPpSocket *>     map_perip_fd;

/* Make fd non-blocking. Returns its flags from before, or -1. */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        WARNING_NO("Unable to make descriptor %d non-blocking", fd);
        return -1;
    }
    return flags;
}

static void trim(char *s)
{
    char *p = s;
    while(isspace(*p)) {
        p++;
    }
    int l = strlen(p);
    for (int i = l - 1; i >= 0 && isspace(p[i]); i--) {
        p[i] = '\0';
    }
    memmove(s, p, l + 1);
}

static void connect_to_peer(const char *peer_host, int peer_port, struct sockaddr_storage *peer_sockaddr,
                            SIPpSocket **peer_socket);

int gai_getsockaddr(struct sockaddr_storage* ss, const char* host,
                    const char *service, int flags, int family, int prefer)
{
    const struct addrinfo hints = {flags, family,};
    struct addrinfo* res;

    int error = getaddrinfo(host, service, &hints, &res);
    if (error == 0) {
        const struct addrinfo *ai = res;
        while (ai && ai->ai_family != prefer) {
            ai = ai->ai_next;
        }
        if (!ai) {
            ai = res;
        }
        memcpy(ss, ai->ai_addr, ai->ai_addrlen);
        freeaddrinfo(res);
    } else {
        WARNING("getaddrinfo failed: %s", gai_strerror(error));
    }

    return error;
}

int gai_getsockaddr(struct sockaddr_storage* ss, const char* host,
                    unsigned short port, int flags, int family, int prefer)
{
    if (port) {
        char service[NI_MAXSERV + 1];
        snprintf(service, sizeof(service), "%d", port);
        return gai_getsockaddr(ss, host, service, flags, family, prefer);
    } else {
        return gai_getsockaddr(ss, host, nullptr, flags, family, prefer);
    }
}

int gai_family(const char *host)
{
    struct sockaddr_storage ss;

    if (gai_getsockaddr(&ss, host, nullptr, AI_PASSIVE, AF_UNSPEC) != 0) {
        return AF_UNSPEC;
    }
    return ss.ss_family;
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
            rotate_messagef();
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

std::string_view get_trimmed_call_id(const char *msg, std::string_view *full)
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
    const std::string_view call_id = get_call_id(msg);
    if (full) {
        *full = call_id;
    }
    const size_t slashes = call_id.find("///");
    if (!callidSlash && slashes != std::string_view::npos) {
        return call_id.substr(slashes + 3);
    }
    return call_id;
}

static std::string get_inet_address(const struct sockaddr_storage *addr)
{
    char ip[NI_MAXHOST];
    if (getnameinfo(_RCAST(struct sockaddr *, addr), socklen_from_addr(addr), ip, sizeof(ip), nullptr, 0,
                    NI_NUMERICHOST) != 0) {
        return "addr not supported";
    }
    return ip;
}

/* The sockets of -t ui are keyed by the -ip_field text and by the
 * address it resolves to, so that another name of an address takes the
 * socket bound to it rather than binding the address again. */
static std::string perip_key(const struct sockaddr_storage *ss)
{
    return get_inet_address(ss);
}

SIPpSocket *find_perip_socket(const std::string &peripaddr, const struct sockaddr_storage *ss)
{
    auto i = map_perip_fd.find(perip_key(ss));
    if (i == map_perip_fd.end()) {
        return nullptr;
    }
    map_perip_fd[peripaddr] = i->second;
    return i->second;
}

void add_perip_socket(const std::string &peripaddr, const struct sockaddr_storage *ss, SIPpSocket *sock)
{
    map_perip_fd[peripaddr] = sock;
    map_perip_fd[perip_key(ss)] = sock;
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
        quitting += 10;
        print_statistics(0);
        break;

    case 'Q':
        /* We are going to break, so we never have a chance to press q twice. */
        quitting += 20;
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
    if (!control_ip.empty()) {
        if (gai_getsockaddr(&ctl_sa, control_ip.c_str(), nullptr, AI_PASSIVE, AF_UNSPEC) != 0) {
            ERROR("Unknown control address '%s'.\n"
                  "Use 'sipp -h' for details",
                  control_ip.c_str());
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
        close(sock);
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
    stdin_mode = set_nonblocking(stdin_fileno);
    if (stdin_mode != -1) {
        atexit(reset_stdin);
    }

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

    /* A WebSocket buffers its messages one by one too. */
    if (ss_transport == T_UDP || ss_transport == T_SCTP || TRANSPORT_IS_WS(ss_transport)) {
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
        } else if (notifMsg->sn_assoc_change.sac_state == SCTP_CANT_STR_ASSOC ||
                   notifMsg->sn_assoc_change.sac_state == SCTP_COMM_LOST) {
            bool lost = notifMsg->sn_assoc_change.sac_state == SCTP_COMM_LOST;
            TRACE_MSG("%s\n", lost ? "SCTP_COMM_LOST" : "SCTP_CANT_STR_ASSOC");
            /* The association never came up, or the peer aborted it: the
             * read fails with the socket's error, as that of a refused or
             * reset TCP connection does. */
            sctpstate = SCTP_DOWN;
            ss_congested = false;
            int err = 0;
            sipp_socklen_t len = sizeof(err);
            if (getsockopt(ss_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || !err) {
                err = lost ? ECONNRESET : ECONNREFUSED;
            }
            errno = err;
            return -1;
        } else {
            TRACE_MSG("else: %d\n", notifMsg->sn_assoc_change.sac_state);
            return -2;
        }
    } else if (notifMsg->sn_header.sn_type == SCTP_SHUTDOWN_EVENT) {
        TRACE_MSG("SCTP_SHUTDOWN_EVENT\n");
        return -2;
    }
    return -2;
}

void set_multihome_addr(SIPpSocket* socket, int port)
{
    if (!multihome_ip.empty()) {
        struct sockaddr_storage secondaryaddress;
        if (gai_getsockaddr(&secondaryaddress, multihome_ip.c_str(), port, AI_PASSIVE, AF_UNSPEC) != 0) {
            ERROR("Can't get multihome IP address in getaddrinfo, multihome_ip='%s'", multihome_ip.c_str());
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
    /* A WebSocket that closed reads no more. Called once its messages are
     * processed and what they sent is out (see to_empty()), it sends its
     * close, and ends as a connection that the peer closes does. */
    if (ss_ws && ss_ws->is_closed()) {
        if (!ss_ws_close.empty()) {
            write_primitive(ss_ws_close.data(), ss_ws_close.size(), &ss_dest);
            ss_ws_close.clear();
        }
        return 0;
    }

    int readsize=0;
    if (ss_transport == T_UDP || ss_transport == T_SCTP) {
        readsize = SIPP_MAX_MSG_SIZE;
    } else {
        readsize = tcp_readsize;
    }

    /* One buffer for every read, made once: the main loop reads one
     * socket at a time, and only what a read got is kept. */
    static std::vector<char> read_buffer;
    if (read_buffer.size() < (size_t)readsize) {
        read_buffer.resize(readsize);
    }
    char *buffer = read_buffer.data();
    struct sockaddr_storage from = {};
    int ret = -1;
    /* Where should we start sending packets to, ideally we should begin to parse
     * the Via, Contact, and Route headers.  But for now SIPp always sends to the
     * host specified on the command line; or for UAS mode to the address that
     * sent the last message. */
    sipp_socklen_t addrlen = sizeof(struct sockaddr_storage);

    switch(ss_transport) {
    case T_TCP:
    case T_WS:
        ret = recvfrom(ss_fd, buffer, readsize, 0, (struct sockaddr *)&from, &addrlen);
        break;
    case T_UDP:
        /* Without waiting: the socket is blocking, and a read past the
         * datagram the poll found (see read_next_datagram()) may find
         * none. */
        ret = recvfrom(ss_fd, buffer, readsize, MSG_DONTWAIT, (struct sockaddr *)&from, &addrlen);
        break;
    case T_TLS:
    case T_WSS:
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        errno = 0;
        ret = SSL_read(ss_ssl, buffer, readsize);
        /* wolfSSL returns 0 on a reset as on a close: tell them apart,
         * so that a reset connection is connected again. */
        if (ret == 0 && errno == ECONNRESET) {
            ret = -1;
        }
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

        ret = sctp_recvmsg(ss_fd, (void *)buffer, readsize, (struct sockaddr *)&from, &addrlen, &recvinfo, &msg_flags);

        if (MSG_NOTIFICATION & msg_flags) {
            errno = 0;
            ret = handleSCTPNotify(buffer);
        }
#else
        ERROR("SCTP support is not enabled!");
#endif
        break;
    }
    if (ret <= 0) {
        return ret;
    }

    if (ss_ws) {
        return ws_empty(buffer, ret, &from);
    }

    buffer_read(alloc_socketbuf(buffer, ret, DO_COPY, &from));

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

    ws_handshaking.erase(this);

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    if (SSL *ssl = ss_ssl) {
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
        SSL_free(ssl);
    }
#endif

    /* In some error conditions, the socket FD has already been closed - if it hasn't, do so now. */
    if (ss_fd != -1) {
        poll_remove();
    }
    if (ss_fd != -1 && ss_fd != stdin_fileno) {
        if (ss_transport == T_TCP || ss_transport == T_WS) {
            /* ENOTCONN: the peer reset the connection already. */
            if (shutdown(ss_fd, SHUT_RDWR) < 0 && errno != ENOTCONN) {
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
    ss_poll_writable = false;

    /* Adds call sockets in the array */
    assert(pollnfds > 0);

    pollnfds--;
    if (ss_call_socket) {
        call_sockets--;
    }
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

/* Close the connection with a reset, but keep the socket, which a call or
 * a global may still use: reset_connection() connects it again. */
void SIPpSocket::drop_connection()
{
    if (ss_fd != -1) {
        struct linger flush;
        flush.l_onoff = 1;
        flush.l_linger = 0;
        if (setsockopt(ss_fd, SOL_SOCKET, SO_LINGER, &flush, sizeof(flush)) < 0) {
            WARNING_NO("Unable to set SO_LINGER option to reset socket %d", ss_fd);
        }
    }
    invalidate();
}

void SIPpSocket::close()
{
    int count = --ss_count;

    if (count == 0) {
        /* End a WebSocket with a close frame, or with the one it has yet
         * to send, unless something is in its way. */
        if (ss_ws && !ss_out && !ss_invalid) {
            std::string frame = ss_ws_close;
            if (ss_ws->is_open() && !ss_ws->is_closed()) {
                frame = ss_ws->close_frame(1000);
            }
            if (!frame.empty()) {
                write_primitive(frame.data(), frame.size(), &ss_dest);
            }
        }
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
        /* The poll loop ends a WebSocket that closed once this last
         * message is processed. */
        if (ss_ws && ss_ws->is_closed()) {
            poll_out();
        }
        pending_messages--;
    }

    return avail;
}

/* Is msg a request that -aa answers outside of any call? */
static bool is_auto_answered(const char *msg)
{
    static const char *methods[] = {"INFO", "NOTIFY", "OPTIONS", "UPDATE"};

    if (!auto_answer) {
        return false;
    }
    for (const char *method : methods) {
        size_t len = strlen(method);
        if (!strncmp(msg, method, len) && msg[len] == ' ') {
            return true;
        }
    }
    return false;
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

    std::string_view full_call_id;
    const std::string_view call_id = get_trimmed_call_id(msg, &full_call_id);
    if (call_id.empty()) {
        WARNING("SIP message without a valid Call-ID: header discarded: '%s'", msg);
        return;
    }
    /* A dialog of a call can have a Call-ID with '///' of its own */
    listener *listener_ptr = call_id.size() != full_call_id.size() ? get_listener(full_call_id) : nullptr;
    if (!listener_ptr) {
        listener_ptr = get_listener(call_id);
    }
    bool twin = socket == localTwinSippSocket || socket == twinSippSocket || is_a_local_socket(socket);
    if (!listener_ptr && !twin) {
        /* A request that starts a dialog of a call waiting for it */
        listener_ptr = call::take_new_dialog(msg);
    }
    struct timeval currentTime;
    GET_TIME (&currentTime);

    if (useShortMessagef == 1) {
        const header_value cseq = get_header_content(msg, "CSeq:");
        const std::string_view first_line = get_first_line(msg);
        TRACE_SHORTMSG("%s\tR\t%.*s\tCSeq:%.*s\t%.*s\n", CStat::formatTime(&currentTime, rfc3339), (int)call_id.size(),
                       call_id.data(), (int)cseq.view().size(), cseq.view().data(), (int)first_line.size(),
                       first_line.data());
    }

    if (useMessagef == 1) {
        TRACE_MSG("----------------------------------------------- %s\n"
                  "%s %smessage received [%zu] bytes:\n\n%s\n",
                  CStat::formatTime(&currentTime, true),
                  TRANSPORT_TO_STRING(socket->ss_transport),
                  socket->ss_control ? "control " : "",
                  msg_size, msg);
    }

    // got as message not relating to a known call
    if (!listener_ptr) {
        /* A message the scenario can't begin with would only take the
         * place of the next call: a response, or a request that -aa or
         * the out-of-call scenario answers, stays out of the calls. */
        bool out_of_call = false;
        if (creationMode == MODE_SERVER || creationMode == MODE_MIXED) {
            scenario *s = creationMode == MODE_SERVER ? main_scenario : rx_scenario;
            out_of_call = !s->startsWith(msg) && (get_reply_code(msg) || ooc_scenario || is_auto_answered(msg));
        }
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
                    case T_WS:
                    case T_WSS:
                        /* None without a remote host in server mode. */
                        if (tcp_multiplex) {
                            new_ptr->associate_socket(tcp_multiplex);
                            tcp_multiplex->ss_count++;
                        }
                        break;
                    }
                }
            }
            listener_ptr = new_ptr;
        } else if (!out_of_call && creationMode == MODE_SERVER) {
            if (quitting >= 1) {
                CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                TRACE_MSG("Discarded message for new calls while quitting\n");
                return;
            }

            // Adding a new INCOMING call !
            main_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
            listener_ptr = new call(main_scenario, call_id, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src);
        } else if (!out_of_call && creationMode == MODE_MIXED) {
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
        } else { // mode != from SERVER and 3PCC Controller B, or out of call
            // This is a message that is not relating to any known call
            if (ooc_scenario) {
                if (!get_reply_code(msg)) {
                    size_t method_len = strcspn(msg, " \t\n\v\f\r");
                    ooc_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
                    WARNING("Received out-of-call %.*s message, using the out-of-call scenario", (int)method_len, msg);
                    /* This should have the real address that the message came from. */
                    call *call_ptr = new call(ooc_scenario, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src, call_id, 0 /* no user. */, socket->ss_ipv6, true, false);
                    CStat::globalStat(CStat::E_AUTO_ANSWERED);
                    call_ptr->process_incoming(msg, src, socket);
                } else {
                    /* We received a response not relating to any known call */
                    /* Do nothing, even if in auto answer mode */
                    CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
                }
            } else if (is_auto_answered(msg)) {
                // If auto answer mode, try to answer the incoming message
                // with automaticResponseMode, which counts it; the call is
                // discarded once it has answered.
                aa_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
                /* This should have the real address that the message came from. */
                call *call_ptr = new call(aa_scenario, socket, use_remote_sending_addr ? &remote_sending_sockaddr : src, call_id, 0 /* no user. */, socket->ss_ipv6, true, false);
                if (call_ptr->process_incoming(msg, src, socket)) {
                    aa_scenario->stats->computeStat(CStat::E_CALL_SUCCESSFULLY_ENDED);
                    delete call_ptr;
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

    if (twin) {
        listener_ptr -> process_twinSippCom(msg);
    } else {
        /* This is a message on a known call - process it */
        listener_ptr -> process_incoming(msg, src, socket);
    }
}

SIPpSocket::SIPpSocket(bool use_ipv6, int transport, int fd, int accepting):
    ss_ipv6(use_ipv6),
    ss_transport(transport),
    ss_fd(fd)
{
    /* Initialize all sockets with our destination address. */
    memcpy(&ss_dest, &remote_sockaddr, sizeof(ss_dest));

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    if (TRANSPORT_IS_TLS(transport)) {
        set_nonblocking(fd);

        if (!(ss_ssl = (accepting ? SSL_new_server() : SSL_new_client()))) {
            ERROR("Unable to create SSL object : Problem with SSL_new()");
        }

        /* The fd itself, not through a socket BIO, whose fd wolfSSL's
         * SSL_get_fd() doesn't return: the waits for the peer polled -1
         * and stalled every handshake. */
        if (!SSL_set_fd(ss_ssl, fd)) {
            ERROR("Unable to set the SSL descriptor: Problem with SSL_set_fd()");
        }
    }
#endif
    /* Store this socket in the tables. */
    ss_pollidx = pollnfds++;
    sockets[ss_pollidx] = this;
    poll_add();
}

SIPpSocket::~SIPpSocket()
{
    ws_handshaking.erase(this);
    delete ss_ws;
}

/* Wait -ws_handshake_timeout for this WebSocket's handshake. */
void SIPpSocket::ws_waiting()
{
    ss_ws_since = getmilliseconds();
    ws_handshaking.insert(this);
}

/* Drop the connections whose WebSocket handshake took too long. Called
 * before the poll loop looks at the sockets, as it may remove some. */
void SIPpSocket::check_ws_handshakes()
{
    if (ws_handshake_timeout <= 0 || ws_handshaking.empty()) {
        return;
    }
    unsigned long now = getmilliseconds();
    std::vector<SIPpSocket*> expired;
    for (SIPpSocket *sock : ws_handshaking) {
        if (now - sock->ss_ws_since >= (unsigned long)ws_handshake_timeout) {
            expired.push_back(sock);
        }
    }
    for (SIPpSocket *sock : expired) {
        /* Unless dropping one took another along. */
        if (ws_handshaking.count(sock)) {
            sock->ws_handshake_expired();
        }
    }
}

/* A server's client sent no handshake request in time: drop it. A
 * client got no answer: its connection failed, and is made again if
 * -max_reconnect allows, as when a TCP one fails. */
void SIPpSocket::ws_handshake_expired()
{
    ws_handshaking.erase(this);
    nb_net_recv_errors++;
    if (ss_accepted) {
        WARNING("No WebSocket handshake request within %d ms, closing the %s connection",
                ws_handshake_timeout, TRANSPORT_TO_STRING(ss_transport));
        peer_closed(false);
        return;
    }
    sockets_pending_reset.insert(this);
    drop_connection();
    if (reconnect_allowed()) {
        WARNING("No WebSocket handshake answer within %d ms", ws_handshake_timeout);
    } else {
        ERROR("No WebSocket handshake answer within %d ms", ws_handshake_timeout);
    }
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
    case T_TCP:
    case T_WS:
    case T_WSS:
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
    /* Only call sockets count: the main, control and stdin sockets
     * don't take from the -max_socket budget. */
    if (call_sockets >= max_multi_socket) {
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
        if (!sock) {
            ERROR("Could not find an existing call socket to re-use!");
        }
    } else {
        sock = new_sipp_socket(use_ipv6, transport);
        sock->ss_call_socket = true;
        call_sockets++;
        /* Its first reference is the call's, so the socket is closed when
         * the last call using it ends. */
        sock->ss_own_ref = false;
        *existing = false;
    }
    return sock;
}

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
/* After SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, wait until the
 * socket is ready, for at most timeout ms. Returns false on a timeout.
 * Sleeping the whole timeout instead delayed every TLS handshake by it,
 * as the peer's reply is usually a moment away. */
static bool wait_for_ssl_socket(SSL *ssl, int ssl_error, int timeout = SIPP_SSL_RETRY_TIMEOUT)
{
    struct pollfd pfd = {};
    pfd.fd = SSL_get_fd(ssl);
    pfd.events = (ssl_error == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
    return poll(&pfd, 1, timeout) > 0;
}

/* Run SSL_accept() or SSL_connect() until the handshake is done, for at
 * most tls_handshake_timeout ms in all: a slow peer may be silent for a
 * while, but one that never answers must not hold SIPp forever. Returns
 * SSL_ERROR_NONE, or the SSL error it failed with, after warning. */
static int ssl_handshake(SSL *ssl, bool accepting)
{
    const char *name = accepting ? "SSL_accept" : "SSL_connect";
    unsigned long start = getmilliseconds();
    int rc;

    while ((rc = accepting ? SSL_accept(ssl) : SSL_connect(ssl)) != 1) {
        int err = SSL_get_error(ssl, rc);
        /* wolfSSL returns its own negative code for a protocol error. */
        if (err < 0) {
            err = SSL_ERROR_SSL;
        }
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            WARNING("Error in %s: %s", name, SSL_error_string(err, rc));
            return err;
        }
        /* These errors are benign we just need to wait for the socket
         * to be readable/writable again. The elapsed time, not a deadline,
         * so that the clock wrapping doesn't matter; and a wait a signal
         * cuts short (EINTR) just goes round again. A timeout of 0 is
         * no limit. */
        unsigned long elapsed = getmilliseconds() - start;
        if (tls_handshake_timeout > 0 && elapsed >= (unsigned long)tls_handshake_timeout) {
            WARNING("Error in %s: no handshake within %d ms", name, tls_handshake_timeout);
            return err;
        }
        wait_for_ssl_socket(ssl, err, tls_handshake_timeout > 0 ? tls_handshake_timeout - elapsed : -1);
    }
    return SSL_ERROR_NONE;
}
#endif

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
    ret->ss_accepted = true;

    /* We should connect back to the address which connected to us if we
     * experience a TCP failure. */
    memcpy(&ret->ss_dest, &remote_sockaddr, sizeof(ret->ss_dest));

    if (TRANSPORT_IS_TLS(ret->ss_transport)) {
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        if (ssl_handshake(ret->ss_ssl, true) != SSL_ERROR_NONE) {
            /* Only this peer failed: drop it, and keep serving the others. */
            ret->close();
            return nullptr;
        }
#else
        ERROR("You need to compile SIPp with TLS support");
#endif
    }

    /* The client's WebSocket handshake comes first. */
    if (TRANSPORT_IS_WS(ret->ss_transport)) {
        ret->ss_ws = new WebSocket(true, SIPP_MAX_MSG_SIZE - 1);
        ret->ws_waiting();
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

    assert(transport_is_reliable(ss_transport));

    if (ss_transport == T_TCP || ss_transport == T_TLS || TRANSPORT_IS_WS(ss_transport)) {
        struct sockaddr_storage with_optional_port;
        int port = -1;
        memcpy(&with_optional_port, &local_sockaddr, sizeof(struct sockaddr_storage));
        if (local_ip_is_ipv6) {
            (_RCAST(struct sockaddr_in6*, &with_optional_port))->sin6_port = htons(ss_bind_port);
        } else {
            (_RCAST(struct sockaddr_in*, &with_optional_port))->sin_port = htons(ss_bind_port);
        }
        if (sipp_bind_socket(this, &with_optional_port, &port)) {
            /* As before: the kernel picks the address, as when a
             * reconnection finds the -p port still taken. */
            WARNING_NO("Unable to bind socket %d before connecting it", ss_fd);
        }
#ifdef USE_SCTP
    } else if (ss_transport == T_SCTP) {
        int port = -1;
        if (sipp_bind_socket(this, &local_sockaddr, &port)) {
            WARNING_NO("Unable to bind socket %d before connecting it", ss_fd);
        }
#endif
    }

    int flags = set_nonblocking(ss_fd);

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

    if (flags != -1 && fcntl(ss_fd, F_SETFL, flags) == -1) {
        WARNING_NO("Unable to restore the flags of socket %d", ss_fd);
    }

    if (TRANSPORT_IS_TLS(ss_transport)) {
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        if (int err = ssl_handshake(ss_ssl, false)) {
            invalidate();
            return err;
        }
#else
        ERROR("You need to compile SIPp with TLS support");
#endif
    }

    if (TRANSPORT_IS_WS(ss_transport)) {
        ws_connect();
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
        drop_connection();
    }

    ss_fd = socket_fd(ss_ipv6, ss_transport);
    if (ss_fd == -1) {
        ERROR_NO("Could not obtain new socket: ");
    }
    /* With the options of the first one: an SCTP socket that asks for no
     * events never learns that its association is up. */
    sipp_customize_socket(this);

    if (ss_invalid) {
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
        ss_ssl = nullptr;

        if (TRANSPORT_IS_TLS(ss_transport)) {
            /* Non-blocking, as in the constructor: connect() keeps the
             * flags it finds, and a blocking SSL_connect() could wait
             * past -tls_handshake_timeout for a silent server. */
            set_nonblocking(ss_fd);

            if (!(ss_ssl = SSL_new_client())) {
                ERROR("Unable to create SSL object : Problem with SSL_new()");
            }

            if (!SSL_set_fd(ss_ssl, ss_fd)) {
                ERROR("Unable to set the SSL descriptor: Problem with SSL_set_fd()");
            }
        }
#endif

        /* Store this socket in the tables. */
        ss_pollidx = pollnfds++;
        sockets[ss_pollidx] = this;
        if (ss_call_socket) {
            call_sockets++;
        }

        ss_invalid = false;
    }

    /* A setdest keeps its place, but not its descriptor (see close_fd()). */
    poll_add();
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
    if (heartbeat > 0 || pathmaxret > 0 || pmtu > 0) {
        /* No address: for the association, all its peer addresses and
         * those it has yet to learn. Set on each address only, a path
         * MTU does not hold: the association still discovers its own. */
        struct sctp_paddrparams peerparam;
        memset(&peerparam, 0, sizeof(peerparam));

        peerparam.spp_hbinterval = heartbeat;
        peerparam.spp_pathmaxrxt = pathmaxret;
        if (heartbeat > 0) peerparam.spp_flags = SPP_HB_ENABLE;

        if (pmtu > 0) {
            peerparam.spp_pathmtu = pmtu;
            peerparam.spp_flags |= SPP_PMTUD_DISABLE;
        }

        if (setsockopt(ss_fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
                       &peerparam, sizeof(peerparam)) == -1) {
            WARNING("setsockopt(SCTP_PEER_ADDR_PARAMS) failed, errno=%d", errno);
        }
    }
}
#endif

void sipp_customize_socket(SIPpSocket *socket)
{
    unsigned int buffsize = buff_size;

    /* Allows fast TCP reuse of the socket */
    if (transport_is_reliable(socket->ss_transport)) {
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

/* Have the poll loop watch this socket's descriptor: for reading, and for
 * writing too after poll_out(). */
void SIPpSocket::poll_add()
{
    unsigned events = POLLER_IN | (ss_poll_writable ? POLLER_OUT : 0);
    /* EPERM: a file epoll can't watch (stdin redirected from /dev/null,
     * say), which it then never reports. */
    if (!poller.add(ss_fd, events, (uintptr_t)this) && errno != EPERM) {
        ERROR_NO("Failed to add FD to the pollset");
    }
}

/* Stop watching its descriptor, before it is closed, along with any event
 * of it that this pass has yet to process. */
void SIPpSocket::poll_remove()
{
    if (!poller.remove(ss_fd) && errno != EPERM) {
        WARNING_NO("Failed to delete FD from the pollset");
    }
    for (int i = 0; i < poll_nevents; i++) {
        if (poll_events[i].key == (uintptr_t)this) {
            poll_events[i].key = 0;
        }
    }
}

void SIPpSocket::close_fd()
{
    if (ss_fd != -1) {
        poll_remove();
        ::close(ss_fd);
        ss_fd = -1;
    }
}

/* Have the poll loop flush this socket once it can be written to. */
void SIPpSocket::poll_out()
{
    ss_poll_writable = true;
    if (!poller.modify(ss_fd, POLLER_IN | POLLER_OUT, (uintptr_t)this)) {
        WARNING_NO("Failed to set POLLOUT");
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
    poll_out();

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

    /* A connection we accepted is the peer's to end, closed or reset, and
     * there is none to make again: reset_connection() ends its calls, as
     * when the peer closes it. */
    if ((ss_transport == T_TCP || ss_transport == T_WS) && ss_accepted && !ss_control &&
            (errno == EPIPE || errno == ECONNRESET)) {
        nb_net_send_errors++;
        sockets_pending_reset.insert(this);
        drop_connection();
        return -1;
    }

    /* A connection that is gone, or that could not be made (a buffered
     * message flushed once a reconnection is refused), is reset as a
     * read finding it so would. Only warning here left it dead, and the
     * next read took it for one the peer closed. So is a TLS client's:
     * it only warned, and asked the SSL object of a connection that the
     * peer had closed, which was freed, for the error. */
    int err = errno;
    bool tls_client = TRANSPORT_IS_TLS(ss_transport) && !ss_accepted;
    if ((ss_transport == T_TCP || ss_transport == T_SCTP || ss_transport == T_WS || tls_client)
            && (err == EPIPE || err == ECONNRESET || err == ECONNREFUSED || err == ENOTCONN)) {
        nb_net_send_errors++;
        sockets_pending_reset.insert(this);
        drop_connection();
        if (err == EPIPE) {
            if (reconnect_allowed()) {
                WARNING("Broken pipe on TCP connection, remote peer "
                        "probably closed the socket");
            } else {
                ERROR("Broken pipe on TCP connection, remote peer "
                      "probably closed the socket");
            }
        } else if (reconnect_allowed()) {
            WARNING("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
        } else {
            ERROR("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
        }
        errno = err;
        return -1;
    }

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    if (TRANSPORT_IS_TLS(ss_transport)) {
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
    /* A WebSocket that closed or failed read nothing: empty() returned 0,
     * for it to end as a TCP connection does, and there is no TLS error. */
    bool ws_closed = ss_ws && ss_ws->is_closed() && ret == 0;
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    if (TRANSPORT_IS_TLS(ss_transport) && !ws_closed) {
        int err = SSL_get_error(ss_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* This is benign - we just need to wait for the socket to be
             * readable/writable again, which will happen naturally as part
             * of the poll/epoll loop. It is no more a warning than EAGAIN
             * is on TCP. */
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
    if (ret < 0 && !TRANSPORT_IS_TLS(ss_transport)) {
        assert(errno != EAGAIN);
    }

    /* An SCTP association ends as a TCP connection does: a read of 0 is
     * the peer's SHUTDOWN, and an error its ABORT. */
    if (transport_is_reliable(ss_transport)) {
        /* A connection we accepted is the peer's to end, and there is none
         * to make again: a reset ends it as a close does. */
        bool reset = ret < 0 && errno == ECONNRESET && ss_accepted && !ss_control;
        if (ret == 0 || reset) {
            /* The remote side closed the connection. */
            if (ss_control) {
                if (extendedTwinSippMode) {
                    /* Closing the listener, the peer and local sockets here,
                     * this one among them, would move sockets under the poll
                     * loop that called us, which only expects this one to
                     * go, and a second peer ending would close them again.
                     * The exit closes them all. */
                    if (quitting < 20) {
                        WARNING("One of the twin instances has ended -> exiting");
                    }
                    quitting += 20;
                    return -1;
                }
                if (thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
                    /* As above, the exit closes the listener and this. */
                    WARNING("3PCC controller A has ended -> exiting");
                    quitting += 20;
                } else {
                    twinSippSocket = nullptr;
                    close();
                    if (!quitting) {
                        quitting = 1;
                    }
                    /* No command comes any more. */
                    int failed = call::close_twin_calls();
                    if (failed) {
                        WARNING("The remote peer closed the TCP connection, failing %d call(s)", failed);
                    }
                }
            } else {
                peer_closed(reset);
            }
            return 0;
        }

        sockets_pending_reset.insert(this);
        drop_connection();

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

/* The peer closed or reset the connection. It was closed "cleanly", but
 * we may have calls that need to be destroyed. Also, if these calls are
 * not complete, and attempt to send again we may "resurrect" the socket
 * by reconnecting it. Nothing reconnects one we accepted, so its calls
 * always end. The socket may be deleted here. */
void SIPpSocket::peer_closed(bool reset)
{
    bool end_calls = reset_close || ss_accepted;
    const char *transport = TRANSPORT_TO_STRING(ss_transport);
    invalidate();
    /* Nothing but its calls can reach this socket now, so drop its
     * own reference: it is deleted here if no call uses it, or
     * when the last one does. The global sockets keep theirs. A
     * call socket has none, so it may go with its calls here. */
    bool own_ref = ss_own_ref && this != main_socket && this != tcp_multiplex && this != main_remote_socket;
    if (end_calls) {
        int failed = close_calls();
        if (failed) {
            WARNING("The remote peer %s the %s connection, failing %d call(s)",
                    reset ? "reset" : "closed", transport, failed);
        }
    }
    if (own_ref) {
        ss_own_ref = false;
        close();
    }
}

/* Queue a whole message that could not be written yet. On a WebSocket
 * what goes out is its frame, which is not a SIP message to trace, so
 * the message is traced now; any other is traced once flush() writes it. */
void SIPpSocket::buffer_whole(const char *buffer, size_t len, const char *out,
                              size_t out_len, struct sockaddr_storage *dest)
{
    if (ss_ws) {
        trace_sent(buffer, len);
    }
    buffer_write(out, out_len, dest, !ss_ws);
}

void SIPpSocket::buffer_write(const char *buffer, size_t len, struct sockaddr_storage *dest,
                              bool untraced)
{
    struct socketbuf *buf = ss_out;

    if (!buf) {
        ss_out = alloc_socketbuf(const_cast<char*>(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
        ss_out->untraced = untraced;
        ss_out_tail = ss_out;
        TRACE_MSG("Added first buffered message to socket %d\n", ss_fd);
        return;
    }

    ss_out_tail->next = alloc_socketbuf(const_cast<char*>(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
    ss_out_tail = ss_out_tail->next;
    ss_out_tail->untraced = untraced;
    TRACE_MSG("Appended buffered message to socket %d\n", ss_fd);
}

/* A connection that failed, to be made again for its calls, keeps what
 * they write until then, for the new one: a WebSocket's once the new
 * connection's handshake is done (see reset_connection()). */
bool SIPpSocket::keep(const char *buffer, size_t len, int flags, struct sockaddr_storage *dest)
{
    if (!(flags & WS_KEEP) || !ss_invalid || reset_close || ss_accepted || ss_control ||
            !sockets_pending_reset.count(this)) {
        return false;
    }
    if (ss_ws) {
        ss_ws->held += ss_ws->frame(buffer, len);
        trace_sent(buffer, len);
    } else {
        buffer_whole(buffer, len, buffer, len, dest);
    }
    return true;
}

bool SIPpSocket::all_written()
{
    return !ss_invalid && !ss_out && !(ss_ws && !ss_ws->held.empty());
}

/* Throw away the output still waiting to be written. */
void SIPpSocket::drop_out()
{
    while (ss_out) {
        struct socketbuf *next = ss_out->next;
        free_socketbuf(ss_out);
        ss_out = next;
    }
    ss_out_tail = nullptr;
}

void SIPpSocket::buffer_read(struct socketbuf *newbuf)
{
    struct socketbuf *buf = ss_in;

    if (!buf) {
        ss_in = newbuf;
        return;
    }

    /* After the last one: a WebSocket may buffer several messages. */
    while (buf->next) {
        buf = buf->next;
    }

    buf->next = newbuf;
}

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)

/* The descriptor of a TLS socket is non-blocking from the start (see
 * the constructor and reconnect()). */
static int send_nowait_tls(SSL* ssl, const void* msg, int len, int /*flags*/)
{
    int rc;
    int i = 0;
    if (SSL_get_fd(ssl) == -1) {
        return -1;
    }
    while ((rc = SSL_write(ssl, msg, len)) < 0) {
        int err = SSL_get_error(ssl, rc);
        if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
                i < SIPP_SSL_MAX_RETRIES) {
            /* These errors are benign we just need to wait for the socket
             * to be readable/writable again. */
            ++i;
            if (!wait_for_ssl_socket(ssl, err)) {
                WARNING("SSL_write failed with error: %s. Attempt %d. "
                        "Retrying...", SSL_error_string(err, rc), i);
            }
            continue;
        }
        return rc;
    }
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
    case T_WSS:
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
    case T_WS:
        rc = send_nowait(ss_fd, buffer, len, 0);
        break;

    case T_UDP:
        rc = sendto(ss_fd, buffer, len, 0, _RCAST(struct sockaddr*, dest),
                    socklen_from_addr(dest));
        break;

    default:
        ERROR("Internal error, unknown transport type %d", ss_transport);
    }

    return rc;
}

/* Trace a message that has been written whole. */
void SIPpSocket::trace_sent(const char *buffer, size_t len)
{
    struct timeval currentTime;
    GET_TIME (&currentTime);

    if (useMessagef == 1) {
        TRACE_MSG("----------------------------------------------- %s\n"
                  "%s %smessage sent [%zu] bytes:\n\n%.*s\n",
                  CStat::formatTime(&currentTime, true),
                  TRANSPORT_TO_STRING(ss_transport),
                  ss_control ? "control " : "",
                  len, (int)len, buffer);
    }

    if (useShortMessagef == 1) {
        /* A buffered message is not null terminated. */
        char *msg = strndup(buffer, len);
        const std::string_view call_id = get_trimmed_call_id(msg);
        const header_value cseq = get_header_content(msg, "CSeq:");
        const std::string_view first_line = get_first_line(msg);
        TRACE_SHORTMSG("%s\tS\t%.*s\tCSeq:%.*s\t%.*s\n", CStat::formatTime(&currentTime, rfc3339), (int)call_id.size(),
                       call_id.data(), (int)cseq.view().size(), cseq.view().data(), (int)first_line.size(),
                       first_line.data());
        free(msg);
    }
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
            if (buf->untraced) {
                trace_sent(buf->buf, buf->len);
            }
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

    /* Then the pong to the last ping that came while this waited. */
    if (!ss_ws_pong.empty()) {
        std::string pong;
        pong.swap(ss_ws_pong);
        ws_reply(pong);
        /* Part of it waits: what write() sends goes after it, not into
         * the middle of it. */
        if (ss_out) {
            errno = EWOULDBLOCK;
            return -1;
        }
    }

    return 0;
}

/* Write data to a socket. */
int SIPpSocket::write(const char *buffer, ssize_t len, int flags, struct sockaddr_storage *dest)
{
    int rc;
    /* What goes out: a WebSocket sends each message in a frame. */
    std::string frame;
    const char *out = buffer;
    ssize_t out_len = len;

    if (ss_ws && !ss_invalid) {
        frame = ss_ws->frame(buffer, len);
        if (!ss_ws->is_open()) {
            /* Held until the server takes the handshake, up to a bound:
             * with no -ws_handshake_timeout, a server that never answers
             * would make it grow without end. The message is then not
             * sent, as when the connection is full. */
            if (ss_ws->held.size() + frame.size() > WS_HELD_MAX) {
                if (!ss_ws->held_full) {
                    WARNING("No WebSocket handshake answer yet, and %zu bytes wait for it: "
                            "not sending more on this %s connection",
                            ss_ws->held.size(), TRANSPORT_TO_STRING(ss_transport));
                    ss_ws->held_full = true;
                }
                errno = ENOBUFS;
                return -1;
            }
            ss_ws->held += frame;
            trace_sent(buffer, len);
            return len;
        }
        out = frame.data();
        out_len = frame.size();
    }

    if (ss_out) {
        rc = flush();
        TRACE_MSG("Attempted socket flush returned %d\r\n", rc);
        if (rc < 0) {
            if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
                buffer_whole(buffer, len, out, out_len, dest);
                return len;
            } else if (keep(buffer, len, flags, dest)) {
                return len;
            } else {
                return rc;
            }
        }
    }

    rc = write_primitive(out, out_len, dest);
    struct timeval currentTime;
    GET_TIME (&currentTime);

    if (rc == out_len) {
        /* Everything is great. */
        trace_sent(buffer, len);
        rc = len;
    } else if (rc <= 0) {
        if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
            buffer_whole(buffer, len, out, out_len, dest);
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
        rc = write_error(errno);
        return keep(buffer, len, flags, dest) ? len : rc;
    } else {
        /* We have a truncated message, which must be handled internally to the write function. */
        if (useMessagef == 1) {
            TRACE_MSG("----------------------------------------------- %s\n"
                      "Truncation sending %s message (%d of %zu sent):\n\n%.*s\n",
                      CStat::formatTime(&currentTime, true),
                      TRANSPORT_TO_STRING(ss_transport),
                      rc, out_len, (int)len, buffer);
        }
        /* Whole, for a new connection to send it whole. */
        buffer_write(out, out_len, dest, false);
        ss_out_tail->offset = rc;
        enter_congestion(errno);
    }

    return rc;
}

/* Start a client's WebSocket handshake on a new connection. */
void SIPpSocket::ws_connect()
{
    std::string ip;
    char port[NI_MAXSERV] = "";

    /* What an earlier connection left may end in the middle of a frame. */
    drop_out();

    /* The host SIPp calls, unless the call went elsewhere. */
    if (!remote_host.empty() && !ss_changed_dest) {
        ip = remote_host;
        snprintf(port, sizeof(port), "%d", remote_port);
    } else {
        char numeric[NI_MAXHOST] = "";
        getnameinfo(_RCAST(struct sockaddr *, &ss_dest), socklen_from_addr(&ss_dest), numeric, sizeof(numeric), port,
                    sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
        ip = numeric;
    }
    const std::string host = (ip.find(':') == std::string::npos ? ip : "[" + ip + "]") + ":" + port;

    delete ss_ws;
    ss_ws = new WebSocket(false, SIPP_MAX_MSG_SIZE - 1);
    ws_waiting();
    std::string request = ss_ws->request(host.c_str(), ws_path);
    TRACE_MSG("WebSocket handshake on socket %d:\n\n%s", ss_fd, request.c_str());
    buffer_write(request.data(), request.size(), &ss_dest, false);
    poll_out();
}

/* Send a WebSocket's own frame, or a server's handshake answer: now,
 * unless other data waits. An error is not one of the SIP messages: the
 * reads find out whether the connection is gone. */
void SIPpSocket::ws_reply(const std::string &reply)
{
    ssize_t rc = 0;

    if (!ss_out) {
        rc = write_primitive(reply.data(), reply.size(), &ss_dest);
        if (rc < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
            return;
        }
        if (rc == (ssize_t)reply.size()) {
            return;
        }
        rc = rc < 0 ? 0 : rc;
    }
    /* Whole, as write() does. */
    buffer_write(reply.data(), reply.size(), &ss_dest, false);
    ss_out_tail->offset = rc;
    poll_out();
}

/* Take the SIP messages out of what a WebSocket connection read, and
 * answer its handshake and control frames. Once it closed or failed, the
 * messages that came before are processed, and their answers sent, before
 * its close (RFC 6455 section 5.5.1): then empty() ends it. */
int SIPpSocket::ws_empty(const char *data, int ret, struct sockaddr_storage *from)
{
    std::string payload, reply;
    WebSocket::Event event;

    ss_ws->feed(data, ret);
    while ((event = ss_ws->next(payload, reply)) != WebSocket::NEED_MORE) {
        switch (event) {
        case WebSocket::OPENED:
            TRACE_MSG("WebSocket open on socket %d\n", ss_fd);
            ws_handshaking.erase(this);
            if (!ss_ws->held.empty()) {
                buffer_write(ss_ws->held.data(), ss_ws->held.size(), &ss_dest, false);
                ss_ws->held.clear();
                poll_out();
            }
            break;
        case WebSocket::MESSAGE:
            /* Each is one SIP message (RFC 7118 section 5.2). */
            if (!payload.empty()) {
                buffer_read(alloc_socketbuf(&payload[0], payload.size(), DO_COPY, from));
            }
            break;
        case WebSocket::REPLY:
            /* While other data waits, only the last ping gets its pong
             * (section 5.5.3), after that data: a peer that pings and
             * does not read fills no memory. */
            if (ss_out) {
                ss_ws_pong.swap(reply);
                reply.clear();
            }
            break;
        case WebSocket::FAILED:
            WARNING("WebSocket error, closing the %s connection: %s",
                    TRANSPORT_TO_STRING(ss_transport), ss_ws->error().c_str());
        /* Fall through */
        case WebSocket::CLOSED:
            ss_ws_close.swap(reply);
            reply.clear();
            break;
        default:
            break;
        }
        if (!reply.empty()) {
            ws_reply(reply);
        }
    }

    if (!ss_msglen) {
        if (int msg_len = check_for_message()) {
            ss_msglen = msg_len;
            pending_messages++;
        }
    }

    /* The poll loop ends it once it can write, so after these messages
     * (see to_empty()). */
    if (ss_ws->is_closed()) {
        poll_out();
    }
    return ret;
}

/* Is there something for empty() to do? Something to read, if readable;
 * but a WebSocket that closed reads no more: it has empty() end it, once
 * its messages are processed and what they sent is out. */
bool SIPpSocket::to_empty(bool readable)
{
    if (ss_ws && ss_ws->is_closed()) {
        return !ss_msglen && !ss_out;
    }
    return readable;
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
    /* A connection we accepted that failed a write is gone for good (see
     * write_error()). */
    if (ss_accepted && !ss_control) {
        peer_closed(false);
        return;
    }

    if (!reconnect_allowed()) {
        ERROR_NO("Max number of reconnections reached");
    }

    if (reset_number != -1) {
        reset_number--;
    }

    if (reset_close) {
        WARNING("Closing calls, because of TCP reset or close!");
        if (twinSippMode && ss_control) {
            call::close_twin_calls();
        }
        /* A call socket goes with its last call, and then there is
         * nothing left to reconnect. */
        ss_count++;
        close_calls();
        if (ss_count == 1) {
            close();
            return;
        }
        ss_count--;
    }

    /* A twin connection we accepted is the peer's to make again, and the
     * listener takes it when it does: this one is only forgotten. */
    if (ss_accepted) {
        if (this == twinSippSocket) {
            twinSippSocket = nullptr;
        }
        for (int i = 0; i < local_nb; i++) {
            if (local_sockets[i] == this) {
                local_sockets[i] = local_sockets[--local_nb];
                local_sockets[local_nb] = nullptr;
                break;
            }
        }
        close();
        return;
    }

    /* Sleep for some period of time before the reconnection. */
    usleep(1000 * reset_sleep);

    /* What a WebSocket's connection did not take waits for the handshake
     * of the new one: the messages held for its own handshake, or once
     * that was done, the frames in its output, each whole. */
    std::string held;
    if (ss_ws) {
        for (struct socketbuf *buf = ss_ws->is_open() ? ss_out : nullptr; buf; buf = buf->next) {
            held.append(buf->buf, buf->len);
        }
        held += ss_ws->held;
    }

    if (int rc = reconnect()) {
        /* A TLS handshake that fails returns its SSL error, which
         * connect() warned about, rather than -1 and errno. */
        if (rc < 0) {
            WARNING_NO("Could not reconnect TCP socket");
        } else {
            WARNING("Could not reconnect TLS socket");
        }
        close_calls();
    } else {
        WARNING("Socket required a reconnection.");
        if (!reset_close) {
            resume_calls(held);
        }
    }
}

/* The calls kept over a reconnection go on on the new connection: what
 * the old one did not take goes on it, whole, and a request that it took
 * but that has no response is sent again, as it may have been lost with
 * it. */
void SIPpSocket::resume_calls(const std::string &held)
{
    if (ss_ws) {
        ss_ws->held = held;
    } else if (ss_out) {
        ss_out->offset = 0;
        poll_out();
    }

    owner_list *owners = get_owners_for_socket(this);
    for (socketowner *owner : *owners) {
        owner->tcpReconnected();
    }
    delete owners;
}

/* Close just those calls for a given socket (e.g., if the remote end closes
 * the connection. Returns how many of them failed. */
int SIPpSocket::close_calls()
{
    owner_list *owners = get_owners_for_socket(this);
    owner_list::iterator owner_it;
    socketowner *owner_ptr = nullptr;
    int failed = 0;

    /* What they left waiting to be written goes with them: sent on a
     * reconnection, it would restart a call that has already failed.
     * What waits on a twin connection are the commands of calls that
     * go on. */
    if (!ss_control) {
        drop_out();
    }

    for (owner_it = owners->begin(); owner_it != owners->end(); owner_it++) {
        owner_ptr = *owner_it;
        if (owner_ptr && owner_ptr->tcpClose()) {
            failed++;
        }
    }

    delete owners;
    return failed;
}

/* The NAPTR service and the SRV name prefix of a SIP transport
 * (RFC 3263); false for WebSocket, which has none. */
static bool sip_dns_service(int transport, const char **service,
                            const char **prefix)
{
    switch (transport) {
    case T_UDP:
        *service = "SIP+D2U";
        *prefix = "_sip._udp.";
        return true;
    case T_TCP:
        *service = "SIP+D2T";
        *prefix = "_sip._tcp.";
        return true;
    case T_TLS:
        *service = "SIPS+D2T";
        *prefix = "_sips._tcp.";
        return true;
    case T_SCTP:
        *service = "SIP+D2S";
        *prefix = "_sip._sctp.";
        return true;
    default:
        return false;
    }
}

static bool is_numeric_host(const char *host)
{
    const struct addrinfo hints = {AI_NUMERICHOST, AF_UNSPEC,};
    struct addrinfo *res;

    if (getaddrinfo(host, nullptr, &hints, &res) != 0) {
        return false;
    }
    freeaddrinfo(res);
    return true;
}

/* -round_robin: the addresses of host on port in the family of
 * remote_sockaddr, in remote_addresses. */
static void get_remote_addresses(const char *host, int port)
{
    const struct addrinfo hints = {AI_PASSIVE, remote_sockaddr.ss_family, SOCK_DGRAM,};
    struct addrinfo *res;
    const std::string service = std::to_string(port);

    if (getaddrinfo(host, service.c_str(), &hints, &res) != 0) {
        return;
    }
    for (const struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        remote_address a = {};
        memcpy(&a.addr, ai->ai_addr, ai->ai_addrlen);
        a.ip = get_inet_address(&a.addr);
        a.ip_w_brackets = a.addr.ss_family == AF_INET6 ? "[" + a.ip + "]" : a.ip;
        remote_addresses.push_back(std::move(a));
    }
    freeaddrinfo(res);
}

int open_connections()
{
    int status=0;
    int family_hint = PF_UNSPEC;
    local_port = 0;

    if (remote_host.empty()) {
        if ((sendMode != MODE_SERVER)) {
            ERROR("Missing remote host parameter. This scenario requires it");
        }
    } else {
        if (round_robin && transport_is_reliable(transport) && !multisocket) {
            ERROR("-round_robin needs UDP or one socket per call (-t un, tn, ln...)");
        }
        int temp_remote_port;
        remote_host = get_host_and_port(remote_host.c_str(), &temp_remote_port);
        if (temp_remote_port != 0) {
            remote_port = temp_remote_port;
        }

        /* Resolving the remote IP */
        {
            fprintf(stderr, "Resolving remote host '%s'... ", remote_host.c_str());
            struct addrinfo   hints;

            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = AF_UNSPEC;

#ifdef USE_LOCAL_IP_HINTS
            struct addrinfo * local_addr;
            int ret;
            if (!local_ip.empty()) {
                if ((ret = getaddrinfo(local_ip.c_str(), nullptr, &hints, &local_addr)) != 0) {
                    ERROR("Can't get local IP address in getaddrinfo, "
                          "local_ip='%s', ret=%d",
                          local_ip.c_str(), ret);
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

            /* An address in the family of the IP we bind on, if there
             * is one: we could not reach the others. */
            int prefer = local_ip.empty() ? AF_UNSPEC : gai_family(local_ip.c_str());
            /* A host name without a port: its NAPTR and SRV records
             * first (RFC 3263), for the transport of -t, taking the
             * first target that resolves. */
            const char *service, *prefix;
            std::string srv_name;
            bool naptr = false;
            std::vector<srv_record> records;
            if (!temp_remote_port && !is_numeric_host(remote_host.c_str()) &&
                sip_dns_service(transport, &service, &prefix)) {
                records = sip_srv_lookup(remote_host.c_str(), service, prefix, srv_name, naptr);
            }
            if (records.size() == 1 && records[0].target == ".") {
                ERROR("SRV %s: the service is not available",
                      srv_name.c_str());
            }
            bool resolved = false;
            const char *resolved_host = remote_host.c_str();
            if (records.empty()) {
                resolved = gai_getsockaddr(&remote_sockaddr, remote_host.c_str(), remote_port, hints.ai_flags,
                                           hints.ai_family, prefer) == 0;
            }
            for (const srv_record &r : records) {
                if (r.port && r.target != "." &&
                        gai_getsockaddr(&remote_sockaddr, r.target.c_str(),
                                        r.port, hints.ai_flags,
                                        hints.ai_family, prefer) == 0) {
                    remote_port = r.port;
                    resolved_host = r.target.c_str();
                    fprintf(stderr, "%sSRV %s: %s:%d. ",
                            naptr ? "NAPTR, " : "", srv_name.c_str(),
                            r.target.c_str(), remote_port);
                    resolved = true;
                    break;
                }
            }
            if (!resolved) {
                ERROR("Unknown remote host '%s'.\n"
                      "Use 'sipp -h' for details",
                      remote_host.c_str());
            }
            if (round_robin) {
                get_remote_addresses(resolved_host, remote_port);
                if (!remote_addresses.empty()) {
                    remote_sockaddr = remote_addresses[0].addr;
                }
                if (remote_addresses.size() > 1) {
                    fprintf(stderr, "%zu addresses. ", remote_addresses.size());
                }
            }

            remote_ip = get_inet_address(&remote_sockaddr);
            family_hint = remote_sockaddr.ss_family;
            if (remote_sockaddr.ss_family == AF_INET) {
                remote_ip_w_brackets = remote_ip;
            } else {
                remote_ip_w_brackets = "[" + remote_ip + "]";
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

        if (!local_ip.empty() || remote_host.empty()) {
            int ret;
            struct addrinfo * local_addr;
            struct addrinfo   hints;

            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = family_hint;

            if (!local_ip.empty()) {
                bind_specific = true;
            } else {
                /* Bind on gethostname() IP by default. This is actually
                 * buggy.  We should be able to bind on :: and decide on
                 * accept() what Contact IP we use.  Right now, if we do
                 * that, we'd send [::] in the contact and :: in the RTP
                 * as "our IP". */
                char name[256] = "";
                if (gethostname(name, sizeof(name) - 1) != 0) {
                    ERROR_NO("Can't get local hostname");
                }
                local_ip = name;
            }

            /* Resolving local IP */
            if ((ret = getaddrinfo(local_ip.c_str(), nullptr, &hints, &local_addr)) != 0) {
#ifdef EAI_ADDRFAMILY
                if (ret == EAI_ADDRFAMILY) {
                    ERROR("Network family mismatch for local (%s) and remote (%s, %d) IP", local_ip.c_str(),
                          remote_ip.c_str(), family_hint);
                }
#endif
                ERROR("Can't get local IP address in getaddrinfo, "
                      "local_ip='%s', ret=%d",
                      local_ip.c_str(), ret);
            }
            memcpy(&local_sockaddr, local_addr->ai_addr, local_addr->ai_addrlen);
            freeaddrinfo(local_addr);

            if (!bind_specific) {
                local_ip = get_inet_address(&local_sockaddr);
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
            /* Not the temp socket's port: call sockets bind to this. */
            sockaddr_update_port(&local_sockaddr, 0);
            local_ip = get_inet_address(&local_sockaddr);
        }

        /* Store local addr info for rsa option */
        memcpy(&local_addr_storage, &local_sockaddr, sizeof(local_sockaddr));

        if (local_sockaddr.ss_family == AF_INET) {
            local_ip_w_brackets = local_ip;
            if (!bind_specific) {
                _RCAST(struct sockaddr_in*, &local_sockaddr)->sin_addr.s_addr = INADDR_ANY;
            }
        } else {
            local_ip_is_ipv6 = true;
            local_ip_w_brackets = "[" + local_ip + "]";
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
    std::string peripaddr;
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
                    peripaddr = inFiles[ip_file]->getField(0, peripfield);
                    if (gai_getsockaddr(&local_sockaddr, peripaddr.c_str(), nullptr, AI_PASSIVE, AF_UNSPEC) != 0) {
                        ERROR("Unknown host '%s'.\n"
                              "Use 'sipp -h' for details",
                              peripaddr.c_str());
                    }
                } else {
                    if (gai_getsockaddr(&local_sockaddr, local_ip.c_str(), nullptr, AI_PASSIVE, AF_UNSPEC) != 0) {
                        ERROR("Unknown host '%s'.\n"
                              "Use 'sipp -h' for details",
                              local_ip.c_str());
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
                peripaddr = inFiles[ip_file]->getField(0, peripfield);
                if (gai_getsockaddr(&local_sockaddr, peripaddr.c_str(), nullptr, AI_PASSIVE, AF_UNSPEC) != 0) {
                    ERROR("Unknown host '%s'.\n"
                          "Use 'sipp -h' for details",
                          peripaddr.c_str());
                }
            } else {
                if (gai_getsockaddr(&local_sockaddr, local_ip.c_str(), nullptr, AI_PASSIVE, AF_UNSPEC) != 0) {
                    ERROR("Unknown host '%s'.\n"
                          "Use 'sipp -h' for details",
                          local_ip.c_str());
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
        add_perip_socket(peripaddr, &local_sockaddr, main_socket);
    }

    // Create additional server sockets when running in socket per
    // IP address mode.
    if (peripsocket && sendMode == MODE_SERVER) {
        struct sockaddr_storage server_sockaddr;
        SIPpSocket *sock;

        unsigned int lines = inFiles[ip_file]->numLines();
        for (unsigned int i = 0; i < lines; i++) {
            const std::string server_ip = inFiles[ip_file]->getField(i, peripfield);
            auto j = map_perip_fd.find(server_ip);

            if (j == map_perip_fd.end()) {
                if (gai_getsockaddr(&server_sockaddr, server_ip.c_str(), local_port, AI_PASSIVE, AF_UNSPEC) != 0) {
                    ERROR("Unknown remote host '%s'.\n"
                          "Use 'sipp -h' for details",
                          server_ip.c_str());
                }
                if (find_perip_socket(server_ip, &server_sockaddr)) {
                    continue;
                }

                bool is_ipv6 = (server_sockaddr.ss_family == AF_INET6);

                if ((sock = new_sipp_socket(is_ipv6, transport)) == nullptr) {
                    ERROR_NO("Unable to get server socket");
                }

                sipp_customize_socket(sock);
                if (sipp_bind_socket(sock, &server_sockaddr, nullptr)) {
                    ERROR_NO("Unable to bind server socket");
                }

                add_perip_socket(server_ip, &server_sockaddr, sock);
            }
        }
    }

    /* A 3PCC controller B or slave scenario that starts with a <recv>
     * still has its calls created by a command, like a client's. */
    if ((!multisocket) && transport_is_reliable(transport) &&
        (sendMode != MODE_SERVER ||
         (!remote_host.empty() && (thirdPartyMode == MODE_3PCC_CONTROLLER_B || thirdPartyMode == MODE_SLAVE)))) {
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


    if (transport_is_reliable(transport)) {
        if (listen(main_socket->ss_fd, 100)) {
            ERROR_NO("Unable to listen main socket");
        }
    }

    /* Trying to connect to Twin Sipp in 3PCC mode */
    if (twinSippMode) {
        if (thirdPartyMode == MODE_3PCC_CONTROLLER_A || thirdPartyMode == MODE_3PCC_A_PASSIVE) {
            connect_to_peer(twinSippHost.c_str(), twinSippPort, &twinSipp_sockaddr, &twinSippSocket);
        } else if (thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
            connect_local_twin_socket();
        } else {
            ERROR("TwinSipp Mode enabled but thirdPartyMode is different "
                  "from 3PCC_CONTROLLER_B and 3PCC_CONTROLLER_A\n");
        }
    } else if (extendedTwinSippMode) {
        if (thirdPartyMode == MODE_MASTER || thirdPartyMode == MODE_MASTER_PASSIVE) {
            twinSippHost = get_host_and_port(get_peer_addr(*master_name).c_str(), &twinSippPort);
            connect_local_twin_socket();
            connect_to_all_peers();
        } else if (thirdPartyMode == MODE_SLAVE) {
            twinSippHost = get_host_and_port(get_peer_addr(*slave_number).c_str(), &twinSippPort);
            connect_local_twin_socket();
        } else {
            ERROR("extendedTwinSipp Mode enabled but thirdPartyMode is different "
                  "from MASTER and SLAVE\n");
        }
    }

    return status;
}


static void connect_to_peer(const char *peer_host, int peer_port, struct sockaddr_storage *peer_sockaddr,
                            SIPpSocket **peer_socket)
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

SIPpSocket **get_peer_socket(const char *peer)
{
    peer_map::iterator peer_it;
    peer_it = peers.find(peer_map::key_type(peer));
    if (peer_it != peers.end()) {
        return &peer_it->second.peer_socket;
    } else {
        ERROR("get_peer_socket: Peer %s not found", peer);
    }
    return nullptr;
}

const std::string &get_peer_addr(const std::string &peer)
{
    peer_addr_map::const_iterator peer_addr_it = peer_addrs.find(peer);
    if (peer_addr_it == peer_addrs.end()) {
        ERROR("get_peer_addr: Peer %s not found", peer.c_str());
    }
    return peer_addr_it->second;
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

void connect_local_twin_socket()
{
    /* Resolving the listener IP */
    printf("Resolving listener address : %s...\n", twinSippHost.c_str());
    bool is_ipv6 = false;

    /* Resolving twin IP */
    if (gai_getsockaddr(&twinSipp_sockaddr, twinSippHost.c_str(), twinSippPort, AI_PASSIVE, AF_UNSPEC) != 0) {
        ERROR("Unknown twin host '%s'.\n"
              "Use 'sipp -h' for details",
              twinSippHost.c_str());
    }

    if (twinSipp_sockaddr.ss_family == AF_INET6) {
        is_ipv6 = true;
    }

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
        infos.peer_host = get_host_and_port(infos.peer_host.c_str(), &infos.peer_port);
        connect_to_peer(infos.peer_host.c_str(), infos.peer_port, &(infos.peer_sockaddr), &(infos.peer_socket));
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

/* A datagram socket gives one message per read, and a poll found it
 * readable once: when the message it read is processed and its buffer is
 * empty, read the next datagram it has, if any, so that the messages
 * behind the first do not wait for the next poll, which a slow pass over
 * the calls may hold up. Processing the message may have freed the
 * socket, which moves another into its place: then leave it alone. */
static void read_next_datagram(SIPpSocket *sock, unsigned pollnfds_before)
{
    if (pollnfds == pollnfds_before && sock->ss_transport == T_UDP &&
            !sock->message_ready()) {
        /* Nothing more, or an error, which the next poll reports. */
        sock->empty();
    }
}

/* How a pass goes: a poll() one reads every socket that has something,
 * then processes the messages of all of them in turns, up to
 * max_recv_loops, and the next pass processes those left before it polls
 * again; an epoll one processes the messages of each socket as it reads
 * it, of up to max_recv_loops ready ones. */
static const bool read_all_first = std::is_same<Poller, PollPoller>::value;

void SIPpSocket::pollset_process(int wait)
{
    int rs; /* Number of times to execute recv().
            For TCP with 1 socket per call:
                no. of events returned by poll
            For UDP and TCP with 1 global socket:
                recv_count is a flag that stays up as
                long as there's data to read */

    check_ws_handshakes();

    int loops = max_recv_loops;

    /* What index should we try reading from? */
    static size_t read_index;

    /* Process the messages that the sockets hold, in turns. */
    auto process_pending_messages = [&loops]() {
        if (read_index >= pollnfds) {
            read_index = 0;
        }

        while (pending_messages && loops > 0) {
            update_clock_tick();
            if (sockets[read_index]->ss_msglen) {
                SIPpSocket *sock = sockets[read_index];
                unsigned before = pollnfds;
                struct sockaddr_storage src;
                char msg[SIPP_MAX_MSG_SIZE];
                ssize_t len = sock->read_message(msg, sizeof(msg), &src);
                if (len > 0) {
                    process_message(sock, msg, len, &src);
                } else {
                    assert(0);
                }
                loops--;
                read_next_datagram(sock, before);
            }
            read_index = (read_index + 1) % pollnfds;
        }
    };

    if (read_all_first) {
        /* We need to process any messages that we have left over. */
        process_pending_messages();

        /* Don't read more data if we still have some left over. */
        if (pending_messages) {
            return;
        }
    }

    /* Get socket events: poll() has them all, and epoll ignores the wait
     * parameter and always waits - when establishing TCP connections, the
     * alternative is that we tight-loop. */
    int max = read_all_first ? poller.size() : max_recv_loops;
    if (poll_events.size() < (size_t)max) {
        poll_events.resize(max);
    }
    rs = poller.wait(read_all_first ? (wait ? 1 : 0) : 1, poll_events.data(), max);
    if (!read_all_first) {
        // If we're receiving as many events as possible, flag CPU congestion
        cpu_max = (rs > (max_recv_loops - 2));
    }
    if (rs < 0 && errno == EINTR) {
        return;
    }

    /* We need to flush all sockets and pull data into all of our buffers. */
    poll_nevents = rs > 0 ? rs : 0;
    for (int event_idx = 0; event_idx < poll_nevents; event_idx++) {
        SIPpSocket *sock = (SIPpSocket *)(uintptr_t)poll_events[event_idx].key;
        unsigned events = poll_events[event_idx].events;
        int ret = 0;

        /* None: it left the poller already (see poll_remove()). */
        if (!sock) {
            continue;
        }

        if (events & POLLER_OUT) {

#ifdef USE_SCTP
            if (sock->ss_transport == T_SCTP && sock->sctpstate != SCTP_UP);
            else
#endif
            {
                /* We can flush this socket. */
                TRACE_MSG("Exit problem event on socket %d \n", sock->ss_fd);
                sock->ss_poll_writable = false;
                if (!poller.modify(sock->ss_fd, POLLER_IN, (uintptr_t)sock)) {
                    ERROR_NO("Failed to clear POLLOUT");
                }
                sock->ss_congested = false;

                unsigned before = pollnfds;
                sock->flush();
                /* A write error may drop the connection. */
                if (pollnfds != before) {
                    continue;
                }
            }
        }

        if (sock->to_empty(events & POLLER_IN)) {
            /* We can empty this socket. */
            if (transport_is_reliable(transport) && sock == main_socket) {
                /* A peer that failed the TLS handshake got dropped (see
                 * accept()): nothing to do for it. */
                sock->accept();
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
                /* Reading may drop the connection already: the flush()
                 * that an SCTP_COMM_UP notification makes can fail. */
                unsigned before = pollnfds;
                if ((ret = sock->empty()) <= 0) {
#ifdef USE_SCTP
                    if (sock->ss_transport == T_SCTP && ret == -2 && pollnfds == before);
                    else
#endif
                    {
                        if (ret != -2) {
                            ret = sock->read_error(ret);
                        }
                        /* An error invalidates the socket too. */
                        if (ret == 0 || pollnfds != before) {
                            continue;
                        }
                    }
                }
            }
        }

        /* Here the logic diverges: an epoll pass stays with this socket
         * and handles its messages; a poll() one waits until after the
         * loop, and spins through the pending messages of all. */
        if (read_all_first) {
            continue;
        }

        unsigned old_pollnfds = pollnfds;
        update_clock_tick();
        /* Keep processing messages until this socket is freed (changing
         * the number of file descriptors) or we run out of messages,
         * reading the next datagram a socket has once its buffer is
         * empty (see read_next_datagram()). */
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
            if (--loops > 0) {
                read_next_datagram(sock, old_pollnfds);
            }
        }
    }
    poll_nevents = 0;

    if (read_all_first) {
        /* We need to process any new messages that we read. */
        process_pending_messages();
        cpu_max = (loops <= 0);
    }
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
    EXPECT_EQ("abc", get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: abc\r\nCall-ID: def\r\n\r\n"));
}

TEST(get_trimmed_call_id, withslashes) {
    EXPECT_EQ("abc2", get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: ///abc2\r\nCall-ID: def\r\n\r\n"));
    EXPECT_EQ("abc3", get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: abc2///abc3\r\nCall-ID: def\r\n\r\n"));
    EXPECT_EQ("abc4///abc5",
              get_trimmed_call_id("OPTIONS..\r\nBla: X\r\nCall-ID: abc3///abc4///abc5\r\nCall-ID: def\r\n\r\n"));
}

#endif //GTEST
