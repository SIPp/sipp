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
 *           Venkatesh
 *           Lee Ballard
 *           Guillaume TEISSIER from FTR&D
 *           Wolfgang Beck
 *           Marc Van Diest from Belgacom
 *           Charles P. Wright from IBM Research
 *           Michael Stovenour
 */

#include <stdlib.h>
#include "sipp.hpp"
#ifdef HAVE_GSL
#include <gsl/gsl_rng.h>
#include <gsl/gsl_randist.h>
#include <gsl/gsl_cdf.h>
#endif

/************************ Class Constructor *************************/

message::message(int index, const char *desc)
{
    this->index = index;
    this->desc = desc;
    pause_distribution = NULL; // delete on exit
    pause_variable = -1;
    pause_desc = NULL; // free on exit
    sessions = 0;
    bShouldRecordRoutes = 0;
    bShouldAuthenticate = 0;

    send_scheme = NULL; // delete on exit
    retrans_delay = 0;
    timeout = 0;

    recv_response = 0;
    recv_request = NULL; // free on exit
    optional = 0;
    advance_state = true;
    regexp_match = 0;
    regexp_compile = NULL; // regfree (if not NULL) and free on exit

    /* Anyway */
    start_rtd = 0;
    stop_rtd  = 0;
    repeat_rtd = 0;
    lost = -1;
    crlf = 0;
    hide = 0;
    display_str = NULL; // free on exit
    test = -1;
    condexec = -1;
    condexec_inverse = false;
    chance = 0;/* meaning always */
    next = -1;
    nextLabel = NULL; // free on exit
    on_timeout = -1;
    onTimeoutLabel = NULL; // free on exit
    timewait = false;

    /* 3pcc extended mode */
    peer_dest = NULL; // free on exit
    peer_src = NULL; // free on exit

    /* Statistics */
    nb_sent = 0;
    nb_recv = 0;
    nb_sent_retrans = 0;
    nb_recv_retrans = 0;
    nb_timeout = 0;
    nb_unexp = 0;
    nb_lost = 0;
    counter = 0;

    M_actions = NULL; // delete on exit

    M_type = 0;

    M_sendCmdData = NULL; // delete on exit
    M_nbCmdSent   = 0;
    M_nbCmdRecv   = 0;

    content_length_flag = ContentLengthNoPresent;

    /* How to match responses to this message. */
    start_txn = 0;
    response_txn = 0;
    ack_txn = 0;
    recv_response_for_cseq_method_list = NULL; // free on exit
}

message::~message()
{
  delete(pause_distribution);
  free(pause_desc);
  delete(send_scheme);
  free(recv_request);
  if (regexp_compile != NULL) {
    regfree(regexp_compile);
  }
  free(regexp_compile);

  free(display_str);
  free(nextLabel);
  free(onTimeoutLabel);

  free(peer_dest);
  free(peer_src);

  delete(M_actions);
  delete(M_sendCmdData);
  free(recv_response_for_cseq_method_list);
}

/******** Global variables which compose the scenario file **********/

scenario      *main_scenario;
scenario      *ooc_scenario;
scenario      *aa_scenario;
scenario      *display_scenario;

/* This mode setting refers to whether we open calls autonomously (MODE_CLIENT)
 * or in response to requests (MODE_SERVER). */
int creationMode  = MODE_CLIENT;
/* Send mode. Do we send to a fixed address or to the last one we got. */
int sendMode  = MODE_CLIENT;
/* This describes what our 3PCC behavior is. */
int thirdPartyMode = MODE_3PCC_NONE;

/*************** Helper functions for various types *****************/
long get_long(const char *ptr, const char *what)
{
    char *endptr;
    long ret;

    ret = strtol(ptr, &endptr, 0);
    if (*endptr) {
        ERROR("%s, \"%s\" is not a valid integer!\n", what, ptr);
    }
    return ret;
}

unsigned long long get_long_long(const char *ptr, const char *what)
{
    char *endptr;
    unsigned long long ret;

    ret = strtoull(ptr, &endptr, 0);
    if (*endptr) {
        ERROR("%s, \"%s\" is not a valid integer!\n", what, ptr);
    }
    return ret;
}

/* This function returns a time in milliseconds from a string.
 * The multiplier is used to convert from the default input type into
 * milliseconds.  For example, for seconds you should use 1000 and for
 * milliseconds use 1. */
long get_time(const char *ptr, const char *what, int multiplier)
{
    char *endptr;
    const char *p;
    long ret;
    double dret;
    int i;

    if (!isdigit(*ptr)) {
        ERROR("%s, \"%s\" is not a valid time!\n", what, ptr);
    }

    for (i = 0, p = ptr; *p; p++) {
        if (*p == ':') {
            i++;
        }
    }

    if (i == 1) { /* mm:ss */
        ERROR("%s, \"%s\" mm:ss not implemented yet!\n", what, ptr);
    } else if (i == 2) { /* hh:mm:ss */
        ERROR("%s, \"%s\" hh:mm:ss not implemented yet!\n", what, ptr);
    } else if (i != 0) {
        ERROR("%s, \"%s\" is not a valid time!\n", what, ptr);
    }

    dret = strtod(ptr, &endptr);
    if (*endptr) {
        if (!strcmp(endptr, "s")) { /* Seconds */
            ret = (long)(dret * 1000);
        } else if (!strcmp(endptr, "ms")) { /* Milliseconds. */
            ret = (long)dret;
        } else if (!strcmp(endptr, "m")) { /* Minutes. */
            ret = (long)(dret * 60000);
        } else if (!strcmp(endptr, "h")) { /* Hours. */
            ret = (long)(dret * 60 * 60 * 1000);
        } else {
            ERROR("%s, \"%s\" is not a valid time!\n", what, ptr);
        }
    } else {
        ret = (long)(dret * multiplier);
    }
    return ret;
}

double get_double(const char *ptr, const char *what)
{
    char *endptr;
    double ret;

    ret = strtod(ptr, &endptr);
    if (*endptr) {
        ERROR("%s, \"%s\" is not a floating point number!\n", what, ptr);
    }
    return ret;
}

#ifdef PCAPPLAY
/* Return static buffer to xml value, as with xp_get_value().
 * If the value is enclosed in [brackets], it is assumed to be
 * a command-line supplied keyword value (-key). */
static const char* xp_get_keyword_value(const char *name)
{
    const char* ptr = xp_get_value(name);
    size_t len;

    if (ptr && ptr[0] == '[' && (len = strlen(ptr)) && ptr[len - 1] == ']') {
        int i = 0;
        len -= 2; /* without the brackets */
        while (generic[i]) {
            const char* keyword = *generic[i];
            if (strncmp(ptr + 1, keyword, len) == 0 && strlen(keyword) == len) {
                const char* value = *(generic[i] + 1);
                return strdup(value);
            }
            ++i;
        }
        ERROR("%s \"%s\" looks like a keyword value, but keyword not supplied!\n", name, ptr);
    }

    return ptr;
}
#endif

static char* xp_get_string(const char *name, const char *what)
{
    char *ptr;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }

    return strdup(ptr);
}

static double xp_get_double(const char *name, const char *what)
{
    char *ptr;
    char *helptext;
    double val;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }
    helptext = (char *)malloc(100 + strlen(name) + strlen(what));
    sprintf(helptext, "%s '%s' parameter", what, name);
    val = get_double(ptr, helptext);
    free(helptext);

    return val;
}

static long xp_get_long(const char *name, const char *what)
{
    char *ptr;
    char *helptext;
    long val;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }
    helptext = (char *)malloc(100 + strlen(name) + strlen(what));
    sprintf(helptext, "%s '%s' parameter", what, name);
    val = get_long(ptr, helptext);
    free(helptext);

    return val;
}

static long xp_get_long(const char *name, const char *what, long defval)
{
    if (!(xp_get_value(name))) {
        return defval;
    }
    return xp_get_long(name, what);
}


static bool xp_get_bool(const char *name, const char *what)
{
    char *ptr;
    char *helptext;
    bool val;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }
    helptext = (char *)malloc(100 + strlen(name) + strlen(what));
    sprintf(helptext, "%s '%s' parameter", what, name);
    val = get_bool(ptr, helptext);
    free(helptext);

    return val;
}

static bool xp_get_bool(const char *name, const char *what, bool defval)
{
    if (!(xp_get_value(name))) {
        return defval;
    }
    return xp_get_bool(name, what);
}

int scenario::get_txn(const char *txnName, const char *what, bool start, bool isInvite, bool isAck)
{
    /* Check the name's validity. */
    if (txnName[0] == '\0') {
        ERROR("Variable names may not be empty for %s\n", what);
    }
    if (strcspn(txnName, "$,") != strlen(txnName)) {
        ERROR("Variable names may not contain $ or , for %s\n", what);
    }

    /* If this transaction has already been used, then we have nothing to do. */
    str_int_map::iterator txn_it = txnMap.find(txnName);
    if (txn_it != txnMap.end()) {
        if (start) {
            /* We need to fill in the invite field. */
            transactions[txn_it->second - 1].started++;
        } else if (isAck) {
            transactions[txn_it->second - 1].acks++;
        } else {
            transactions[txn_it->second - 1].responses++;
        }
        return txn_it->second;
    }

    /* Assign this variable the next slot. */
    struct txnControlInfo transaction;

    transaction.name = strdup(txnName);
    if (start) {
        transaction.started = 1;
        transaction.responses = 0;
        transaction.acks = 0;
        transaction.isInvite = isInvite;
    } else if (isAck) {
        /* Does not start or respond to this txn. */
        transaction.started = 0;
        transaction.responses = 0;
        transaction.acks = 1;
        transaction.isInvite = false;
    } else {
        transaction.started = 0;
        transaction.responses = 1;
        transaction.acks = 0;
        transaction.isInvite = false;
    }

    transactions.push_back(transaction);
    int txnNum = transactions.size();
    txnMap[txnName] = txnNum;

    return txnNum;
}

int scenario::find_var(const char *varName)
{
    return allocVars->find(varName, false);
}

int scenario::get_var(const char *varName, const char *what)
{
    /* Check the name's validity. */
    if (varName[0] == '\0') {
        ERROR("Transaction names may not be empty for %s\n", what);
    }
    if (strcspn(varName, "$,") != strlen(varName)) {
        ERROR("Transaction names may not contain $ or , for %s\n", what);
    }

    return allocVars->find(varName, true);
}

int scenario::xp_get_var(const char *name, const char *what)
{
    char *ptr;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' variable parameter.", what, name);
    }

    return get_var(ptr, what);
}

static int xp_get_optional(const char *name, const char *what)
{
    char *ptr = xp_get_value(name);

    if (!ptr) {
        return OPTIONAL_FALSE;
    }

    if(!strcmp(ptr, "true")) {
        return OPTIONAL_TRUE;
    } else if(!strcmp(ptr, "global")) {
        return OPTIONAL_GLOBAL;
    } else if(!strcmp(ptr, "false")) {
        return OPTIONAL_FALSE;
    } else {
        ERROR("Could not understand optional value for %s: %s", what, ptr);
    }

    return OPTIONAL_FALSE;
}


int scenario::xp_get_var(const char *name, const char *what, int defval)
{
    char *ptr;

    if (!(ptr = xp_get_value(name))) {
        return defval;
    }

    return xp_get_var(name, what);
}

bool get_bool(const char *ptr, const char *what)
{
    char *endptr;
    long ret;

    if (!strcasecmp(ptr, "true")) {
        return true;
    }
    if (!strcasecmp(ptr, "false")) {
        return false;
    }

    ret = strtol(ptr, &endptr, 0);
    if (*endptr) {
        ERROR("%s, \"%s\" is not a valid boolean!\n", what, ptr);
    }
    return ret ? true : false;
}

/* Pretty print a time. */
int time_string(double ms, char *res, int reslen)
{
    if (ms < 10000) {
        /* Less then 10 seconds we represent accurately. */
        if ((int)(ms + 0.9999) == (int)(ms)) {
            /* We have an integer, or close enough to it. */
            return snprintf(res, reslen, "%dms", (int)ms);
        } else {
            if (ms < 1000) {
                return snprintf(res, reslen, "%.2lfms", ms);
            } else {
                return snprintf(res, reslen, "%.1lfms", ms);
            }
        }
    } else if (ms < 60000) {
        /* We round to 100ms for times less than a minute. */
        return snprintf(res, reslen, "%.1fs", ms/1000);
    } else if (ms < 60 * 60000) {
        /* We round to 1s for times more than a minute. */
        int s = (unsigned int)(ms / 1000);
        int m = s / 60;
        s %= 60;
        return snprintf(res, reslen, "%d:%02d", m, s);
    } else {
        int s = (unsigned int)(ms / 1000);
        int m = s / 60;
        int h = m / 60;
        s %= 60;
        m %= 60;
        return snprintf(res, reslen, "%d:%02d:%02d", h, m, s);
    }
}

/* For backwards compatibility, we assign "true" to slot 1, false to 0, and
 * allow other valid integers. */
int scenario::get_rtd(const char *ptr, bool start)
{
    if(!strcmp(ptr, (char *)"false"))
        return 0;

    if(!strcmp(ptr, (char *)"true"))
        return stats->findRtd("1", start);

    return stats->findRtd(ptr, start);
}

/* Get a counter */
int scenario::get_counter(const char *ptr, const char *what)
{
    /* Check the name's validity. */
    if (ptr[0] == '\0') {
        ERROR("Counter names names may not be empty for %s\n", what);
    }
    if (strcspn(ptr, "$,") != strlen(ptr)) {
        ERROR("Counter names may not contain $ or , for %s\n", what);
    }

    return stats->findCounter(ptr, true);
}


/* Some validation functions. */

void scenario::validate_variable_usage()
{
    allocVars->validate();
}

void scenario::validate_txn_usage()
{
    for (unsigned int i = 0; i < transactions.size(); i++) {
        if(transactions[i].started == 0) {
            ERROR("Transaction %s is never started!\n", transactions[i].name);
        } else if(transactions[i].responses == 0) {
            ERROR("Transaction %s has no responses defined!\n", transactions[i].name);
        }
        if (transactions[i].isInvite && transactions[i].acks == 0) {
            ERROR("Transaction %s is an INVITE transaction without an ACK!\n", transactions[i].name);
        }
        if (!transactions[i].isInvite && (transactions[i].acks > 0)) {
            ERROR("Transaction %s is a non-INVITE transaction with an ACK!\n", transactions[i].name);
        }
    }
}

/* Apply the next and ontimeout labels according to our map. */
void scenario::apply_labels(msgvec v, str_int_map labels)
{
    for (unsigned int i = 0; i < v.size(); i++) {
        if (v[i]->nextLabel) {
            str_int_map::iterator label_it = labels.find(v[i]->nextLabel);
            if (label_it == labels.end()) {
                ERROR("The label '%s' was not defined (index %d, next attribute)\n", v[i]->nextLabel, i);
            }
            v[i]->next = label_it->second;
        }
        if (v[i]->onTimeoutLabel) {
            str_int_map::iterator label_it = labels.find(v[i]->onTimeoutLabel);
            if (label_it == labels.end()) {
                ERROR("The label '%s' was not defined (index %d, ontimeout attribute)\n", v[i]->onTimeoutLabel, i);
            }
            v[i]->on_timeout = label_it->second;
        }
    }
}

int get_cr_number(const char *src)
{
    int res=0;
    while(*src) {
        if(*src == '\n') res++;
        src++;
    }
    return res;
}

static char* clean_cdata(char *ptr, int *removed_crlf = NULL)
{
    char * msg;

    while((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n')) ptr++;

    msg = (char *) malloc(strlen(ptr) + 3);
    if(!msg) {
        ERROR("Memory Overflow");
    }
    strcpy(msg, ptr);

    ptr = msg + strlen(msg);
    ptr --;

    while((ptr >= msg) &&
            ((*ptr == ' ')  ||
             (*ptr == '\t') ||
             (*ptr == '\n'))) {
        if(*ptr == '\n' && removed_crlf) {
            (*removed_crlf)++;
        }
        *ptr-- = 0;
    }

    if(!strstr(msg, "\n\n")) {
        strcat(msg, "\n\n");
    }

    if(ptr == msg) {
        ERROR("Empty cdata in xml scenario file");
    }
    while ((ptr = strstr(msg, "\n "))) {
        memmove(ptr + 1, ptr + 2, strlen(ptr) - 1);
    }
    while ((ptr = strstr(msg, " \n"))) {
        memmove(ptr, ptr + 1, strlen(ptr));
    }
    while ((ptr = strstr(msg, "\n\t"))) {
        memmove(ptr + 1, ptr + 2, strlen(ptr) - 1);
    }
    while ((ptr = strstr(msg, "\t\n"))) {
        memmove(ptr, ptr + 1, strlen(ptr));
    }

    return msg;
}



/********************** Scenario File analyser **********************/

void scenario::checkOptionalRecv(char *elem, unsigned int scenario_file_cursor)
{
    if (last_recv_optional) {
        ERROR("<recv> before <%s> sequence without a mandatory message. Please remove one 'optional=true' (element %d).", elem, scenario_file_cursor);
    }
    last_recv_optional = false;
}

scenario::scenario(char * filename, int deflt)
{
    char * elem;
    char *method_list = NULL;
    unsigned int scenario_file_cursor = 0;
    int    L_content_length = 0 ;
    char * peer;
    const char* cptr;

    last_recv_optional = false;

    if(filename) {
        if(!xp_set_xml_buffer_from_file(filename)) {
            ERROR("Unable to load or parse '%s' xml scenario file", filename);
        }
    } else {
        if(!xp_set_xml_buffer_from_string(default_scenario[deflt])) {
            ERROR("Unable to load default xml scenario file");
        }
    }

    stats = new CStat();
    allocVars = new AllocVariableTable(userVariables);

    hidedefault = false;

    elem = xp_open_element(0);
    if (!elem) {
        ERROR("No element in xml scenario file");
    }
    if(strcmp("scenario", elem)) {
        ERROR("No 'scenario' section in xml scenario file");
    }

    if ((cptr = xp_get_value("name"))) {
        name = strdup(cptr);
    } else {
        name = strdup("");
    }

    duration = 0;
    found_timewait = false;

    scenario_file_cursor = 0;

    while ((elem = xp_open_element(scenario_file_cursor))) {
        char * ptr;
        scenario_file_cursor ++;

        if(!strcmp(elem, "CallLengthRepartition")) {
            ptr = xp_get_string("value", "CallLengthRepartition");
            stats->setRepartitionCallLength(ptr);
            free(ptr);
        } else if(!strcmp(elem, "ResponseTimeRepartition")) {
            ptr = xp_get_string("value", "ResponseTimeRepartition");
            stats->setRepartitionResponseTime(ptr);
            free(ptr);
        } else if(!strcmp(elem, "Global")) {
            ptr = xp_get_string("variables", "Global");

            char **       currentTabVarName = NULL;
            int           currentNbVarNames;

            createStringTable(ptr, &currentTabVarName, &currentNbVarNames);
            for (int i = 0; i < currentNbVarNames; i++) {
                globalVariables->find(currentTabVarName[i], true);
            }
            freeStringTable(currentTabVarName, currentNbVarNames);
            free(ptr);
        } else if(!strcmp(elem, "User")) {
            ptr = xp_get_string("variables", "User");

            char **       currentTabVarName = NULL;
            int           currentNbVarNames;

            createStringTable(ptr, &currentTabVarName, &currentNbVarNames);
            for (int i = 0; i < currentNbVarNames; i++) {
                userVariables->find(currentTabVarName[i], true);
            }
            freeStringTable(currentTabVarName, currentNbVarNames);
            free(ptr);
        } else if(!strcmp(elem, "Reference")) {
            ptr = xp_get_string("variables", "Reference");

            char **       currentTabVarName = NULL;
            int           currentNbVarNames;

            createStringTable(ptr, &currentTabVarName, &currentNbVarNames);
            for (int i = 0; i < currentNbVarNames; i++) {
                int id = allocVars->find(currentTabVarName[i], false);
                if (id == -1) {
                    ERROR("Could not reference non-existant variable '%s'", currentTabVarName[i]);
                }
            }
            freeStringTable(currentTabVarName, currentNbVarNames);
            free(ptr);
        } else if(!strcmp(elem, "DefaultMessage")) {
            char *id = xp_get_string("id", "DefaultMessage");
            if(!(ptr = xp_get_cdata())) {
                ERROR("No CDATA in 'send' section of xml scenario file");
            }
            char *msg = clean_cdata(ptr);
            set_default_message(id, msg);
            free(id);
            /* XXX: This should really be per scenario. */
        } else if(!strcmp(elem, "label")) {
            ptr = xp_get_string("id", "label");
            if (labelMap.find(ptr) != labelMap.end()) {
                ERROR("The label name '%s' is used twice.", ptr);
            }
            labelMap[ptr] = messages.size();
            free(ptr);
        } else if (!strcmp(elem, "init")) {
            /* We have an init section, which must be full of nops or labels. */
            int nop_cursor = 0;
            char *initelem;
            while ((initelem = xp_open_element(nop_cursor++))) {
                if (!strcmp(initelem, "nop")) {
                    /* We should parse this. */
                    message *nopmsg = new message(initmessages.size(), "scenario initialization");
                    initmessages.push_back(nopmsg);
                    nopmsg->M_type = MSG_TYPE_NOP;
                    getCommonAttributes(nopmsg);
                } else if (!strcmp(initelem, "label")) {
                    /* Add an init label. */
                    cptr = xp_get_value("id");
                    if (initLabelMap.find(cptr) != initLabelMap.end()) {
                        ERROR("The label name '%s' is used twice.", cptr);
                    }
                    initLabelMap[cptr] = initmessages.size();
                } else {
                    ERROR("Invalid element in an init stanza: '%s'", initelem);
                }
                xp_close_element();
            }
        } else { /** Message Case */
            if (found_timewait) {
                ERROR("<timewait> can only be the last message in a scenario!\n");
            }
            message *curmsg = new message(messages.size(), name ? name : "unknown scenario");
            messages.push_back(curmsg);

            if(!strcmp(elem, "send")) {
                checkOptionalRecv(elem, scenario_file_cursor);
                curmsg->M_type = MSG_TYPE_SEND;
                /* Sent messages descriptions */
                if(!(ptr = xp_get_cdata())) {
                    ERROR("No CDATA in 'send' section of xml scenario file");
                }

                int removed_clrf = 0;
                char * msg = clean_cdata(ptr, &removed_clrf);

                L_content_length = xp_get_content_length(msg);
                switch (L_content_length) {
                case  -1 :
                    // the msg does not contain content-length field
                    break ;
                case  0 :
                    curmsg -> content_length_flag =
                        message::ContentLengthValueZero;   // Initialize to No present
                    break ;
                default :
                    curmsg -> content_length_flag =
                        message::ContentLengthValueNoZero;   // Initialize to No present
                    break ;
                }

                if((msg[strlen(msg) - 1] != '\n') && (removed_clrf)) {
                    strcat(msg, "\n");
                }
                char *tsrc = msg;
                while(*tsrc++);
                curmsg -> send_scheme = new SendingMessage(this, msg);
                free(msg);

                // If this is a request we are sending, then store our transaction/method matching information.
                if (!curmsg->send_scheme->isResponse()) {
                    char *method = curmsg->send_scheme->getMethod();
                    bool isInvite = !strcmp(method, "INVITE");
                    bool isAck = !strcmp(method, "ACK");

                    if ((cptr = xp_get_value("start_txn"))) {
                        if (isAck) {
                            ERROR("An ACK message can not start a transaction!");
                        }
                        curmsg->start_txn = get_txn(cptr, "start transaction", true, isInvite, false);
                    } else if ((cptr = xp_get_value("ack_txn"))) {
                        if (!isAck) {
                            ERROR("The ack_txn attribute is valid only for ACK messages!");
                        }
                        curmsg->ack_txn = get_txn(cptr, "ack transaction", false, false, true);
                    } else {
                        int len = method_list ? strlen(method_list) : 0;
                        method_list = (char *)realloc(method_list, len + strlen(method) + 1);
                        if (!method_list) {
                            ERROR_NO("Out of memory allocating method_list!");
                        }
                        strcpy(method_list + len, method);
                    }
                } else {
                    if (xp_get_value("start_txn")) {
                        ERROR("Responses can not start a transaction");
                    }
                    if (xp_get_value("ack_txn")) {
                        ERROR("Responses can not ACK a transaction");
                    }
                }

                if (xp_get_value("response_txn")) {
                    ERROR("response_txn can only be used for received messages.");
                }

                curmsg -> retrans_delay = xp_get_long("retrans", "retransmission timer", 0);
                curmsg -> timeout = xp_get_long("timeout", "message send timeout", 0);
            } else if (!strcmp(elem, "recv")) {
                curmsg->M_type = MSG_TYPE_RECV;
                /* Received messages descriptions */
                if((cptr = xp_get_value("response"))) {
                    curmsg ->recv_response = get_long(cptr, "response code");
                    if (method_list) {
                        curmsg->recv_response_for_cseq_method_list = strdup(method_list);
                    }
                    if ((cptr = xp_get_value("response_txn"))) {
                        curmsg->response_txn = get_txn(cptr, "transaction response", false, false, false);
                    }
                }

                if ((cptr = xp_get_value("request"))) {
                    curmsg->recv_request = strdup(cptr);
                    if (xp_get_value("response_txn")) {
                        ERROR("response_txn can only be used for received responses.");
                    }
                }

                curmsg->optional = xp_get_optional("optional", "recv");
                last_recv_optional = curmsg->optional;
                curmsg->advance_state = xp_get_bool("advance_state", "recv", true);
                if (!curmsg->advance_state && curmsg->optional == OPTIONAL_FALSE) {
                    ERROR("advance_state is allowed only for optional messages (index = %zu)\n", messages.size() - 1);
                }

                if ((cptr = xp_get_value("regexp_match"))) {
                    if (!strcmp(cptr, "true")) {
                        curmsg->regexp_match = 1;
                    }
                }

                curmsg->timeout = xp_get_long("timeout", "message timeout", 0);

                /* record the route set  */
                /* TODO disallow optional and rrs to coexist? */
                if ((cptr = xp_get_value("rrs"))) {
                    curmsg->bShouldRecordRoutes = get_bool(cptr, "record route set");
                }

                /* record the authentication credentials  */
                if ((cptr = xp_get_value("auth"))) {
                    bool temp = get_bool(cptr, "message authentication");
                    curmsg->bShouldAuthenticate = temp;
                }
            } else if(!strcmp(elem, "pause") || !strcmp(elem, "timewait")) {
                checkOptionalRecv(elem, scenario_file_cursor);
                curmsg->M_type = MSG_TYPE_PAUSE;
                if (!strcmp(elem, "timewait")) {
                    curmsg->timewait = true;
                    found_timewait = true;
                }

                int var;
                if ((var = xp_get_var("variable", "pause", -1)) != -1) {
                    curmsg->pause_variable = var;
                } else {
                    CSample *distribution = parse_distribution(true);

                    bool sanity_check = xp_get_bool("sanity_check", "pause", true);

                    double pause_duration = distribution->cdfInv(0.99);
                    if (sanity_check && (pause_duration > INT_MAX)) {
                        char percentile[100];
                        char desc[100];

                        distribution->timeDescr(desc, sizeof(desc));
                        time_string(pause_duration, percentile, sizeof(percentile));

                        ERROR("The distribution %s has a 99th percentile of %s, which is larger than INT_MAX.  You should chose different parameters.", desc, percentile);
                    }

                    curmsg->pause_distribution = distribution;
                    /* Update scenario duration with max duration */
                    duration += (int)pause_duration;
                }
            } else if(!strcmp(elem, "nop")) {
                checkOptionalRecv(elem, scenario_file_cursor);
                /* Does nothing at SIP level.  This message type can be used to handle
                 * actions, increment counters, or for RTDs. */
                curmsg->M_type = MSG_TYPE_NOP;
            } else if(!strcmp(elem, "recvCmd")) {
                curmsg->M_type = MSG_TYPE_RECVCMD;
                curmsg->optional = xp_get_optional("optional", "recv");
                last_recv_optional = curmsg->optional;

                /* 3pcc extended mode */
                if ((cptr = xp_get_value("src"))) {
                    curmsg->peer_src = strdup(cptr);
                } else if (extendedTwinSippMode) {
                    ERROR("You must specify a 'src' for recvCmd when using extended 3pcc mode!");
                }
            } else if(!strcmp(elem, "sendCmd")) {
                checkOptionalRecv(elem, scenario_file_cursor);
                curmsg->M_type = MSG_TYPE_SENDCMD;
                /* Sent messages descriptions */

                /* 3pcc extended mode */
                if ((cptr = xp_get_value("dest"))) {
                    peer = strdup(cptr);
                    curmsg->peer_dest = peer;
                    peer_map::iterator peer_it;
                    peer_it = peers.find(peer_map::key_type(peer));
                    if(peer_it == peers.end())
                        /* the peer (slave or master)
                        has not been added in the map
                        (first occurrence in the scenario) */
                    {
                        T_peer_infos infos = {};
                        infos.peer_socket = 0;
                        strncpy(infos.peer_host, get_peer_addr(peer), sizeof(infos.peer_host) - 1);
                        peers[std::string(peer)] = infos;
                    }
                } else if (extendedTwinSippMode) {
                    ERROR("You must specify a 'dest' for sendCmd with extended 3pcc mode!");
                }

                if (!(ptr = xp_get_cdata())) {
                    ERROR("No CDATA in 'sendCmd' section of xml scenario file");
                }
                char *msg = clean_cdata(ptr);

                curmsg -> M_sendCmdData = new SendingMessage(this, msg, true /* skip sanity */);
                free(msg);
            } else {
                ERROR("Unknown element '%s' in xml scenario file", elem);
            }

            getCommonAttributes(curmsg);
        } /** end * Message case */
        xp_close_element();
    } // end while

    free(method_list);

    str_int_map::iterator label_it = labelMap.find("_unexp.main");
    if (label_it != labelMap.end()) {
        unexpected_jump = label_it->second;
    } else {
        unexpected_jump = -1;
    }
    retaddr = find_var("_unexp.retaddr");
    pausedaddr = find_var("_unexp.pausedaddr");

    /* Patch up the labels. */
    apply_labels(messages, labelMap);
    apply_labels(initmessages, initLabelMap);

    /* Some post-scenario loading validation. */
    stats->validateRtds();

    /* Make sure that all variables are used more than once. */
    validate_variable_usage();

    /* Make sure that all started transactions have responses, and vice versa. */
    validate_txn_usage();

    if (messages.size() == 0) {
        ERROR("Did not find any messages inside of scenario!");
    }
}

void scenario::runInit()
{
    call *initcall;
    if (initmessages.size() > 0) {
        initcall = new call(main_scenario, NULL, NULL, "///main-init", 0, false, false, true);
        initcall->run();
    }
}

void clear_int_str(int_str_map m)
{
    for(int_str_map::iterator it = m.begin(); it != m.end(); it = m.begin()) {
        free(it->second);
        m.erase(it);
    }
}

void clear_str_int(str_int_map m)
{
    for(str_int_map::iterator it = m.begin(); it != m.end(); it = m.begin()) {
        m.erase(it);
    }
}

void clear_int_int(int_int_map m)
{
    for(int_int_map::iterator it = m.begin(); it != m.end(); it = m.begin()) {
        m.erase(it);
    }
}

scenario::~scenario()
{
    for (msgvec::iterator i = messages.begin(); i != messages.end(); i++) {
        delete *i;
    }
    messages.clear();

    free(name);

    allocVars->putTable();
    delete stats;

    for (unsigned int i = 0; i < transactions.size(); i++) {
        free(transactions[i].name);
    }
    transactions.clear();

    clear_str_int(labelMap);
    clear_str_int(initLabelMap);
    clear_str_int(txnMap);
}

CSample *parse_distribution(bool oldstyle = false)
{
    CSample *distribution;
    const char *distname;
    const char *ptr = 0;

    if(!(distname = xp_get_value("distribution"))) {
        if (!oldstyle) {
            ERROR("statistically distributed actions or pauses requires 'distribution' parameter");
        }
        if ((ptr = xp_get_value("normal"))) {
            distname = "normal";
        } else if ((ptr = xp_get_value("exponential"))) {
            distname = "exponential";
        } else if ((ptr = xp_get_value("lognormal"))) {
            distname = "lognormal";
        } else if ((ptr = xp_get_value("weibull"))) {
            distname = "weibull";
        } else if ((ptr = xp_get_value("pareto"))) {
            distname = "pareto";
        } else if ((ptr = xp_get_value("gamma"))) {
            distname = "gamma";
        } else if ((ptr = xp_get_value("min"))) {
            distname = "uniform";
        } else if ((ptr = xp_get_value("max"))) {
            distname = "uniform";
        } else if ((ptr = xp_get_value("milliseconds"))) {
            double val = get_double(ptr, "Pause milliseconds");
            return new CFixed(val);
        } else {
            return new CDefaultPause();
        }
    }

    if (!strcmp(distname, "fixed")) {
        double value = xp_get_double("value", "Fixed distribution");
        distribution = new CFixed(value);
    } else if (!strcmp(distname, "uniform")) {
        double min = xp_get_double("min", "Uniform distribution");
        double max = xp_get_double("max", "Uniform distribution");
        distribution = new CUniform(min, max);
#ifdef HAVE_GSL
    } else if (!strcmp(distname, "normal")) {
        double mean = xp_get_double("mean", "Normal distribution");
        double stdev = xp_get_double("stdev", "Normal distribution");
        distribution = new CNormal(mean, stdev);
    } else if (!strcmp(distname, "lognormal")) {
        double mean = xp_get_double("mean", "Lognormal distribution");
        double stdev = xp_get_double("stdev", "Lognormal distribution");
        distribution = new CLogNormal(mean, stdev);
    } else if (!strcmp(distname, "exponential")) {
        double mean = xp_get_double("mean", "Exponential distribution");
        distribution = new CExponential(mean);
    } else if (!strcmp(distname, "weibull")) {
        double lambda = xp_get_double("lambda", "Weibull distribution");
        double k = xp_get_double("k", "Weibull distribution");
        distribution = new CWeibull(lambda, k);
    } else if (!strcmp(distname, "pareto")) {
        double k = xp_get_double("k", "Pareto distribution");
        double xsubm = xp_get_double("x_m", "Pareto distribution");
        distribution = new CPareto(k, xsubm);
    } else if (!strcmp(distname, "gpareto")) {
        double shape = xp_get_double("shape", "Generalized Pareto distribution");
        double scale = xp_get_double("scale", "Generalized Pareto distribution");
        double location = xp_get_double("location", "Generalized Pareto distribution");
        distribution = new CGPareto(shape, scale, location);
    } else if (!strcmp(distname, "gamma")) {
        double k = xp_get_double("k", "Gamma distribution");
        double theta = xp_get_double("theta", "Gamma distribution");
        distribution = new CGamma(k, theta);
    } else if (!strcmp(distname, "negbin")) {
        double n = xp_get_double("n", "Negative Binomial distribution");
        double p = xp_get_double("p", "Negative Binomial distribution");
        distribution = new CNegBin(n, p);
#else
    } else if (!strcmp(distname, "normal")
               || !strcmp(distname, "lognormal")
               || !strcmp(distname, "exponential")
               || !strcmp(distname, "pareto")
               || !strcmp(distname, "gamma")
               || !strcmp(distname, "negbin")
               || !strcmp(distname, "weibull")) {
        ERROR("The distribution '%s' is only available with GSL.", distname);
#endif
    } else {
        ERROR("Unknown distribution: %s\n", ptr);
    }

    return distribution;
}



/* 3pcc extended mode:
   get the correspondances between
   slave and master names and their
   addresses */

void parse_slave_cfg()
{
    FILE * f;
    char line[MAX_PEER_SIZE];
    char * temp_peer;
    char * temp_host;
    char * peer_host;

    f = fopen(slave_cfg_file, "r");
    if(f) {
        while (fgets(line, MAX_PEER_SIZE, f) != NULL) {
            temp_peer = strtok(line, ";");
            if (!temp_peer)
                continue;

            temp_host = strtok(NULL, ";");
            if (!temp_host)
                continue;

            peer_host = strdup(temp_host);
            if (!peer_host)
                ERROR("Cannot allocate memory!\n");

            peer_addrs[std::string(temp_peer)] = peer_host;
        }
    } else {
        ERROR("Can not open slave_cfg file %s\n", slave_cfg_file);
    }

    fclose(f);
}

// Determine in which mode the sipp tool has been
// launched (client, server, 3pcc client, 3pcc server, 3pcc extended master or slave)
void scenario::computeSippMode()
{
    bool isRecvCmdFound = false;
    bool isSendCmdFound = false;

    creationMode = -1;
    sendMode = -1;
    thirdPartyMode = MODE_3PCC_NONE;

    assert(messages.size() > 0);

    for(unsigned int i=0; i<messages.size(); i++) {
        switch(messages[i]->M_type) {
        case MSG_TYPE_PAUSE:
        case MSG_TYPE_NOP:
            /* Allow pauses or nops to go first. */
            continue;
        case MSG_TYPE_SEND:
            if (sendMode == -1) {
                sendMode = MODE_CLIENT;
            }
            if (creationMode == -1) {
                creationMode = MODE_CLIENT;
            }
            break;

        case MSG_TYPE_RECV:
            if (sendMode == -1) {
                sendMode = MODE_SERVER;
            }
            if (creationMode == -1) {
                creationMode = MODE_SERVER;
            }
            break;
        case MSG_TYPE_SENDCMD:
            isSendCmdFound = true;
            if (creationMode == -1) {
                creationMode = MODE_CLIENT;
            }
            if(!isRecvCmdFound) {
                if (creationMode == MODE_SERVER) {
                    /*
                     * If it is a server already, then start it in
                     * 3PCC A passive mode
                     */
                    if(twinSippMode) {
                        thirdPartyMode = MODE_3PCC_A_PASSIVE;
                    } else if (extendedTwinSippMode) {
                        thirdPartyMode = MODE_MASTER_PASSIVE;
                    }
                } else {
                    if(twinSippMode) {
                        thirdPartyMode = MODE_3PCC_CONTROLLER_A;
                    } else if (extendedTwinSippMode) {
                        thirdPartyMode = MODE_MASTER;
                    }
                }
                if((thirdPartyMode == MODE_MASTER_PASSIVE || thirdPartyMode == MODE_MASTER) && !master_name) {
                    ERROR("Inconsistency between command line and scenario: master scenario but -master option not set\n");
                }
                if(!twinSippMode && !extendedTwinSippMode)
                    ERROR("sendCmd message found in scenario but no twin sipp"
                          " address has been passed! Use -3pcc option or 3pcc extended mode.\n");
            }
            break;

        case MSG_TYPE_RECVCMD:
            if (creationMode == -1) {
                creationMode = MODE_SERVER;
            }
            isRecvCmdFound = true;
            if(!isSendCmdFound) {
                if(twinSippMode) {
                    thirdPartyMode = MODE_3PCC_CONTROLLER_B;
                } else if(extendedTwinSippMode) {
                    thirdPartyMode = MODE_SLAVE;
                    if(!slave_number) {
                        ERROR("Inconsistency between command line and scenario: slave scenario but -slave option not set\n");
                    } else {
                        thirdPartyMode = MODE_SLAVE;
                    }
                }
                if(!twinSippMode && !extendedTwinSippMode)
                    ERROR("recvCmd message found in scenario but no "
                          "twin sipp address has been passed! Use "
                          "-3pcc option\n");
            }
            break;
        default:
            break;
        }
    }
    if(creationMode == -1)
        ERROR("Unable to determine creation mode of the tool (server, client)\n");
    if(sendMode == -1)
        ERROR("Unable to determine send mode of the tool (server, client)\n");
}

void scenario::handle_rhs(CAction *tmpAction, const char *what)
{
    if (xp_get_value("value")) {
        tmpAction->setDoubleValue(xp_get_double("value", what));
        if (xp_get_value("variable")) {
            ERROR("Value and variable are mutually exclusive for %s action!", what);
        }
    } else if (xp_get_value("variable")) {
        tmpAction->setVarInId(xp_get_var("variable", what));
        if (xp_get_value("value")) {
            ERROR("Value and variable are mutually exclusive for %s action!", what);
        }
    } else {
        ERROR("No value or variable defined for %s action!", what);
    }
}

void scenario::handle_arithmetic(CAction *tmpAction, const char *what)
{
    tmpAction->setVarId(xp_get_var("assign_to", what));
    handle_rhs(tmpAction, what);
}

void scenario::parseAction(CActions *actions)
{
    char *        actionElem;
    unsigned int recvScenarioLen = 0;
    char *        currentRegExp = NULL;
    char **       currentTabVarName = NULL;
    int           currentNbVarNames;
    int           sub_currentNbVarId;
    char* ptr;
    const char* cptr;

    while((actionElem = xp_open_element(recvScenarioLen))) {
        CAction *tmpAction = new CAction(this);

        if(!strcmp(actionElem, "ereg")) {
            ptr = xp_get_string("regexp", "ereg");

            // keeping regexp expression in memory
            if(currentRegExp != NULL)
                delete[] currentRegExp;
            currentRegExp = new char[strlen(ptr)+1];
            xp_unescape(ptr, currentRegExp);
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_REGEXP);

            // warning - although these are detected for both msg and hdr
            // they are only implemented for search_in="hdr"
            tmpAction->setCaseIndep(xp_get_bool("case_indep", "ereg", false));
            tmpAction->setHeadersOnly(xp_get_bool("start_line", "ereg", false));

            free(ptr);
            if ((cptr = xp_get_value("search_in"))) {
                tmpAction->setOccurrence(1);

                if (strcmp(cptr, "msg") == 0) {
                    tmpAction->setLookingPlace(CAction::E_LP_MSG);
                    tmpAction->setLookingChar (NULL);
                } else if (strcmp(cptr, "body") == 0) {
                    tmpAction->setLookingPlace(CAction::E_LP_BODY);
                    tmpAction->setLookingChar (NULL);
                } else if (strcmp(cptr, "var") == 0) {
                    tmpAction->setVarInId(xp_get_var("variable", "ereg"));
                    tmpAction->setLookingPlace(CAction::E_LP_VAR);
                } else if (strcmp(cptr, "hdr") == 0) {
                    cptr = xp_get_value("header");
                    if (!cptr || !strlen(cptr)) {
                        ERROR("search_in=\"hdr\" requires header field");
                    }
                    tmpAction->setLookingPlace(CAction::E_LP_HDR);
                    tmpAction->setLookingChar(cptr);
                    if ((cptr = xp_get_value("occurrence"))) {
                        tmpAction->setOccurrence(atol(cptr));
                    } else if ((cptr = xp_get_value("occurence"))) {
                        /* old misspelling */
                        tmpAction->setOccurrence(atol(cptr));
                    }
                } else {
                    ERROR("Unknown search_in value %s", cptr);
                }
            } else {
                tmpAction->setLookingPlace(CAction::E_LP_MSG);
                tmpAction->setLookingChar(NULL);
            } // end if-else search_in

            if (xp_get_value("check_it")) {
                tmpAction->setCheckIt(xp_get_bool("check_it", "ereg", false));
                if (xp_get_value("check_it_inverse")) {
                    ERROR("Can not have both check_it and check_it_inverse for ereg!");
                }
            } else {
                tmpAction->setCheckItInverse(xp_get_bool("check_it_inverse", "ereg", false));
            }

            if (!(ptr = xp_get_value("assign_to"))) {
                ERROR("assign_to value is missing");
            }

            createStringTable(ptr, &currentTabVarName, &currentNbVarNames);

            int varId = get_var(currentTabVarName[0], "assign_to");
            tmpAction->setVarId(varId);

            tmpAction->setRegExp(currentRegExp);
            if (currentNbVarNames > 1 ) {
                sub_currentNbVarId = currentNbVarNames - 1 ;
                tmpAction->setNbSubVarId(sub_currentNbVarId);

                for(int i=1; i<= sub_currentNbVarId; i++) {
                    int varId = get_var(currentTabVarName[i], "sub expression assign_to");
                    tmpAction->setSubVarId(varId);
                }
            }

            freeStringTable(currentTabVarName, currentNbVarNames);

            if(currentRegExp != NULL) {
                delete[] currentRegExp;
            }
            currentRegExp = NULL;
        } /* end !strcmp(actionElem, "ereg") */ else if(!strcmp(actionElem, "log")) {
            ptr = xp_get_string("message", "log");
            tmpAction->setMessage(ptr);
            free(ptr);
            tmpAction->setActionType(CAction::E_AT_LOG_TO_FILE);
        } else if(!strcmp(actionElem, "warning")) {
            ptr = xp_get_string("message", "warning");
            tmpAction->setMessage(ptr);
            free(ptr);
            tmpAction->setActionType(CAction::E_AT_LOG_WARNING);
        } else if(!strcmp(actionElem, "error")) {
            ptr = xp_get_string("message", "error");
            tmpAction->setMessage(ptr);
            free(ptr);
            tmpAction->setActionType(CAction::E_AT_LOG_ERROR);
        } else if(!strcmp(actionElem, "assign")) {
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_VALUE);
            handle_arithmetic(tmpAction, "assign");
        } else if(!strcmp(actionElem, "assignstr")) {
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_STRING);
            tmpAction->setVarId(xp_get_var("assign_to", "assignstr"));
            ptr = xp_get_string("value", "assignstr");
            tmpAction->setMessage(ptr);
            free(ptr);
        } else if(!strcmp(actionElem, "gettimeofday")) {
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_GETTIMEOFDAY);

            if (!(ptr = xp_get_value("assign_to"))) {
                ERROR("assign_to value is missing");
            }
            createStringTable(ptr, &currentTabVarName, &currentNbVarNames);
            if (currentNbVarNames != 2 ) {
                ERROR("The gettimeofday action requires two output variables!");
            }
            tmpAction->setNbSubVarId(1);

            int varId = get_var(currentTabVarName[0], "gettimeofday seconds assign_to");
            tmpAction->setVarId(varId);
            varId = get_var(currentTabVarName[1], "gettimeofday useconds assign_to");
            tmpAction->setSubVarId(varId);

            freeStringTable(currentTabVarName, currentNbVarNames);
        } else if(!strcmp(actionElem, "index")) {
            tmpAction->setVarId(xp_get_var("assign_to", "index"));
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_INDEX);
        } else if(!strcmp(actionElem, "jump")) {
            tmpAction->setActionType(CAction::E_AT_JUMP);
            handle_rhs(tmpAction, "jump");
        } else if(!strcmp(actionElem, "pauserestore")) {
            tmpAction->setActionType(CAction::E_AT_PAUSE_RESTORE);
            handle_rhs(tmpAction, "pauserestore");
        } else if(!strcmp(actionElem, "add")) {
            tmpAction->setActionType(CAction::E_AT_VAR_ADD);
            handle_arithmetic(tmpAction, "add");
        } else if(!strcmp(actionElem, "subtract")) {
            tmpAction->setActionType(CAction::E_AT_VAR_SUBTRACT);
            handle_arithmetic(tmpAction, "subtract");
        } else if(!strcmp(actionElem, "multiply")) {
            tmpAction->setActionType(CAction::E_AT_VAR_MULTIPLY);
            handle_arithmetic(tmpAction, "multiply");
        } else if(!strcmp(actionElem, "divide")) {
            tmpAction->setActionType(CAction::E_AT_VAR_DIVIDE);
            handle_arithmetic(tmpAction, "divide");
            if (tmpAction->getVarInId() == 0) {
                if (tmpAction->getDoubleValue() == 0.0) {
                    ERROR("divide actions can not have a value of zero!");
                }
            }
        } else if(!strcmp(actionElem, "sample")) {
            tmpAction->setVarId(xp_get_var("assign_to", "sample"));
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_SAMPLE);
            tmpAction->setDistribution(parse_distribution());
        } else if(!strcmp(actionElem, "todouble")) {
            tmpAction->setActionType(CAction::E_AT_VAR_TO_DOUBLE);
            tmpAction->setVarId(xp_get_var("assign_to", "todouble"));
            tmpAction->setVarInId(xp_get_var("variable", "todouble"));
        } else if(!strcmp(actionElem, "test")) {
            tmpAction->setVarId(xp_get_var("assign_to", "test"));
            tmpAction->setVarInId(xp_get_var("variable", "test"));
            if (xp_get_value("value")) {
                tmpAction->setDoubleValue(xp_get_double("value", "test"));
                if (xp_get_value("variable2")) {
                    ERROR("Can not have both a value and a variable2 for test!");
                }
            } else {
                tmpAction->setVarIn2Id(xp_get_var("variable2", "test"));
            }
            tmpAction->setActionType(CAction::E_AT_VAR_TEST);
            ptr = xp_get_string("compare", "test");
            if (!strcmp(ptr, "equal")) {
                tmpAction->setComparator(CAction::E_C_EQ);
            } else if (!strcmp(ptr, "not_equal")) {
                tmpAction->setComparator(CAction::E_C_NE);
            } else if (!strcmp(ptr, "greater_than")) {
                tmpAction->setComparator(CAction::E_C_GT);
            } else if (!strcmp(ptr, "less_than")) {
                tmpAction->setComparator(CAction::E_C_LT);
            } else if (!strcmp(ptr, "greater_than_equal")) {
                tmpAction->setComparator(CAction::E_C_GEQ);
            } else if (!strcmp(ptr, "less_than_equal")) {
                tmpAction->setComparator(CAction::E_C_LEQ);
            } else {
                ERROR("Invalid 'compare' parameter: %s", ptr);
            }
            free(ptr);
        } else if(!strcmp(actionElem, "verifyauth")) {
            tmpAction->setVarId(xp_get_var("assign_to", "verifyauth"));
            char* username_ptr = xp_get_string("username", "verifyauth");
            char* password_ptr = xp_get_string("password", "verifyauth");
            tmpAction->setMessage(username_ptr, 0);
            tmpAction->setMessage(password_ptr, 1);
            tmpAction->setActionType(CAction::E_AT_VERIFY_AUTH);
            free(username_ptr);
            free(password_ptr);
            username_ptr = password_ptr = NULL;
        } else if(!strcmp(actionElem, "lookup")) {
            tmpAction->setVarId(xp_get_var("assign_to", "lookup"));
            tmpAction->setMessage(xp_get_string("file", "lookup"), 0);
            tmpAction->setMessage(xp_get_string("key", "lookup"), 1);
            tmpAction->setActionType(CAction::E_AT_LOOKUP);
        } else if(!strcmp(actionElem, "insert")) {
            tmpAction->setMessage(xp_get_string("file", "insert"), 0);
            tmpAction->setMessage(xp_get_string("value", "insert"), 1);
            tmpAction->setActionType(CAction::E_AT_INSERT);
        } else if(!strcmp(actionElem, "replace")) {
            tmpAction->setMessage(xp_get_string("file", "replace"), 0);
            tmpAction->setMessage(xp_get_string("line", "replace"), 1);
            tmpAction->setMessage(xp_get_string("value", "replace"), 2);
            tmpAction->setActionType(CAction::E_AT_REPLACE);
        } else if(!strcmp(actionElem, "setdest")) {
            tmpAction->setMessage(xp_get_string("host", actionElem), 0);
            tmpAction->setMessage(xp_get_string("port", actionElem), 1);
            tmpAction->setMessage(xp_get_string("protocol", actionElem), 2);
            tmpAction->setActionType(CAction::E_AT_SET_DEST);
        } else if(!strcmp(actionElem, "closecon")) {
            tmpAction->setActionType(CAction::E_AT_CLOSE_CON);
        } else if(!strcmp(actionElem, "strcmp")) {
            tmpAction->setVarId(xp_get_var("assign_to", "strcmp"));
            tmpAction->setVarInId(xp_get_var("variable", "strcmp"));
            if (xp_get_value("value")) {
                tmpAction->setStringValue(xp_get_string("value", "strcmp"));
                if (xp_get_value("variable2")) {
                    ERROR("Can not have both a value and a variable2 for strcmp!");
                }
            } else {
                tmpAction->setVarIn2Id(xp_get_var("variable2", "strcmp"));
            }
            tmpAction->setActionType(CAction::E_AT_VAR_STRCMP);
        } else if(!strcmp(actionElem, "trim")) {
            tmpAction->setVarId(xp_get_var("assign_to", "trim"));
            tmpAction->setActionType(CAction::E_AT_VAR_TRIM);
        } else if(!strcmp(actionElem, "exec")) {
            if ((ptr = xp_get_value("command"))) {
                tmpAction->setActionType(CAction::E_AT_EXECUTE_CMD);
                tmpAction->setMessage(ptr);
            } else if((cptr = xp_get_value("int_cmd"))) {
                CAction::T_IntCmdType type(CAction::E_INTCMD_STOPCALL); /* assume the default */

                if (strcmp(cptr, "stop_now") == 0) {
                    type = CAction::E_INTCMD_STOP_NOW;
                } else if (strcmp(cptr, "stop_gracefully") == 0) {
                    type = CAction::E_INTCMD_STOP_ALL;
                } else if (strcmp(cptr, "stop_call") == 0) {
                    type = CAction::E_INTCMD_STOPCALL;
                }

                /* the action is well formed, adding it in the */
                /* tmpActionTable */
                tmpAction->setActionType(CAction::E_AT_EXEC_INTCMD);
                tmpAction->setIntCmd(type);
#ifdef PCAPPLAY
            } else if ((cptr = xp_get_keyword_value("play_pcap_audio"))) {
                tmpAction->setPcapArgs(cptr);
                tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_AUDIO);
                hasMedia = 1;
            } else if ((cptr = xp_get_keyword_value("play_pcap_image"))) {
                tmpAction->setPcapArgs(cptr);
                tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_IMAGE);
                hasMedia = 1;
            } else if ((cptr = xp_get_keyword_value("play_pcap_video"))) {
                tmpAction->setPcapArgs(cptr);
                tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_VIDEO);
                hasMedia = 1;
#else
            } else if (xp_get_value("play_pcap_audio")) {
                ERROR("Scenario specifies a play_pcap_audio action, but this version of SIPp does not have PCAP support");
            } else if (xp_get_value("play_pcap_image")) {
                ERROR("Scenario specifies a play_pcap_image action, but this version of SIPp does not have PCAP support");
            } else if (xp_get_value("play_pcap_video")) {
                ERROR("Scenario specifies a play_pcap_video action, but this version of SIPp does not have PCAP support");
#endif
            } else if ((cptr = xp_get_value("rtp_stream"))) {
#ifdef RTP_STREAM
                hasMedia = 1;
                if (strcmp(cptr, "pause") == 0) {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PAUSE);
                } else if (strcmp(cptr, "resume") == 0) {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RESUME);
                } else {
                    tmpAction->setRTPStreamActInfo(cptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PLAY);
                }
#else
                ERROR("Scenario specifies a rtp_stream action, but this version of SIPp does not have RTP stream support");
#endif
            } else {
                ERROR("illegal <exec> in the scenario\n");
            }
        } else {
            ERROR("Unknown action: %s", actionElem);
        }

        /* If the action was not well-formed, there should have already been an
         * ERROR declaration, thus it is safe to add it here at the end of the loop. */
        actions->setAction(tmpAction);

        xp_close_element();
        recvScenarioLen++;
    } // end while
}

// Action list for the message indexed by message_index in
// the scenario
void scenario::getActionForThisMessage(message *message)
{
    char *        actionElem;

    if(!(actionElem = xp_open_element(0))) {
        return;
    }
    if(strcmp(actionElem, "action")) {
        return;
    }

    /* We actually have an action element. */
    if(message->M_actions != NULL) {
        ERROR("Duplicate action for %s index %d", message->desc, message->index);
    }
    message->M_actions = new CActions();

    parseAction(message->M_actions);
    xp_close_element();
}

void scenario::getBookKeeping(message *message)
{
    const char *ptr;

    if ((ptr = xp_get_value("rtd"))) {
        message->stop_rtd = get_rtd(ptr, false);
    }
    if ((ptr = xp_get_value("repeat_rtd"))) {
        if (message->stop_rtd) {
            message->repeat_rtd = get_bool(ptr, "repeat_rtd");
        } else {
            ERROR("There is a repeat_rtd element without an rtd element");
        }
    }

    if ((ptr = xp_get_value("start_rtd"))) {
        message->start_rtd = get_rtd(ptr, true);
    }

    if ((ptr = xp_get_value("counter"))) {
        message->counter = get_counter(ptr, "counter");
    }
}

void scenario::getCommonAttributes(message *message)
{
    char *ptr;

    getBookKeeping(message);
    getActionForThisMessage(message);

    if((ptr = xp_get_value((char *)"lost"))) {
        message -> lost = get_double(ptr, "lost percentage");
        lose_packets = 1;
    }

    if((ptr = xp_get_value((char *)"crlf"))) {
        message -> crlf = 1;
    }

    if (xp_get_value("hiderest")) {
        hidedefault = xp_get_bool("hiderest", "hiderest");
    }
    message -> hide = xp_get_bool("hide", "hide", hidedefault);
    if((ptr = xp_get_value((char *)"display"))) {
        message -> display_str = strdup(ptr);
    }

    message -> condexec = xp_get_var("condexec", "condexec variable", -1);
    message -> condexec_inverse = xp_get_bool("condexec_inverse", "condexec_inverse", false);

    if ((ptr = xp_get_value("next"))) {
        if (found_timewait) {
            ERROR("next labels are not allowed in <timewait> elements.");
        }
        message->nextLabel = strdup(ptr);
        message->test = xp_get_var("test", "test variable", -1);
        if ( 0 != ( ptr = xp_get_value((char *)"chance") ) ) {
            float chance = get_double(ptr,"chance");
            /* probability of branch to next */
            if (( chance < 0.0 ) || (chance > 1.0 )) {
                ERROR("Chance %s not in range [0..1]", ptr);
            }
            message -> chance = (int)((1.0-chance)*RAND_MAX);
        } else {
            message -> chance = 0; /* always */
        }
    }

    if ((ptr = xp_get_value((char *)"ontimeout"))) {
        if (found_timewait) {
            ERROR("ontimeout labels are not allowed in <timewait> elements.");
        }
        message -> onTimeoutLabel = strdup(ptr);
    }
}

// char* manipulation : create a int[] from a char*
// test first is the char* is formed by int separeted by coma
// and then create the table

int isWellFormed(char * P_listeStr, int * nombre)
{
    char * ptr = P_listeStr;
    int sizeOf;
    bool isANumber;

    (*nombre) = 0;
    sizeOf = strlen(P_listeStr);
    // getting the number
    if(sizeOf > 0) {
        // is the string well formed ? [0-9] [,]
        isANumber = false;
        for(int i=0; i<=sizeOf; i++) {
            switch(ptr[i]) {
            case ',':
                if(isANumber == false) {
                    return(0);
                } else {
                    (*nombre)++;
                }
                isANumber = false;
                break;
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                isANumber = true;
                break;
            case '\t':
            case ' ' :
                break;
            case '\0':
                if(isANumber == false) {
                    return(0);
                } else {
                    (*nombre)++;
                }
                break;
            default:
                return(0);
            }
        } // end for
    }
    return(1);
}

int createIntegerTable(char * P_listeStr,
                       unsigned int ** listeInteger,
                       int * sizeOfList)
{
    int nb=0;
    char * ptr = P_listeStr;
    char * ptr_prev = P_listeStr;
    unsigned int current_int;

    if(P_listeStr) {
        if(isWellFormed(P_listeStr, sizeOfList) == 1) {
            (*listeInteger) = new unsigned int[(*sizeOfList)];
            while((*ptr) != ('\0')) {
                if((*ptr) == ',') {
                    sscanf(ptr_prev, "%u", &current_int);
                    if (nb<(*sizeOfList))
                        (*listeInteger)[nb] = current_int;
                    nb++;
                    ptr_prev = ptr+1;
                }
                ptr++;
            }

            // Read the last
            sscanf(ptr_prev, "%u", &current_int);
            if (nb<(*sizeOfList))
                (*listeInteger)[nb] = current_int;
            nb++;
            return(1);
        }
        return(0);
    } else return(0);
}

int createStringTable(char * inputString, char *** stringList, int *sizeOfList)
{
    if(!inputString) {
        return 0;
    }

    *stringList = NULL;
    *sizeOfList = 0;

    do {
        char *p = strchr(inputString, ',');
        if (p) {
            *p++ = '\0';
        }

        *stringList = (char **)realloc(*stringList, sizeof(char *) * (*sizeOfList + 1));
        (*stringList)[*sizeOfList] = strdup(inputString);
        (*sizeOfList)++;

        inputString = p;
    } while (inputString);

    return 1;
}

void freeStringTable(char ** stringList, int sizeOfList)
{
    for (int i = 0; i < sizeOfList; i++) {
        free(stringList[i]);
    }
    free(stringList);
}

/* These are the names of the scenarios, they must match the default_scenario table. */
const char *scenario_table[] = {
    "uac",
    "uas",
    "regexp",
    "3pcc-C-A",
    "3pcc-C-B",
    "3pcc-A",
    "3pcc-B",
    "branchc",
    "branchs",
    "uac_pcap",
    "ooc_default",
    "ooc_dummy",
};

int find_scenario(const char *scenario)
{
    int i, max;
    max = sizeof(scenario_table)/sizeof(scenario_table[0]);

    for (i = 0; i < max; i++) {
        if (!strcmp(scenario_table[i], scenario)) {
            return i;
        }
    }

    ERROR("Invalid default scenario name '%s'.\n", scenario);
    return -1;
}

// TIP: to integrate an existing XML scenario, use the following sed line:
// cat ../3pcc-controller-B.xml | sed -e 's/\"/\\\"/g' -e 's/\(.*\)/\"\1\\n\"/'
const char * default_scenario [] = {
    /************* Default_scenario[0] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp default 'uac' scenario.                       -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"Basic Sipstone UAC\">\n"
    "  <!-- In client mode (sipp placing calls), the Call-ID MUST be         -->\n"
    "  <!-- generated by sipp. To do so, use [call_id] keyword.                -->\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 INVITE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[media_ip_type] [media_ip]\n"
    "      t=0 0\n"
    "      m=audio [media_port] RTP/AVP 0\n"
    "      a=rtpmap:0 PCMU/8000\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"100\"\n"
    "        optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"180\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"183\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- By adding rrs=\"true\" (Record Route Sets), the route sets         -->\n"
    "  <!-- are saved and used for following messages sent. Useful to test   -->\n"
    "  <!-- against stateful SIP proxies/B2BUAs.                             -->\n"
    "  <recv response=\"200\" rtd=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- Packet lost can be simulated in any send/recv message by         -->\n"
    "  <!-- by adding the 'lost = \"10\"'. Value can be [1-100] percent.       -->\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 ACK\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- This delay can be customized by the -d command-line option       -->\n"
    "  <!-- or by adding a 'milliseconds = \"value\"' option here.             -->\n"
    "  <pause/>\n"
    "\n"
    "  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 2 BYE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"200\" crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
    "\n"
    "  <!-- definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
    "\n"
    "</scenario>\n"
    "\n"
    ,

    /************* Default_scenario[1] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp default 'uas' scenario.                       -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"Basic UAS responder\">\n"
    "  <!-- By adding rrs=\"true\" (Record Route Sets), the route sets         -->\n"
    "  <!-- are saved and used for following messages sent. Useful to test   -->\n"
    "  <!-- against stateful SIP proxies/B2BUAs.                             -->\n"
    "  <recv request=\"INVITE\" crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- The '[last_*]' keyword is replaced automatically by the          -->\n"
    "  <!-- specified header if it was present in the last message received  -->\n"
    "  <!-- (except if it was a retransmission). If the header was not       -->\n"
    "  <!-- present or if no message has been received, the '[last_*]'       -->\n"
    "  <!-- keyword is discarded, and all bytes until the end of the line    -->\n"
    "  <!-- are also discarded.                                              -->\n"
    "  <!--                                                                  -->\n"
    "  <!-- If the specified header was present several times in the         -->\n"
    "  <!-- message, all occurrences are concatenated (CRLF separated)       -->\n"
    "  <!-- to be used in place of the '[last_*]' keyword.                   -->\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 180 Ringing\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag01[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag01[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[media_ip_type] [media_ip]\n"
    "      t=0 0\n"
    "      m=audio [media_port] RTP/AVP 0\n"
    "      a=rtpmap:0 PCMU/8000\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv request=\"ACK\"\n"
    "        optional=\"true\"\n"
    "        rtd=\"true\"\n"
    "        crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv request=\"BYE\">\n"
    "  </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
    "  <!-- able to retransmit it if we receive the BYE again.               -->\n"
    "  <timewait milliseconds=\"4000\"/>\n"
    "\n"
    "\n"
    "  <!-- definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
    "\n"
    "  <!-- definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
    "\n"
    "</scenario>\n"
    "\n",

    /************* Default_scenario[2] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp default 'regexp client' scenario.             -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"Client with regexp scenario\">\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag02[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 INVITE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[media_ip_type] [media_ip]\n"
    "      t=0 0\n"
    "      m=audio [media_port] RTP/AVP 0\n"
    "      a=rtpmap:0 PCMU/8000\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"100\"\n"
    "        optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"180\" optional=\"true\">\n"
    "  </recv>\n"
    "  <recv response=\"183\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"200\" start_rtd=\"true\">\n"
    "    <!-- Definition of regexp in the action tag. The regexp must follow -->\n"
    "    <!-- the Posix Extended standard (POSIX 1003.2), see:               -->\n"
    "    <!--                                                                -->\n"
    "    <!--   http://www.opengroup.org/onlinepubs/007908799/xbd/re.html    -->\n"
    "    <!--                                                                -->\n"
    "    <!-- regexp    : Contain the regexp to use for matching the         -->\n"
    "    <!--             received message                                   -->\n"
    "    <!--             MANDATORY                                          -->\n"
    "    <!-- search_in : msg (try to match against the entire message)      -->\n"
    "    <!--           : hdr (try to match against a specific SIP header    -->\n"
    "    <!--             (passed in the header tag)                         -->\n"
    "    <!--             OPTIONAL - default value : msg                     -->\n"
    "    <!-- header    : Header to try to match against.                    -->\n"
    "    <!--             Only used when the search_in tag is set to hdr     -->\n"
    "    <!--             MANDATORY IF search_in is equal to hdr             -->\n"
    "    <!-- check_it  : if set to true, the call is marked as failed if    -->\n"
    "    <!--             the regexp doesn't match.                          -->\n"
    "    <!--             OPTIONAL - default value : false                   -->\n"
    "    <!-- assign_to : contain the variable id (integer) or a list of     -->\n"
    "    <!--             variable id which will be used to store the        -->\n"
    "    <!--             result of the matching process between the regexp  -->\n"
    "    <!--             and the message. This variable can be re-used at   -->\n"
    "    <!--             a later time in the scenario using '[$n]' syntax   -->\n"
    "    <!--             where n is the variable id.                        -->\n"
    "    <!--             MANDATORY                                          -->\n"
    "    <action>\n"
    "      <ereg regexp=\"[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[:][0-9]{1,5}\" \n"
    "            search_in=\"msg\" \n"
    "            check_it=\"true\" \n"
    "            assign_to=\"1\"/>\n"
    "      <ereg regexp=\".*\" \n"
    "            search_in=\"hdr\" \n"
    "            header=\"Contact:\" \n"
    "            check_it=\"true\" \n"
    "            assign_to=\"6\"/>\n"
    "      <ereg regexp=\"o=([[:alnum:]]*) ([[:alnum:]]*) ([[:alnum:]]*)\"\n"
    "            search_in=\"msg\" \n"
    "            check_it=\"true\" \n"
    "            assign_to=\"3,4,5,8\"/>\n"
    "    </action>\n"
    "  </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag02[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 ACK\n"
    "      retrievedIp: [$1]\n"
    "      retrievedContact:[$6]\n"
    "      retrievedSdpOrigin:[$3]\n"
    "      retrievedSdpOrigin-username:[$4]\n"
    "      retrievedSdpOrigin-session-id:[$5]\n"
    "      retrievedSdpOrigin-version:[$8]\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- This delay can be customized by the -d command-line option       -->\n"
    "  <!-- or by adding a 'milliseconds = \"value\"' option here.           -->\n"
    "  <pause milliseconds = \"1000\"/>\n"
    "\n"
    "  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag02[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 2 BYE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"200\" crlf=\"true\" rtd=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"1000, 1040, 1080, 1120, 1160, 1200\"/>\n"
    "\n"
    "  <!-- definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"1000, 1100, 1200, 1300, 1400\"/>\n"
    "\n"
    "</scenario>\n"
    "\n",

    /************* Default_scenario[3] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 3PCC - Controller - A side                         -->\n"
    "<!--                                                                    -->\n"
    "<!--             A              Controller               B              -->\n"
    "<!--             |(1) INVITE no SDP  |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(2) 200 offer1     |                   |              -->\n"
    "<!--             |==================>|                   |              -->\n"
    "<!--             |                   |(3) INVITE offer1  |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |                   |(4) 200 OK answer1 |              -->\n"
    "<!--             |                   |<==================|              -->\n"
    "<!--             |                   |(5) ACK            |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |(6) ACK answer1    |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(7) RTP            |                   |              -->\n"
    "<!--             |.......................................|              -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"3PCC Controller - A side\">\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag03[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 INVITE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"100\" optional=\"true\"> </recv>\n"
    "  <recv response=\"180\" optional=\"true\"> </recv>\n"
    "  <recv response=\"183\" optional=\"true\"> </recv>\n"
    "  <recv response=\"200\" crlf=\"true\" start_rtd=\"true\">\n"
    "    <action>\n"
    "       <ereg regexp=\"Content-Type:.*\" \n"
    "             search_in=\"msg\"  \n"
    "             assign_to=\"1\" /> \n"
    "    </action>\n"
    "  </recv>\n"
    "\n"
    "  <sendCmd>\n"
    "    <![CDATA[\n"
    "      Call-ID: [call_id]\n"
    "      [$1]\n"
    "\n"
    "     ]]>\n"
    "  </sendCmd>\n"
    "  \n"
    "  <recvCmd>\n"
    "    <action>\n"
    "       <ereg regexp=\"Content-Type:.*\"  \n"
    "             search_in=\"msg\"  \n"
    "             assign_to=\"2\" /> \n"
    "    </action>\n"
    "  \n"
    "  </recvCmd>\n"
    "  \n"
    "  <send rtd=\"true\">\n"
    "    <![CDATA[\n"
    "\n"
    "      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag03[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 ACK\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      [$2]\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <pause milliseconds=\"1000\"/>\n"
    "\n"
    "  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag03[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 2 BYE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"200\" crlf=\"true\"> </recv>\n"
    "\n"
    "</scenario>\n"
    "\n",

    /************* Default_scenario[4] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 3PCC - Controller - B side                         -->\n"
    "<!--                                                                    -->\n"
    "<!--             A              Controller               B              -->\n"
    "<!--             |(1) INVITE no SDP  |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(2) 200 offer1     |                   |              -->\n"
    "<!--             |==================>|                   |              -->\n"
    "<!--             |                   |(3) INVITE offer1  |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |                   |(4) 200 OK answer1 |              -->\n"
    "<!--             |                   |<==================|              -->\n"
    "<!--             |                   |(5) ACK            |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |(6) ACK answer1    |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(7) RTP            |                   |              -->\n"
    "<!--             |.......................................|              -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "\n"
    "<scenario name=\"3PCC Controller - B side\">\n"
    "\n"
    "<recvCmd>\n"
    "  <action>\n"
    "       <ereg regexp=\"Content-Type:.*\"  \n"
    "             search_in=\"msg\"  \n"
    "             assign_to=\"1\" /> \n"
    "  </action>\n"
    "</recvCmd>\n"
    "\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag04[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 INVITE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      [$1]\n"
    "\n"
    "     ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"100\" optional=\"true\"> </recv>\n"
    "  <recv response=\"180\" optional=\"true\"> </recv>\n"
    "  <recv response=\"183\" optional=\"true\"> </recv>\n"
    "  <recv response=\"200\" crlf=\"true\">\n"
    "    <action>\n"
    "       <ereg regexp=\"Content-Type:.*\"  \n"
    "             search_in=\"msg\"  \n"
    "             assign_to=\"2\" /> \n"
    "    </action>\n"
    "  </recv>\n"
    "  \n"
    "    \n"
    "  <send start_rtd=\"true\">\n"
    "    <![CDATA[\n"
    "\n"
    "      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag04[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 ACK\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <sendCmd>\n"
    "    <![CDATA[\n"
    "      Call-ID: [call_id]\n"
    "      [$2]\n"
    "\n"
    "    ]]>\n"
    "  </sendCmd>\n"
    " \n"
    "  <pause milliseconds=\"1000\"/>\n"
    "\n"
    "\n"
    "  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
    "  <send retrans=\"500\" rtd=\"true\">\n"
    "    <![CDATA[\n"
    "\n"
    "      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag04[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 2 BYE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"200\" crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "\n"
    "</scenario>\n"
    "\n",

    /************* Default_scenario[5] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 3PCC - A side emulator                             -->\n"
    "<!--                                                                    -->\n"
    "<!--             A              Controller               B              -->\n"
    "<!--             |(1) INVITE no SDP  |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(2) 200 offer1     |                   |              -->\n"
    "<!--             |==================>|                   |              -->\n"
    "<!--             |                   |(3) INVITE offer1  |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |                   |(4) 200 OK answer1 |              -->\n"
    "<!--             |                   |<==================|              -->\n"
    "<!--             |                   |(5) ACK            |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |(6) ACK answer1    |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(7) RTP            |                   |              -->\n"
    "<!--             |.......................................|              -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "\n"
    "<scenario name=\"3PCC A side\">\n"
    "  <recv request=\"INVITE\" crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag05[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[media_ip_type] [media_ip]\n"
    "      t=0 0\n"
    "      m=audio [media_port] RTP/AVP 0\n"
    "      a=rtpmap:0 PCMU/8000\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv request=\"ACK\" rtd=\"true\" crlf=\"true\"> </recv>\n"
    "\n"
    "  <!-- RTP flow starts from here! -->\n"
    "\n"
    "  <recv request=\"BYE\" crlf=\"true\"> </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
    "  <!-- able to retransmit it if we receive the BYE again.               -->\n"
    "  <timewait milliseconds=\"2000\"/>\n"
    "\n"
    "</scenario>\n"
    "\n",

    /************* Default_scenario[6] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 3PCC - B side emulator                             -->\n"
    "<!--                                                                    -->\n"
    "<!--             A              Controller               B              -->\n"
    "<!--             |(1) INVITE no SDP  |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(2) 200 offer1     |                   |              -->\n"
    "<!--             |==================>|                   |              -->\n"
    "<!--             |                   |(3) INVITE offer1  |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |                   |(4) 200 OK answer1 |              -->\n"
    "<!--             |                   |<==================|              -->\n"
    "<!--             |                   |(5) ACK            |              -->\n"
    "<!--             |                   |==================>|              -->\n"
    "<!--             |(6) ACK answer1    |                   |              -->\n"
    "<!--             |<==================|                   |              -->\n"
    "<!--             |(7) RTP            |                   |              -->\n"
    "<!--             |.......................................|              -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "\n"
    "\n"
    "<scenario name=\"3PCC B side\">\n"
    "  <recv request=\"INVITE\" crlf=\"true\"> </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag06[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[media_ip_type] [media_ip]\n"
    "      t=0 0\n"
    "      m=audio [media_port] RTP/AVP 0\n"
    "      a=rtpmap:0 PCMU/8000\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv request=\"ACK\" rtd=\"true\" crlf=\"true\"> </recv>\n"
    "\n"
    "  <!-- RTP flow starts from here! -->\n"
    "\n"
    "  <recv request=\"BYE\"> </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
    "  <!-- able to retransmit it if we receive the BYE again.               -->\n"
    "  <timewait milliseconds=\"2000\"/>\n"
    "\n"
    "</scenario>\n",

    /************* Default_scenario[7] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp default 'branchc' scenario.                   -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"branch_client\">\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      REGISTER sip:CA.cym.com SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: ua1 <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07[call_number]\n"
    "      To: ua1 <sip:ua1@nnl.cym:[local_port]>\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 REGISTER\n"
    "      Contact: sip:ua1@[local_ip]:[local_port]\n"
    "      Content-Length: 0\n"
    "      Expires: 300\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- simple case - just jump over a line   -->\n"
    "  <recv response=\"200\" rtd=\"true\" next=\"5\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"200\">\n"
    "  </recv>\n"
    "\n"
    "  <label id=\"5\"/>\n"
    "\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      INVITE sip:ua2@CA.cym.com SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: ua[call_number] <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07b[call_number]\n"
    "      To: ua2 <sip:ua2@nnl.cym:[remote_port]>\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 INVITE\n"
    "      Contact: sip:ua1@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[media_ip_type] [media_ip]\n"
    "      t=0 0\n"
    "      m=audio [media_port] RTP/AVP 0\n"
    "      a=rtpmap:0 PCMU/8000\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"100\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"180\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"183\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- Do something different on an optional receive   -->\n"
    "  <recv response=\"403\" optional=\"true\" next=\"1\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"200\">\n"
    "    <action>\n"
    "      <ereg regexp=\"ua25\"\n"
    "            search_in=\"hdr\"\n"
    "            header=\"From: \"\n"
    "            assign_to=\"8\"/>\n"
    "    </action>\n"
    "  </recv>\n"
    "\n"
    "  <!-- set variable 8 above on 25th call, send the ACK but skip the pause for it   -->\n"
    "  <send next=\"1\" test=\"8\">\n"
    "    <![CDATA[\n"
    "\n"
    "      ACK sip:ua2@CA.cym.com SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: ua1 <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07b[call_number]\n"
    "      To: ua2 <sip:ua2@nnl.cym:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 ACK\n"
    "      Contact: sip:ua1@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <pause milliseconds=\"5000\"/>\n"
    "\n"
    "  <label id=\"1\"/>\n"
    "\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      BYE sip:ua2@CA.cym.com SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: ua1 <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07b[call_number]\n"
    "      To: ua2 <sip:ua2@nnl.cym:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 2 BYE\n"
    "      Contact: sip:ua1@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"200\" crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <pause milliseconds=\"4000\"/>\n"
    "\n"
    "  <!-- definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
    "\n"
    "  <!-- definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
    "\n"
    "</scenario>\n"
    "\n",

    /************* Default_scenario[8] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp default 'branchs' scenario.                   -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"branch_server\">\n"
    "  <recv request=\"REGISTER\">\n"
    "  </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag08[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "      Expires: 300\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- Set variable 3 if the ua is of the form ua2... -->\n"
    "  <recv request=\"INVITE\" crlf=\"true\">\n"
    "    <action>\n"
    "      <ereg regexp=\"ua2\"\n"
    "            search_in=\"hdr\"\n"
    "            header=\"From: \"\n"
    "            assign_to=\"3\"/>\n"
    "    </action>\n"
    "  </recv>\n"
    "\n"
    "  <!-- send 180 then trying if variable 3 is set -->\n"
    "  <send next=\"1\" test=\"3\">\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 180 Ringing\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- if not, send a 403 error then skip to wait for a BYE -->\n"
    "  <send next=\"2\">\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 403 Error\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <label id=\"1\"/>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 100 Trying\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[media_ip_type] [media_ip]\n"
    "      t=0 0\n"
    "      m=audio [media_port] RTP/AVP 0\n"
    "      a=rtpmap:0 PCMU/8000\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv request=\"ACK\"\n"
    "        optional=\"true\"\n"
    "        rtd=\"true\"\n"
    "        crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <label id=\"2\"/>\n"
    "\n"
    "  <recv request=\"BYE\">\n"
    "  </recv>\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
    "  <!-- able to retransmit it if we receive the BYE again.               -->\n"
    "  <timewait milliseconds=\"4000\"/>\n"
    "\n"
    "  <!-- Definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
    "\n"
    "  <!-- Definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
    "\n"
    "</scenario>\n"
    "\n",

    /* Although this scenario will not work without pcap play enabled, there is no
     * harm in including it in the binary anyway, because the user could have
     * dumped it and passed it with -sf. */

    /************* Default_scenario[9] ***************/
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp 'uac' scenario with pcap (rtp) play           -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"UAC with media\">\n"
    "  <!-- In client mode (sipp placing calls), the Call-ID MUST be         -->\n"
    "  <!-- generated by sipp. To do so, use [call_id] keyword.                -->\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag09[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 INVITE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Type: application/sdp\n"
    "      Content-Length: [len]\n"
    "\n"
    "      v=0\n"
    "      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
    "      s=-\n"
    "      c=IN IP[local_ip_type] [local_ip]\n"
    "      t=0 0\n"
    "      m=audio [auto_media_port] RTP/AVP 8 101\n"
    "      a=rtpmap:8 PCMA/8000\n"
    "      a=rtpmap:101 telephone-event/8000\n"
    "      a=fmtp:101 0-11,16\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"100\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <recv response=\"180\" optional=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- By adding rrs=\"true\" (Record Route Sets), the route sets         -->\n"
    "  <!-- are saved and used for following messages sent. Useful to test   -->\n"
    "  <!-- against stateful SIP proxies/B2BUAs.                             -->\n"
    "  <recv response=\"200\" rtd=\"true\" crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- Packet lost can be simulated in any send/recv message by         -->\n"
    "  <!-- by adding the 'lost = \"10\"'. Value can be [1-100] percent.       -->\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "\n"
    "      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag09[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 1 ACK\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- Play a pre-recorded PCAP file (RTP stream)                       -->\n"
    "  <nop>\n"
    "    <action>\n"
    "      <exec play_pcap_audio=\"pcap/g711a.pcap\"/>\n"
    "    </action>\n"
    "  </nop>\n"
    "\n"
    "  <!-- Pause 8 seconds, which is approximately the duration of the      -->\n"
    "  <!-- PCAP file                                                        -->\n"
    "  <pause milliseconds=\"8000\"/>\n"
    "\n"
    "  <!-- Play an out of band DTMF '1'                                     -->\n"
    "  <nop>\n"
    "    <action>\n"
    "      <exec play_pcap_audio=\"pcap/dtmf_2833_1.pcap\"/>\n"
    "    </action>\n"
    "  </nop>\n"
    "\n"
    "  <pause milliseconds=\"1000\"/>\n"
    "\n"
    "  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
    "  <send retrans=\"500\">\n"
    "    <![CDATA[\n"
    "\n"
    "      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag09[call_number]\n"
    "      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
    "      Call-ID: [call_id]\n"
    "      CSeq: 2 BYE\n"
    "      Contact: sip:sipp@[local_ip]:[local_port]\n"
    "      Max-Forwards: 70\n"
    "      Subject: Performance Test\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <recv response=\"200\" crlf=\"true\">\n"
    "  </recv>\n"
    "\n"
    "  <!-- definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
    "\n"
    "  <!-- definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
    "\n"
    "</scenario>\n"
    "\n",
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp default 'uas' scenario.                       -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"Out-of-call UAS\">\n"
    "  <recv request=\".*\" regexp_match=\"true\" />\n"
    "\n"
    "  <send>\n"
    "    <![CDATA[\n"
    "      SIP/2.0 200 OK\n"
    "      [last_Via:]\n"
    "      [last_From:]\n"
    "      [last_To:]\n"
    "      [last_Call-ID:]\n"
    "      [last_CSeq:]\n"
    "      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "      Content-Length: 0\n"
    "\n"
    "    ]]>\n"
    "  </send>\n"
    "\n"
    "  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
    "  <!-- able to retransmit it if we receive the BYE again.               -->\n"
    "  <timewait milliseconds=\"4000\"/>\n"
    "\n"
    "\n"
    "  <!-- definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
    "\n"
    "  <!-- definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
    "\n"
    "</scenario>\n",
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
    "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
    "\n"
    "<!-- This program is free software; you can redistribute it and/or      -->\n"
    "<!-- modify it under the terms of the GNU General Public License as     -->\n"
    "<!-- published by the Free Software Foundation; either version 2 of the -->\n"
    "<!-- License, or (at your option) any later version.                    -->\n"
    "<!--                                                                    -->\n"
    "<!-- This program is distributed in the hope that it will be useful,    -->\n"
    "<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
    "<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
    "<!-- GNU General Public License for more details.                       -->\n"
    "<!--                                                                    -->\n"
    "<!-- You should have received a copy of the GNU General Public License  -->\n"
    "<!-- along with this program; if not, write to the                      -->\n"
    "<!-- Free Software Foundation, Inc.,                                    -->\n"
    "<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
    "<!--                                                                    -->\n"
    "<!--                 Sipp default 'uas' scenario.                       -->\n"
    "<!--                                                                    -->\n"
    "\n"
    "<scenario name=\"Out-of-call UAS\">\n"
    "  <recv request=\"DUMMY\" />\n"
    "\n"
    "  <!-- definition of the response time repartition table (unit is ms)   -->\n"
    "  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
    "\n"
    "  <!-- definition of the call length repartition table (unit is ms)     -->\n"
    "  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
    "\n"
    "</scenario>\n",
};
