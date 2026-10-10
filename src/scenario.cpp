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
#include <sstream>
#include "config.h"
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
    pause_distribution = nullptr; // delete on exit
    pause_variable = -1;
    sessions = 0;
    bShouldRecordRoutes = 0;
    bShouldAuthenticate = 0;

    send_scheme = nullptr; // delete on exit
    retrans_delay = 0;
    timeout = 0;
    timeout_scheme = nullptr; // delete on exit

    recv_response_code = 0;
    optional = 0;
    advance_state = true;
    regexp_match = 0;
    regexp_compile = nullptr; // regfree (if not nullptr) and free on exit

    /* Anyway */
    repeat_rtd = 0;
    lost = -1;
    crlf = 0;
    ignoresdp = false;
    hide = 0;
    test = -1;
    condexec = -1;
    condexec_inverse = false;
    chance = 0;/* meaning always */
    next = -1;
    on_timeout = -1;
    timewait = false;

    /* Statistics */
    nb_sent = 0;
    nb_recv = 0;
    nb_sent_retrans = 0;
    nb_recv_retrans = 0;
    nb_timeout = 0;
    nb_unexp = 0;
    nb_lost = 0;
    counter = 0;

    M_actions = nullptr; // delete on exit

    M_type = 0;

    M_sendCmdData = nullptr; // delete on exit
    M_nbCmdSent = 0;
    M_nbCmdRecv = 0;

    content_length_flag = ContentLengthNoPresent;

    /* How to match responses to this message. */
    start_txn = 0;
    response_txn = 0;
    ack_txn = 0;
    dialog = 0;
}

message::~message()
{
    delete pause_distribution;
    delete send_scheme;
    delete timeout_scheme;
    if (regexp_compile != nullptr) {
        regfree(regexp_compile);
    }
    delete regexp_compile;

    delete M_actions;
    delete M_sendCmdData;
}

bool message::matchesRequest(const char *method)
{
    if (!recv_request) {
        return false;
    }
    if (!regexp_match) {
        return *recv_request == method;
    }
    if (regexp_compile == nullptr) {
        regex_t *re = new regex_t;
        /* No regex match position needed (NOSUB), we're simply
         * looking for the <request method="INVITE|REGISTER"../>
         * regex. */
        if (regcomp(re, recv_request->c_str(), REGCOMP_PARAMS | REG_NOSUB)) {
            ERROR("Invalid regular expression for index %d: %s", index, recv_request->c_str());
        }
        regexp_compile = re;
    }
    return !regexec(regexp_compile, method, (size_t)0, nullptr, REGEXEC_PARAMS);
}

bool message::matchesResponse(int code)
{
    if (!recv_response) {
        return false;
    }
    if (!regexp_match) {
        return recv_response_code == code;
    }
    if (regexp_compile == nullptr) {
        regex_t *re = new regex_t;
        if (regcomp(re, recv_response->c_str(), REGCOMP_PARAMS | REG_NOSUB)) {
            ERROR("Invalid regular expression for index %d: %s", index, recv_response->c_str());
        }
        regexp_compile = re;
    }
    char code_str[8];
    snprintf(code_str, sizeof(code_str), "%d", code);
    return !regexec(regexp_compile, code_str, (size_t)0, nullptr, REGEXEC_PARAMS);
}

/******** Global variables which compose the scenario file **********/

scenario      *rx_scenario;
scenario      *main_scenario;
scenario      *ooc_scenario;
scenario      *aa_scenario;
scenario      *display_scenario;

/* This mode setting refers to whether we open calls autonomously (MODE_CLIENT)
 * or in response to requests (MODE_SERVER). */
int creationMode = MODE_CLIENT;
/* Send mode. Do we send to a fixed address or to the last one we got. */
int sendMode = MODE_CLIENT;
/* This describes what our 3PCC behavior is. */
int thirdPartyMode = MODE_3PCC_NONE;

/*************** Helper functions for various types *****************/
/* Integers are decimal, or hexadecimal after "0x": a leading 0 does not
 * make them octal. */
static int integer_base(const char *ptr)
{
    while (isspace((unsigned char)*ptr)) {
        ptr++;
    }
    if (*ptr == '-' || *ptr == '+') {
        ptr++;
    }
    return ptr[0] == '0' && (ptr[1] == 'x' || ptr[1] == 'X') ? 16 : 10;
}

long get_long(const char *ptr, const char *what)
{
    char *endptr;
    long ret;

    errno = 0;
    ret = strtol(ptr, &endptr, integer_base(ptr));
    if (endptr == ptr || *endptr || errno == ERANGE) {
        ERROR("%s, \"%s\" is not a valid integer!", what, ptr);
    }
    return ret;
}

int get_int(const char *ptr, const char *what)
{
    long ret = get_long(ptr, what);

    if (ret < INT_MIN || ret > INT_MAX) {
        ERROR("%s, \"%s\" is not a valid integer!", what, ptr);
    }
    return ret;
}

unsigned long long get_long_long(const char *ptr, const char *what)
{
    char *endptr;
    unsigned long long ret;

    errno = 0;
    ret = strtoull(ptr, &endptr, integer_base(ptr));
    if (endptr == ptr || *endptr || errno == ERANGE) {
        ERROR("%s, \"%s\" is not a valid integer!", what, ptr);
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
    long ret = 0;
    double dret;
    int i;

    if (!isdigit(*ptr)) {
        ERROR("%s, \"%s\" is not a valid time!", what, ptr);
    }

    for (i = 0, p = ptr; *p; p++) {
        if (*p == ':') {
            i++;
        }
    }

    if (i == 1) { /* mm:ss */
        ERROR("%s, \"%s\" mm:ss not implemented yet!", what, ptr);
    } else if (i == 2) { /* hh:mm:ss */
        ERROR("%s, \"%s\" hh:mm:ss not implemented yet!", what, ptr);
    } else if (i != 0) {
        ERROR("%s, \"%s\" is not a valid time!", what, ptr);
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
            ERROR("%s, \"%s\" is not a valid time!", what, ptr);
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
    if (endptr == ptr || *endptr) {
        ERROR("%s, \"%s\" is not a floating point number!", what, ptr);
    }
    return ret;
}

#ifdef PCAPPLAY
/* If the value is enclosed in [brackets], it is assumed to be
 * a command-line supplied keyword value (-key). */
static std::optional<std::string> xp_get_keyword_value(const char *name)
{
    const char* ptr = xp_get_value(name);
    size_t len;

    if (ptr && ptr[0] == '[' && (len = strlen(ptr)) && ptr[len - 1] == ']') {
        auto gen = generic.find(std::string(ptr + 1, len - 2));
        if (gen != generic.end()) {
            return (*gen).second;
        }

        ERROR("%s \"%s\" looks like a keyword value, but keyword not supplied!", name, ptr);
    }

    if (ptr) {
        return ptr;
    }
    return std::nullopt;
}
#endif

static std::string xp_get_string(const char *name, const char *what)
{
    const char *ptr;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }

    return ptr;
}

/* Set the n-th message of an action from the required attribute name. */
static void xp_set_message(CAction *action, int n, const char *name, const char *what)
{
    action->setMessage(xp_get_string(name, what), n);
}

/* The text naming a required parameter in an error */
static std::string xp_helptext(const char *name, const char *what)
{
    return std::string(what) + " '" + name + "' parameter";
}

static double xp_get_double(const char *name, const char *what)
{
    const char *ptr;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }
    return get_double(ptr, xp_helptext(name, what).c_str());
}

static long xp_get_long(const char *name, const char *what)
{
    const char *ptr;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }
    return get_long(ptr, xp_helptext(name, what).c_str());
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
    const char *ptr;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' parameter.", what, name);
    }
    return get_bool(ptr, xp_helptext(name, what).c_str());
}

static bool xp_get_bool(const char *name, const char *what, bool defval)
{
    if (!(xp_get_value(name))) {
        return defval;
    }
    return xp_get_bool(name, what);
}

int scenario::get_txn(const char *txnName, const char *what, bool start, bool isInvite, bool isAck,
                      bool server)
{
    /* Check the name's validity. */
    if (txnName[0] == '\0') {
        ERROR("Transaction names may not be empty for %s", what);
    }
    if (strcspn(txnName, "$,") != strlen(txnName)) {
        ERROR("Transaction names may not contain '$' or ',' for %s", what);
    }

    int txnNum;
    str_int_map::iterator txn_it = txnMap.find(txnName);
    if (txn_it != txnMap.end()) {
        txnNum = txn_it->second;
    } else {
        /* Assign this variable the next slot. */
        struct txnControlInfo transaction;

        transaction.name = txnName;
        transaction.started = 0;
        transaction.responses = 0;
        transaction.acks = 0;
        transaction.isInvite = start && isInvite;
        transactions.push_back(std::move(transaction));
        txnNum = transactions.size();
        txnMap[txnName] = txnNum;
    }

    txnControlInfo &transaction = transactions[txnNum - 1];
    if (start) {
        if (transaction.started && transaction.server != server) {
            ERROR("Transaction %s is started by both a sent and a received message", txnName);
        }
        transaction.started++;
        transaction.server = server;
    } else if (isAck) {
        transaction.acks++;
    } else if (server) {
        transaction.sent_responses++;
    } else {
        transaction.responses++;
    }

    return txnNum;
}

int scenario::find_var(const char *varName)
{
    return allocVars->find(varName, false);
}

void scenario::setFileName(const char *name)
{
    const char* sep = strrchr(name, '/');
    if (sep) {
        ++sep; // include slash
        path = std::string(name, sep - name);
    } else {
        path.clear();
        sep = name;
    }
    const char* ext = strrchr(sep, '.');
    if (ext && strcmp(ext, ".xml") == 0) {
        fileName = std::string(sep, ext - sep);
    } else {
        fileName = sep;
    }
    stats->setFileName(fileName.c_str(), ".csv");
}

int scenario::get_var(const char *varName, const char *what)
{
    /* Check the name's validity. */
    if (varName[0] == '\0') {
        ERROR("Variable names may not be empty for %s", what);
    }
    if (strcspn(varName, "$,") != strlen(varName)) {
        ERROR("Variable names may not contain '$' or ',' for %s", what);
    }

    return allocVars->find(varName, true);
}

int scenario::xp_get_var(const char *name, const char *what)
{
    const char *ptr;

    if (!(ptr = xp_get_value(name))) {
        ERROR("%s is missing the required '%s' variable parameter.", what, name);
    }

    return get_var(ptr, what);
}

static int xp_get_optional(const char *name, const char *what)
{
    const char *ptr = xp_get_value(name);

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
    const char *ptr;

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

    ret = strtol(ptr, &endptr, integer_base(ptr));
    if (endptr == ptr || *endptr) {
        ERROR("%s, \"%s\" is not a valid boolean!", what, ptr);
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

/* Get the RTDs of a comma-separated list of names. */
std::vector<int> scenario::get_rtds(const char *ptr, bool start)
{
    std::vector<int> rtds;
    std::istringstream names(ptr);
    std::string name;

    while (std::getline(names, name, ',')) {
        if (int rtd = get_rtd(name.c_str(), start)) {
            rtds.push_back(rtd);
        }
    }
    return rtds;
}

/* Get a counter */
int scenario::get_counter(const char *ptr, const char *what)
{
    /* Check the name's validity. */
    if (ptr[0] == '\0') {
        ERROR("Counter names may not be empty for %s", what);
    }
    if (strcspn(ptr, "$,") != strlen(ptr)) {
        ERROR("Counter names may not contain '$' or ',' for %s", what);
    }

    return stats->findCounter(ptr, true);
}


/* Some validation functions. */

void scenario::validate_variable_usage()
{
    if (!uses_lua) {
        allocVars->validate();
    }
}

void scenario::validate_txn_usage()
{
    for (unsigned int i = 0; i < transactions.size(); i++) {
        if(transactions[i].started == 0) {
            ERROR("Transaction %s is never started!", transactions[i].name.c_str());
        }
        if (transactions[i].server) {
            /* Started by a received request: we send its responses */
            if (transactions[i].sent_responses == 0) {
                ERROR("Transaction %s has no responses defined!", transactions[i].name.c_str());
            } else if (transactions[i].responses || transactions[i].acks) {
                ERROR("Transaction %s is started by a received request: it takes no received responses or ACK!",
                      transactions[i].name.c_str());
            }
            continue;
        }
        if (transactions[i].sent_responses) {
            ERROR("Transaction %s is started by a sent request: it takes no sent responses!",
                  transactions[i].name.c_str());
        } else if(transactions[i].responses == 0) {
            ERROR("Transaction %s has no responses defined!", transactions[i].name.c_str());
        }
        if (transactions[i].isInvite && transactions[i].acks == 0) {
            ERROR("Transaction %s is an INVITE transaction without an ACK!", transactions[i].name.c_str());
        }
        if (!transactions[i].isInvite && (transactions[i].acks > 0)) {
            ERROR("Transaction %s is a non-INVITE transaction with an ACK!", transactions[i].name.c_str());
        }
    }
}

/* Apply the next and ontimeout labels according to our map. */
void scenario::apply_labels(msgvec v, str_int_map labels)
{
    for (unsigned int i = 0; i < v.size(); i++) {
        if (v[i]->nextLabel) {
            str_int_map::iterator label_it = labels.find(*v[i]->nextLabel);
            if (label_it == labels.end()) {
                ERROR("The label '%s' was not defined (index %d, next attribute)", v[i]->nextLabel->c_str(), i);
            }
            v[i]->next = label_it->second;
        }
        if (v[i]->onTimeoutLabel) {
            str_int_map::iterator label_it = labels.find(*v[i]->onTimeoutLabel);
            if (label_it == labels.end()) {
                ERROR("The label '%s' was not defined (index %d, ontimeout attribute)", v[i]->onTimeoutLabel->c_str(),
                      i);
            }
            v[i]->on_timeout = label_it->second;
        }
    }
}

/* Remove the character at offset which of each pair in msg, until none is left */
static void remove_pairs(std::string &msg, const char *pair, int which)
{
    size_t pos;
    while ((pos = msg.find(pair)) != std::string::npos) {
        msg.erase(pos + which, 1);
    }
}

static std::string clean_cdata(const char *ptr, int *removed_crlf = nullptr)
{
    while((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n')) ptr++;

    std::string msg = ptr;

    while (!msg.empty() && (msg.back() == ' ' || msg.back() == '\t' || msg.back() == '\n')) {
        if (msg.back() == '\n' && removed_crlf) {
            (*removed_crlf)++;
        }
        msg.pop_back();
    }

    if (msg.empty()) {
        ERROR("Empty cdata in xml scenario file");
    }
    remove_pairs(msg, "\n ", 1);
    remove_pairs(msg, " \n", 0);
    remove_pairs(msg, "\n\t", 1);
    remove_pairs(msg, "\t\n", 0);

    if (msg.find("\n\n") == std::string::npos) {
        msg += "\n\n";
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
    /* The methods of the requests sent so far, run together */
    std::string method_list;
    unsigned int scenario_file_cursor = 0;
    int L_content_length = 0;
    const char* cptr;

    last_recv_optional = false;

    if(filename) {
        if(!xp_set_xml_buffer_from_file(filename)) {
            if (*xp_get_error()) {
                ERROR("Unable to load '%s' xml scenario file: %s", filename,
                      xp_get_error());
            }
            ERROR("Unable to load or parse '%s' xml scenario file", filename);
        }
    } else {
        if(!xp_set_xml_buffer_from_string(default_scenario[deflt])) {
            ERROR("Unable to load default xml scenario file");
        }
    }

    stats = new CStat();
    allocVars = new AllocVariableTable(userVariables);

    if(filename) {
        setFileName(filename);
    }
    hidedefault = false;

    elem = xp_open_element(0);
    if (!elem) {
        ERROR("No element in xml scenario file");
    }
    if(strcmp("scenario", elem)) {
        ERROR("No 'scenario' section in xml scenario file");
    }

    if ((cptr = xp_get_value("name"))) {
        name = cptr;
    }

    duration = 0;
    found_timewait = false;

    scenario_file_cursor = 0;

    while ((elem = xp_open_element(scenario_file_cursor))) {
        char * ptr;
        scenario_file_cursor ++;

        if(!strcmp(elem, "CallLengthRepartition")) {
            stats->setRepartitionCallLength(xp_get_string("value", "CallLengthRepartition").data());
        } else if(!strcmp(elem, "ResponseTimeRepartition")) {
            stats->setRepartitionResponseTime(xp_get_string("value", "ResponseTimeRepartition").data());
        } else if(!strcmp(elem, "Global")) {
            for (const std::string &varName : createStringTable(xp_get_string("variables", "Global"))) {
                globalVariables->find(varName.c_str(), true);
            }
        } else if(!strcmp(elem, "User")) {
            for (const std::string &varName : createStringTable(xp_get_string("variables", "User"))) {
                userVariables->find(varName.c_str(), true);
            }
        } else if(!strcmp(elem, "Reference")) {
            for (const std::string &varName : createStringTable(xp_get_string("variables", "Reference"))) {
                int id = allocVars->find(varName.c_str(), false);
                if (id == -1) {
                    ERROR("Could not reference non-existent variable '%s'", varName.c_str());
                }
            }
        } else if(!strcmp(elem, "DefaultMessage")) {
            std::string id = xp_get_string("id", "DefaultMessage");
            if(!(ptr = xp_get_cdata())) {
                ERROR("No CDATA in 'send' section of xml scenario file");
            }
            set_default_message(id.c_str(), clean_cdata(ptr));
            /* XXX: This should really be per scenario. */
        } else if(!strcmp(elem, "label")) {
            std::string id = xp_get_string("id", "label");
            if (labelMap.find(id) != labelMap.end()) {
                ERROR("The label name '%s' is used twice.", id.c_str());
            }
            labelMap[std::move(id)] = messages.size();
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
                    std::string id = xp_get_string("id", "label");
                    if (initLabelMap.find(id) != initLabelMap.end()) {
                        ERROR("The label name '%s' is used twice.", id.c_str());
                    }
                    initLabelMap[std::move(id)] = initmessages.size();
                } else {
                    ERROR("Invalid element in an init stanza: '%s'", initelem);
                }
                xp_close_element();
            }
        } else { /** Message Case */
            if (found_timewait) {
                ERROR("<timewait> can only be the last message in a scenario!");
            }
            message *curmsg = new message(messages.size(), name.c_str());
            messages.push_back(curmsg);

            if(!strcmp(elem, "send")) {
                checkOptionalRecv(elem, scenario_file_cursor);
                curmsg->M_type = MSG_TYPE_SEND;
                /* Sent messages descriptions */
                if(!(ptr = xp_get_cdata())) {
                    ERROR("No CDATA in 'send' section of xml scenario file");
                }

                int removed_clrf = 0;
                std::string msg = clean_cdata(ptr, &removed_clrf);

                const header_value cl = get_header(msg.c_str(), "Content-Length:", true);
                L_content_length = !cl.empty() ? (int)header_number(cl.view()) : -1;
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

                if ((msg.back() != '\n') && (removed_clrf)) {
                    msg += "\n";
                }
                curmsg->send_scheme = new SendingMessage(this, msg.c_str());

                // If this is a request we are sending, then store our transaction/method matching information.
                if (!curmsg->send_scheme->isResponse()) {
                    const char *method = curmsg->send_scheme->getMethod();
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
                        method_list += method;
                    }
                    if (xp_get_value("response_txn")) {
                        ERROR("response_txn can only be used for received responses or sent responses.");
                    }
                } else {
                    if (xp_get_value("start_txn")) {
                        ERROR("Responses can not start a transaction");
                    }
                    if (xp_get_value("ack_txn")) {
                        ERROR("Responses can not ACK a transaction");
                    }
                    if ((cptr = xp_get_value("response_txn"))) {
                        curmsg->response_txn = get_txn(cptr, "transaction response", false, false, false, true);
                    }
                }

                curmsg -> retrans_delay = xp_get_long("retrans", "retransmission timer", 0);
                curmsg -> timeout = xp_get_long("timeout", "message send timeout", 0);
            } else if (!strcmp(elem, "recv")) {
                curmsg->M_type = MSG_TYPE_RECV;
                /* Received messages descriptions */
                if((cptr = xp_get_value("response"))) {
                    curmsg->recv_response = cptr;
                    curmsg->recv_response_code = atoi(cptr);
                    curmsg->recv_response_for_cseq_method_list = method_list;
                    if ((cptr = xp_get_value("response_txn"))) {
                        curmsg->response_txn = get_txn(cptr, "transaction response", false, false, false);
                    }
                }

                if ((cptr = xp_get_value("request"))) {
                    curmsg->recv_request = cptr;
                    if (xp_get_value("response_txn")) {
                        ERROR("response_txn can only be used for received responses.");
                    }
                    if ((cptr = xp_get_value("start_txn"))) {
                        if (*curmsg->recv_request == "ACK") {
                            ERROR("An ACK message can not start a transaction!");
                        }
                        curmsg->start_txn = get_txn(cptr, "start transaction", true, false, false, true);
                    }
                }

                curmsg->optional = xp_get_optional("optional", "recv");
                last_recv_optional = curmsg->optional;
                curmsg->advance_state = xp_get_bool("advance_state", "recv", true);
                if (!curmsg->advance_state && curmsg->optional == OPTIONAL_FALSE) {
                    ERROR("advance_state is allowed only for optional messages (index = %zu)", messages.size() - 1);
                }

                if ((cptr = xp_get_value("regexp_match"))) {
                    if (!strcmp(cptr, "true")) {
                        curmsg->regexp_match = 1;
                    }
                }

                if ((cptr = xp_get_value("timeout")) && strchr(cptr, '[')) {
                    curmsg->timeout_scheme = new SendingMessage(this, cptr, true /* skip sanity */);
                } else {
                    curmsg->timeout = xp_get_long("timeout", "message timeout", 0);
                }

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
                    curmsg->peer_src = cptr;
                } else if (extendedTwinSippMode) {
                    ERROR("You must specify a 'src' for recvCmd when using extended 3pcc mode!");
                }
            } else if(!strcmp(elem, "sendCmd")) {
                checkOptionalRecv(elem, scenario_file_cursor);
                curmsg->M_type = MSG_TYPE_SENDCMD;
                /* Sent messages descriptions */

                /* 3pcc extended mode */
                if ((cptr = xp_get_value("dest"))) {
                    curmsg->peer_dest = cptr;
                    const std::string &peer = curmsg->peer_dest;
                    peer_map::iterator peer_it;
                    peer_it = peers.find(peer);
                    if(peer_it == peers.end())
                        /* the peer (slave or master)
                        has not been added in the map
                        (first occurrence in the scenario) */
                    {
                        T_peer_infos infos = {};
                        infos.peer_socket = 0;
                        infos.peer_host = get_peer_addr(peer);
                        peers[peer] = std::move(infos);
                    }
                } else if (extendedTwinSippMode) {
                    ERROR("You must specify a 'dest' for sendCmd with extended 3pcc mode!");
                }

                if (!(ptr = xp_get_cdata())) {
                    ERROR("No CDATA in 'sendCmd' section of xml scenario file");
                }
                curmsg->M_sendCmdData = new SendingMessage(this, clean_cdata(ptr).c_str(), true /* skip sanity */);
            } else {
                ERROR("Unknown element '%s' in xml scenario file", elem);
            }

            if (curmsg->M_type == MSG_TYPE_SEND || curmsg->M_type == MSG_TYPE_RECV) {
                long dialog = xp_get_long("dialog", "dialog number", 0);
                if (xp_get_value("dialog") && (dialog < 1 || dialog > INT_MAX)) {
                    ERROR("dialog must be a positive number, not '%s'", xp_get_value("dialog"));
                }
                curmsg->dialog = dialog;
                if (dialog > 1) {
                    dialogs = true;
                    if (curmsg->recv_request) {
                        new_dialogs = true;
                    }
                }
            }

            getCommonAttributes(curmsg);
        } /** end * Message case */
        xp_close_element();
    } // end while

    /* Close scenario element */
    xp_close_element();
    if (xp_is_invalid()) {
        ERROR("Invalid XML in scenario near line %d. See: https://github.com/SIPp/sipp/issues/414",
                xp_get_invalid_line());
    }

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
    if (messages[0]->M_type == MSG_TYPE_RECV && messages[0]->dialog > 1) {
        ERROR("A call begins in dialog 1: its first message can not have dialog=\"%d\"",
              messages[0]->dialog);
    }
}

void scenario::runInit()
{
    call *initcall;
    if (initmessages.size() > 0) {
        initcall = new call(this, nullptr, nullptr, "///main-init", 0, false, false, true);
        initcall->run();
    }
}

scenario::~scenario()
{
    for (msgvec::iterator i = messages.begin(); i != messages.end(); i++) {
        delete *i;
    }
    messages.clear();
    for (msgvec::iterator i = initmessages.begin(); i != initmessages.end(); i++) {
        delete *i;
    }
    initmessages.clear();

    allocVars->putTable();
    delete stats;

    /* transactions vector with std::string name members auto-cleans */

    /* Maps with std::string keys/values auto-clean via destructors.
     * No manual clearing needed - removed buggy clear_* calls. */
}

CSample *parse_distribution(bool oldstyle = false)
{
    CSample *distribution = nullptr;
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
        distribution = new CNegBin(p, n);
#else
    } else if (!strcmp(distname, "normal")
               || !strcmp(distname, "lognormal")
               || !strcmp(distname, "exponential")
               || !strcmp(distname, "pareto")
               || !strcmp(distname, "gamma")
               || !strcmp(distname, "negbin")
               || !strcmp(distname, "weibull")) {
        ERROR("The distribution '%s' is only available with GSL", distname);
#endif
    } else {
        ERROR("Unknown distribution: %s", distname);
    }

    return distribution;
}



/* 3pcc extended mode:
 * get the correspondences between
 * slave and master names and their
 * addresses */

void parse_slave_cfg()
{
    FILE * f;
    char line[MAX_PEER_SIZE];
    char * temp_peer;
    char *temp_host;

    f = fopen(slave_cfg_file, "r");
    if(f) {
        while (fgets(line, MAX_PEER_SIZE, f) != nullptr) {
            temp_peer = strtok(line, ";");
            if (!temp_peer)
                continue;

            temp_host = strtok(nullptr, ";");
            if (!temp_host)
                continue;

            peer_addrs[temp_peer] = temp_host;
        }
    } else {
        ERROR("Can not open -slave_cfg/-secondary_cfg file %s", slave_cfg_file);
    }

    fclose(f);
}

bool scenario::startsWith(const char *msg)
{
    /* A call jumps to _unexp.main on any message it doesn't expect. */
    if (unexpected_jump >= 0) {
        return true;
    }

    int code = get_reply_code(msg);
    std::string method(msg, strcspn(msg, " \t\r\n"));

    for (message *curmsg : messages) {
        if (curmsg->M_type == MSG_TYPE_PAUSE || curmsg->M_type == MSG_TYPE_NOP) {
            continue;
        }
        if (curmsg->M_type != MSG_TYPE_RECV) {
            return true;
        }
        if (code ? curmsg->matchesResponse(code) : curmsg->matchesRequest(method.c_str())) {
            return true;
        }
        if (curmsg->optional == OPTIONAL_FALSE) {
            return false;
        }
    }
    return true;
}

// Determine in which mode the sipp tool has been
// launched (client, server, 3pcc client, 3pcc server, 3pcc extended master or slave)
void scenario::computeSippMode()
{
    bool isRecvCmdFound = false;
    bool isSendCmdFound = false;

    if (creationMode != MODE_MIXED) {
        creationMode = -1;
    }
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
                    ERROR("Inconsistency between command line and scenario: master scenario but -master/-primary option not set");
                }
                if(!twinSippMode && !extendedTwinSippMode)
                    ERROR("sendCmd message found in scenario but no twin sipp"
                          " address has been passed! Use -3pcc option or 3pcc extended mode");
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
                        ERROR("Inconsistency between command line and scenario: slave scenario but -slave/-secondary option not set");
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
    /* A 3PCC scenario with only commands sends no SIP: like a server, it
     * needs no remote host. */
    if (sendMode == -1 && (isSendCmdFound || isRecvCmdFound)) {
        sendMode = MODE_SERVER;
    }
    if(creationMode == -1)
        ERROR("Unable to determine creation mode of the tool (server, client)");
    if(sendMode == -1)
        ERROR("Unable to determine send mode of the tool (server, client)");
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
    int sub_currentNbVarId;
    const char* cptr;

    while((actionElem = xp_open_element(recvScenarioLen))) {
        CAction *tmpAction = new CAction(this);

        if(!strcmp(actionElem, "ereg")) {
            std::string regexp = xp_get_string("regexp", "ereg");

            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_REGEXP);

            // warning - although these are detected for both msg and hdr
            // they are only implemented for search_in="hdr"
            tmpAction->setCaseIndep(xp_get_bool("case_indep", "ereg", false));
            tmpAction->setHeadersOnly(xp_get_bool("start_line", "ereg", false));

            if ((cptr = xp_get_value("search_in"))) {
                tmpAction->setOccurrence(1);

                if (strcmp(cptr, "msg") == 0) {
                    tmpAction->setLookingPlace(CAction::E_LP_MSG);
                } else if (strcmp(cptr, "body") == 0) {
                    tmpAction->setLookingPlace(CAction::E_LP_BODY);
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
            } // end if-else search_in

            if (xp_get_value("check_it")) {
                tmpAction->setCheckIt(xp_get_bool("check_it", "ereg", false));
                if (xp_get_value("check_it_inverse")) {
                    ERROR("Can not have both check_it and check_it_inverse for ereg!");
                }
            } else {
                tmpAction->setCheckItInverse(xp_get_bool("check_it_inverse", "ereg", false));
            }

            if (!(cptr = xp_get_value("assign_to"))) {
                ERROR("assign_to value is missing");
            }

            std::vector<std::string> varNames = createStringTable(cptr);

            int varId = get_var(varNames[0].c_str(), "assign_to");
            tmpAction->setVarId(varId);

            tmpAction->setRegExp(regexp);
            if (varNames.size() > 1) {
                sub_currentNbVarId = varNames.size() - 1;
                tmpAction->setNbSubVarId(sub_currentNbVarId);

                for(int i=1; i<= sub_currentNbVarId; i++) {
                    tmpAction->setSubVarId(get_var(varNames[i].c_str(), "sub expression assign_to"));
                }
            }
        } /* end !strcmp(actionElem, "ereg") */ else if(!strcmp(actionElem, "log")) {
            tmpAction->setMessage(xp_get_string("message", "log"));
            tmpAction->setActionType(CAction::E_AT_LOG_TO_FILE);
        } else if(!strcmp(actionElem, "warning")) {
            tmpAction->setMessage(xp_get_string("message", "warning"));
            tmpAction->setActionType(CAction::E_AT_LOG_WARNING);
        } else if(!strcmp(actionElem, "error")) {
            tmpAction->setMessage(xp_get_string("message", "error"));
            tmpAction->setActionType(CAction::E_AT_LOG_ERROR);
        } else if(!strcmp(actionElem, "assign")) {
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_VALUE);
            handle_arithmetic(tmpAction, "assign");
        } else if(!strcmp(actionElem, "assignstr")) {
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_STRING);
            tmpAction->setVarId(xp_get_var("assign_to", "assignstr"));
            tmpAction->setMessage(xp_get_string("value", "assignstr"));
        } else if(!strcmp(actionElem, "gettimeofday")) {
            tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_GETTIMEOFDAY);

            if (!(cptr = xp_get_value("assign_to"))) {
                ERROR("assign_to value is missing");
            }
            std::vector<std::string> varNames = createStringTable(cptr);
            if (varNames.size() != 2) {
                ERROR("The gettimeofday action requires two output variables!");
            }
            tmpAction->setNbSubVarId(1);

            int varId = get_var(varNames[0].c_str(), "gettimeofday seconds assign_to");
            tmpAction->setVarId(varId);
            varId = get_var(varNames[1].c_str(), "gettimeofday useconds assign_to");
            tmpAction->setSubVarId(varId);
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
            if (xp_get_value("check_it")) {
                tmpAction->setCheckIt(xp_get_bool("check_it", "test"));
                if (xp_get_value("check_it_inverse")) {
                    ERROR("Can not have both check_it and check_it_inverse for test!");
                }
            } else if (xp_get_value("check_it_inverse")) {
                tmpAction->setCheckItInverse(xp_get_bool("check_it_inverse", "test"));
            }
            // "assign_to" is optional when "check_it" or "check_it_inverse" set
            if (xp_get_value("assign_to") ||
                (!xp_get_value("check_it") && !xp_get_value("check_it_inverse"))
            ) {
                tmpAction->setVarId(xp_get_var("assign_to", "test"));
            }
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
            std::string compare = xp_get_string("compare", "test");
            if (compare == "equal") {
                tmpAction->setComparator(CAction::E_C_EQ);
            } else if (compare == "not_equal") {
                tmpAction->setComparator(CAction::E_C_NE);
            } else if (compare == "greater_than") {
                tmpAction->setComparator(CAction::E_C_GT);
            } else if (compare == "less_than") {
                tmpAction->setComparator(CAction::E_C_LT);
            } else if (compare == "greater_than_equal") {
                tmpAction->setComparator(CAction::E_C_GEQ);
            } else if (compare == "less_than_equal") {
                tmpAction->setComparator(CAction::E_C_LEQ);
            } else {
                ERROR("Invalid 'compare' parameter: %s", compare.c_str());
            }
        } else if(!strcmp(actionElem, "verifyauth")) {
            tmpAction->setVarId(xp_get_var("assign_to", "verifyauth"));
            std::string username = xp_get_string("username", "verifyauth");
            std::string password = xp_get_string("password", "verifyauth");
            tmpAction->setMessage(username, 0);
            tmpAction->setMessage(password, 1);
            tmpAction->setActionType(CAction::E_AT_VERIFY_AUTH);
        } else if(!strcmp(actionElem, "lookup")) {
            tmpAction->setVarId(xp_get_var("assign_to", "lookup"));
            xp_set_message(tmpAction, 0, "file", "lookup");
            xp_set_message(tmpAction, 1, "key", "lookup");
            tmpAction->setActionType(CAction::E_AT_LOOKUP);
        } else if(!strcmp(actionElem, "insert")) {
            xp_set_message(tmpAction, 0, "file", "insert");
            xp_set_message(tmpAction, 1, "value", "insert");
            tmpAction->setActionType(CAction::E_AT_INSERT);
        } else if(!strcmp(actionElem, "replace")) {
            xp_set_message(tmpAction, 0, "file", "replace");
            xp_set_message(tmpAction, 1, "line", "replace");
            xp_set_message(tmpAction, 2, "value", "replace");
            tmpAction->setActionType(CAction::E_AT_REPLACE);
        } else if(!strcmp(actionElem, "setdest")) {
            xp_set_message(tmpAction, 0, "host", "setdest");
            xp_set_message(tmpAction, 1, "port", "setdest");
            xp_set_message(tmpAction, 2, "protocol", "setdest");
            tmpAction->setActionType(CAction::E_AT_SET_DEST);
        } else if(!strcmp(actionElem, "closecon")) {
            tmpAction->setActionType(CAction::E_AT_CLOSE_CON);
        } else if(!strcmp(actionElem, "strcmp")) {
            if (xp_get_value("check_it")) {
                tmpAction->setCheckIt(xp_get_bool("check_it", "strcmp"));
                if (xp_get_value("check_it_inverse")) {
                    ERROR("Can not have both check_it and check_it_inverse for strcmp!");
                }
            } else if (xp_get_value("check_it_inverse")) {
                tmpAction->setCheckItInverse(xp_get_bool("check_it_inverse", "strcmp"));
            }
            // "assign_to" is optional when "check_it" or "check_it_inverse" set
            if (xp_get_value("assign_to") ||
                (!xp_get_value("check_it") && !xp_get_value("check_it_inverse"))
            ) {
                tmpAction->setVarId(xp_get_var("assign_to", "strcmp"));
            }
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
        } else if(!strcmp(actionElem, "urldecode")) {
            tmpAction->setVarId(xp_get_var("variable", "urldecode"));
            tmpAction->setActionType(CAction::E_AT_VAR_URLDECODE);
        } else if(!strcmp(actionElem, "urlencode")) {
            tmpAction->setVarId(xp_get_var("variable", "urlencode"));
            tmpAction->setActionType(CAction::E_AT_VAR_URLENCODE);
        } else if(!strcmp(actionElem, "exec")) {
            if ((cptr = xp_get_value("command"))) {
                tmpAction->setActionType(CAction::E_AT_EXECUTE_CMD);
                tmpAction->setMessage(cptr);
            } else if ((cptr = xp_get_value("lua"))) {
#ifndef USE_LUA
                ERROR("Scenario specifies a lua action, but this version of SIPp does not have Lua support");
#endif
                uses_lua = true;
                tmpAction->setActionType(CAction::E_AT_EXEC_LUA);
                tmpAction->setMessage(cptr);
            } else if ((cptr = xp_get_value("verify"))) {
                tmpAction->setActionType(CAction::E_AT_VERIFY_CMD);
                tmpAction->setMessage(cptr);
            } else if ((cptr = xp_get_value("int_cmd"))) {
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
            } else if (std::optional<std::string> args = xp_get_keyword_value("play_pcap_audio")) {
                tmpAction->setPcapArgs(args->c_str());
                tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_AUDIO);
                pcap_plays = true;
                hasMedia = 1;
            } else if (std::optional<std::string> args = xp_get_keyword_value("play_pcap_image")) {
                tmpAction->setPcapArgs(args->c_str());
                tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_IMAGE);
                pcap_plays = true;
                hasMedia = 1;
            } else if (std::optional<std::string> args = xp_get_keyword_value("play_pcap_video")) {
                tmpAction->setPcapArgs(args->c_str());
                tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_VIDEO);
                pcap_plays = true;
                hasMedia = 1;
            } else if (std::optional<std::string> args = xp_get_keyword_value("play_pcap_text")) {
                tmpAction->setPcapArgs(args->c_str());
                tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_TEXT);
                pcap_plays = true;
                hasMedia = 1;
            } else if ((cptr = xp_get_value("play_dtmf"))) {
                /* without keywords, what would be played is known now */
                if (!strchr(cptr, '[')) {
                    unsigned long tone_len;
                    uint8_t payload_type;
                    std::string args = cptr;
                    const char *error = parse_dtmf(args.data(), &tone_len, &payload_type);
                    if (error) {
                        ERROR("Invalid play_dtmf \"%s\": %s", cptr, error);
                    }
                }
                tmpAction->setMessage(cptr);
                tmpAction->setActionType(CAction::E_AT_PLAY_DTMF);
                pcap_plays = true;
                hasMedia = 1;
#else
            } else if (xp_get_value("play_pcap_audio")) {
                ERROR("Scenario specifies a play_pcap_audio action, but this version of SIPp does not have PCAP support");
            } else if (xp_get_value("play_pcap_image")) {
                ERROR("Scenario specifies a play_pcap_image action, but this version of SIPp does not have PCAP support");
            } else if (xp_get_value("play_pcap_video")) {
                ERROR("Scenario specifies a play_pcap_video action, but this version of SIPp does not have PCAP support");
            } else if (xp_get_value("play_pcap_text")) {
                ERROR(
                    "Scenario specifies a play_pcap_text action, but this version of SIPp does not have PCAP support");
            } else if (xp_get_value("play_dtmf")) {
                ERROR("Scenario specifies a play_dtmf action, but this version of SIPp does not have PCAP support");
#endif
            } else if ((cptr = xp_get_value("rtp_stream"))) {
                std::string value = cptr;
                const char *ptr = value.c_str();
                hasMedia = 1;
                if (!strcmp(ptr, "pauseapattern"))
                {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PAUSEAPATTERN);
                }
                else if (!strcmp(ptr, "resumeapattern"))
                {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RESUMEAPATTERN);
                }
                else if (!strncmp(ptr, "apattern", 8))
                {
                    tmpAction->setMessage(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PLAYAPATTERN);
                }
                else if (!strcmp(ptr, "pausevpattern"))
                {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PAUSEVPATTERN);
                }
                else if (!strcmp(ptr, "resumevpattern"))
                {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RESUMEVPATTERN);
                }
                else if (!strncmp(ptr, "vpattern", 8))
                {
                    tmpAction->setMessage(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PLAYVPATTERN);
                }
                else if (!strcmp(ptr, "pause"))
                {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PAUSE);
                }
                else if (!strcmp(ptr, "resume"))
                {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RESUME);
                }
                else if (!strcmp(ptr, "wait"))
                {
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_WAIT);
                    long timeout = xp_get_long("timeout", "rtp_stream wait", 0);
                    if (timeout < 0) {
                        ERROR("rtp_stream wait timeout must not be negative");
                    }
                    tmpAction->setDoubleValue(timeout);
                }
                else
                {
                    /* Check a plain filename now; a filename with
                     * keywords can only be checked when played. */
                    if (!strchr(ptr, '[')) {
                        tmpAction->setRTPStreamActInfo(ptr);
                    }
                    tmpAction->setMessage(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_PLAY);
                }
            } else if ((cptr = xp_get_value("rtp_echo"))) {
                std::string value = cptr;
                const char *ptr = value.c_str();
                hasMedia = 1;
                if (!strncmp(ptr, "startaudio", 10))
                {
                    tmpAction->setRTPEchoActInfo(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RTPECHO_STARTAUDIO);
                }
                else if (!strncmp(ptr, "updateaudio", 11))
                {
                    tmpAction->setRTPEchoActInfo(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RTPECHO_UPDATEAUDIO);
                }
                else if (!strncmp(ptr, "stopaudio", 9))
                {
                    tmpAction->setRTPEchoActInfo(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RTPECHO_STOPAUDIO);
                }
                else if (!strncmp(ptr, "startvideo", 10))
                {
                    tmpAction->setRTPEchoActInfo(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RTPECHO_STARTVIDEO);
                }
                else if (!strncmp(ptr, "updatevideo", 11))
                {
                    tmpAction->setRTPEchoActInfo(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RTPECHO_UPDATEVIDEO);
                }
                else if (!strncmp(ptr, "stopvideo", 9))
                {
                    tmpAction->setRTPEchoActInfo(ptr);
                    tmpAction->setActionType(CAction::E_AT_RTP_STREAM_RTPECHO_STOPVIDEO);
                }
            } else {
                ERROR("illegal <exec> in the scenario");
            }
        } else if (!strcmp(actionElem, "rtp_stats")) {
            tmpAction->setActionType(CAction::E_AT_RTP_STATS);
            if (!(cptr = xp_get_value("assign_to"))) {
                ERROR("assign_to value is missing in rtp_stats");
            }
            std::vector<std::string> varNames = createStringTable(cptr);
            if (varNames.size() < 1 || varNames.size() > 3) {
                ERROR("rtp_stats assigns one to three variables: the packets, and the payload type and payload of the first");
            }
            tmpAction->setVarId(get_var(varNames[0].c_str(), "rtp_stats packets assign_to"));
            tmpAction->setNbSubVarId(varNames.size() - 1);
            for (size_t i = 1; i < varNames.size(); i++) {
                tmpAction->setSubVarId(get_var(varNames[i].c_str(), "rtp_stats assign_to"));
            }
            cptr = xp_get_value("media");
            if (cptr && strcmp(cptr, "audio") && strcmp(cptr, "video")) {
                ERROR("rtp_stats media must be audio or video, not %s", cptr);
            }
            tmpAction->setDoubleValue(cptr && !strcmp(cptr, "video"));
            rtp_stats_used = true;
        } else if (!strcmp(actionElem, "rtp_dtmf")) {
            tmpAction->setActionType(CAction::E_AT_RTP_DTMF);
            if (!(cptr = xp_get_value("assign_to"))) {
                ERROR("assign_to value is missing in rtp_dtmf");
            }
            tmpAction->setVarId(get_var(cptr, "rtp_dtmf assign_to"));
            long pt = 96;
            if ((cptr = xp_get_value("payload_type"))) {
                pt = get_long(cptr, "rtp_dtmf payload_type");
                if (pt < 0 || pt > 127) {
                    ERROR("rtp_dtmf payload_type must be from 0 to 127, not %s", cptr);
                }
            }
            tmpAction->setDoubleValue(pt);
            rtp_dtmf_payload_types[pt] = true;
            rtp_stats_used = true;
        } else if (!strcmp(actionElem, "rtp_echo")) {
            tmpAction->setActionType(CAction::E_AT_RTP_ECHO);
            handle_rhs(tmpAction, "rtp_echo");
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

    if (!(actionElem = xp_open_element(0))) {
        return;
    }
    if (strcmp(actionElem, "action")) {
        xp_close_element();
        return;
    }

    /* We actually have an action element. */
    if (message->M_actions != nullptr) {
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
        message->stop_rtd = get_rtds(ptr, false);
    }
    if ((ptr = xp_get_value("repeat_rtd"))) {
        if (!message->stop_rtd.empty()) {
            message->repeat_rtd = get_bool(ptr, "repeat_rtd");
        } else {
            ERROR("There is a repeat_rtd element without an rtd element");
        }
    }

    if ((ptr = xp_get_value("start_rtd"))) {
        message->start_rtd = get_rtds(ptr, true);
    }

    if ((ptr = xp_get_value("counter"))) {
        message->counter = get_counter(ptr, "counter");
    }
}

void scenario::getCommonAttributes(message *message)
{
    const char *ptr;

    getBookKeeping(message);
    getActionForThisMessage(message);

    if ((ptr = xp_get_value("lost"))) {
        message -> lost = get_double(ptr, "lost percentage");
        lose_packets = 1;
    }

    if ((ptr = xp_get_value("crlf"))) {
        message -> crlf = 1;
    }

    if ((ptr = xp_get_value("ignoresdp"))) {
        message->ignoresdp = get_bool(ptr, "ignoresdp");
    }

    if (xp_get_value("hiderest")) {
        hidedefault = xp_get_bool("hiderest", "hiderest");
    }
    message -> hide = xp_get_bool("hide", "hide", hidedefault);
    if((ptr = xp_get_value((char *)"display"))) {
        message->display_str = ptr;
    }

    message -> condexec = xp_get_var("condexec", "condexec variable", -1);
    message -> condexec_inverse = xp_get_bool("condexec_inverse", "condexec_inverse", false);

    if ((ptr = xp_get_value("next"))) {
        if (found_timewait) {
            ERROR("next labels are not allowed in <timewait> elements.");
        }
        message->nextLabel = ptr;
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
        message->onTimeoutLabel = ptr;
    }
}

std::vector<std::string> createStringTable(std::string_view inputString)
{
    std::vector<std::string> stringList;
    size_t comma;

    while ((comma = inputString.find(',')) != std::string_view::npos) {
        stringList.emplace_back(inputString.substr(0, comma));
        inputString.remove_prefix(comma + 1);
    }
    stringList.emplace_back(inputString);
    return stringList;
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

    ERROR("Invalid default scenario name '%s'", scenario);
    return -1;
}

// docs/<name>.xml, made into a string literal by CMakeLists.txt, in
// scenario_table's order.
const char *default_scenario[] = {
#include "docs/uac.xml.inc"
#include "docs/uas.xml.inc"
#include "docs/regexp.xml.inc"
#include "docs/3pcc-C-A.xml.inc"
#include "docs/3pcc-C-B.xml.inc"
#include "docs/3pcc-A.xml.inc"
#include "docs/3pcc-B.xml.inc"
#include "docs/branchc.xml.inc"
#include "docs/branchs.xml.inc"
#include "docs/uac_pcap.xml.inc"
#include "docs/ooc_default.xml.inc"
#include "docs/ooc_dummy.xml.inc"
};

#ifdef GTEST
#include "gtest/gtest.h"

TEST(get_long, decimal_or_hex) {
    EXPECT_EQ(10, get_long("010", "test"));
    EXPECT_EQ(-10, get_long("-010", "test"));
    EXPECT_EQ(16, get_long("0x10", "test"));
    EXPECT_EQ(8ULL, get_long_long("08", "test"));
    EXPECT_TRUE(get_bool("08", "test"));
    EXPECT_FALSE(get_bool("0x0", "test"));
}

TEST(get_long, refuses_empty_and_garbage) {
    EXPECT_DEATH(get_long("", "test"), "is not a valid integer");
    EXPECT_DEATH(get_long("5x", "test"), "is not a valid integer");
    EXPECT_DEATH(get_long_long("", "test"), "is not a valid integer");
    EXPECT_DEATH(get_int("4294967296", "test"), "is not a valid integer");
    EXPECT_DEATH(get_bool("", "test"), "is not a valid boolean");
    EXPECT_DEATH(get_double("", "test"), "is not a floating point number");
}
#endif //GTEST
