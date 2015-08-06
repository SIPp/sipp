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
 *  Authors : Benjamin GAUTHIER - 24 Mar 2004
 *            Joseph BANINO
 *            Olivier JACQUES
 *            Richard GAYRAUD
 *            From Hewlett Packard Company.
 */

#ifndef __STAT_H__
#define __STAT_H__


#define TIME_LENGTH 64
#define DEFAULT_FILE_NAME (char*)"dumpFile"
#define DEFAULT_EXTENSION (char*)".csv"

#define MAX_CHAR_BUFFER_SIZE 1024

#include <ctime>
#include <vector>
#include <string>
#include <sys/time.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <stdio.h>

#ifdef HAVE_GSL
#include <gsl/gsl_rng.h>
#include <gsl/gsl_randist.h>
#include <gsl/gsl_cdf.h>
#endif

#include "variables.hpp"

using namespace std;

/*
__________________________________________________________________________

              C S t a t    C L A S S
__________________________________________________________________________
*/

/**
 * This class provides some means to compute and display statistics.
 * This is a singleton class.
 */

class CStat
{
public:

    std::vector<int> error_codes;

    /*
     * This struct is used for repartition table
     * border max is the max value allow for this range
     * nbInThisBorder is the counter of value in this range
     */
    typedef struct _T_dynamicalRepartition {
        unsigned int  borderMax;
        unsigned long nbInThisBorder;
    } T_dynamicalRepartition;

    typedef struct _T_value_rtt {
        double  date ;
        int  rtd_no ;
        double  rtt  ;
    } T_value_rtt, *T_pValue_rtt ;

    /**
     * Actions on counters
     */
    enum E_Action {
        E_NO_ACTION,
        E_CREATE_OUTGOING_CALL,
        E_CREATE_INCOMING_CALL,
        E_CALL_FAILED,
        E_CALL_SUCCESSFULLY_ENDED,
        E_RESET_C_COUNTERS,
        E_RESET_PD_COUNTERS,
        E_RESET_PL_COUNTERS,
        E_ADD_CALL_DURATION,
        E_ADD_RESPONSE_TIME_DURATION,
        E_FAILED_CANNOT_SEND_MSG,
        E_FAILED_MAX_UDP_RETRANS,
        E_FAILED_TCP_CONNECT,
        E_FAILED_TCP_CLOSED,
        E_FAILED_UNEXPECTED_MSG,
        E_FAILED_CALL_REJECTED,
        E_FAILED_CMD_NOT_SENT,
        E_FAILED_REGEXP_DOESNT_MATCH,
        E_FAILED_REGEXP_SHOULDNT_MATCH,
        E_FAILED_REGEXP_HDR_NOT_FOUND,
        E_FAILED_OUTBOUND_CONGESTION,
        E_FAILED_TIMEOUT_ON_RECV,
        E_FAILED_TIMEOUT_ON_SEND,
        E_OUT_OF_CALL_MSGS,
        E_WATCHDOG_MAJOR,
        E_WATCHDOG_MINOR,
        E_DEAD_CALL_MSGS,
        E_FATAL_ERRORS,
        E_WARNING,
        E_RETRANSMISSION,
        E_AUTO_ANSWERED,
        E_ADD_GENERIC_COUNTER
    };
    /**
     * Counters management
     */
    enum E_CounterName {
        // Per-Scenario Counters
        // Cumulative counters
        CPT_C_IncomingCallCreated,
        CPT_C_OutgoingCallCreated,
        CPT_C_SuccessfulCall,
        CPT_C_FailedCall,
        CPT_C_CurrentCall,
        CPT_C_CurrentCallPeak,
        CPT_C_CurrentCallPeakTime,
        CPT_C_NbOfCallUsedForAverageCallLength,
        CPT_C_AverageCallLength_Sum,
        CPT_C_AverageCallLength_Squares,
        CPT_C_FailedCallCannotSendMessage,
        CPT_C_FailedCallMaxUdpRetrans,
        CPT_C_FailedCallTcpConnect,
        CPT_C_FailedCallTcpClosed,
        CPT_C_FailedCallUnexpectedMessage,
        CPT_C_FailedCallCallRejected,
        CPT_C_FailedCallCmdNotSent,
        CPT_C_FailedCallRegexpDoesntMatch,
        CPT_C_FailedCallRegexpShouldntMatch,
        CPT_C_FailedCallRegexpHdrNotFound,
        CPT_C_FailedOutboundCongestion,
        CPT_C_FailedTimeoutOnRecv,
        CPT_C_FailedTimeoutOnSend,
        CPT_C_Retransmissions,

        // Periodic Display counter
        CPT_PD_IncomingCallCreated, // must be first (RESET_PD_COUNTER macro)
        CPT_PD_OutgoingCallCreated,
        CPT_PD_SuccessfulCall,
        CPT_PD_FailedCall,
        CPT_PD_CurrentCallPeak,
        CPT_PD_CurrentCallPeakTime,
        CPT_PD_NbOfCallUsedForAverageCallLength,
        CPT_PD_AverageCallLength_Sum,
        CPT_PD_AverageCallLength_Squares,
        CPT_PD_NbOfCallUsedForAverageResponseTime,
        CPT_PD_NbOfCallUsedForAverageResponseTime_2, // This must match or exceed MAX_RTD_INFO
        CPT_PD_NbOfCallUsedForAverageResponseTime_3, // This must match or exceed MAX_RTD_INFO
        CPT_PD_NbOfCallUsedForAverageResponseTime_4, // This must match or exceed MAX_RTD_INFO
        CPT_PD_NbOfCallUsedForAverageResponseTime_5, // This must match or exceed MAX_RTD_INFO
        CPT_PD_AverageResponseTime_Sum,
        CPT_PD_AverageResponseTime_Sum_2,
        CPT_PD_AverageResponseTime_Sum_3,
        CPT_PD_AverageResponseTime_Sum_4,
        CPT_PD_AverageResponseTime_Sum_5,
        CPT_PD_AverageResponseTime_Squares,
        CPT_PD_AverageResponseTime_Squares_2,
        CPT_PD_AverageResponseTime_Squares_3,
        CPT_PD_AverageResponseTime_Squares_4,
        CPT_PD_AverageResponseTime_Squares_5,
        CPT_PD_FailedCallCannotSendMessage,
        CPT_PD_FailedCallMaxUdpRetrans,
        CPT_PD_FailedCallTcpConnect,
        CPT_PD_FailedCallTcpClosed,
        CPT_PD_FailedCallUnexpectedMessage,
        CPT_PD_FailedCallCallRejected,
        CPT_PD_FailedCallCmdNotSent,
        CPT_PD_FailedCallRegexpDoesntMatch,
        CPT_PD_FailedCallRegexpShouldntMatch,
        CPT_PD_FailedCallRegexpHdrNotFound,
        CPT_PD_FailedOutboundCongestion,
        CPT_PD_FailedTimeoutOnRecv,
        CPT_PD_FailedTimeoutOnSend,
        CPT_PD_Retransmissions,

        // Periodic logging counter
        CPT_PL_IncomingCallCreated, // must be first (RESET_PL_COUNTER macro)
        CPT_PL_OutgoingCallCreated,
        CPT_PL_SuccessfulCall,
        CPT_PL_FailedCall,
        CPT_PL_CurrentCallPeak,
        CPT_PL_CurrentCallPeakTime,
        CPT_PL_NbOfCallUsedForAverageCallLength,
        CPT_PL_AverageCallLength_Sum,
        /* The squares let us compute the standard deviation. */
        CPT_PL_AverageCallLength_Squares,
        CPT_PL_NbOfCallUsedForAverageResponseTime,
        CPT_PL_NbOfCallUsedForAverageResponseTime_2,
        CPT_PL_NbOfCallUsedForAverageResponseTime_3,
        CPT_PL_NbOfCallUsedForAverageResponseTime_4,
        CPT_PL_NbOfCallUsedForAverageResponseTime_5,
        CPT_PL_AverageResponseTime_Sum,
        CPT_PL_AverageResponseTime_Sum_2,
        CPT_PL_AverageResponseTime_Sum_3,
        CPT_PL_AverageResponseTime_Sum_4,
        CPT_PL_AverageResponseTime_Sum_5,
        CPT_PL_AverageResponseTime_Squares,
        CPT_PL_AverageResponseTime_Squares_2,
        CPT_PL_AverageResponseTime_Squares_3,
        CPT_PL_AverageResponseTime_Squares_4,
        CPT_PL_AverageResponseTime_Squares_5,
        CPT_PL_FailedCallCannotSendMessage,
        CPT_PL_FailedCallMaxUdpRetrans,
        CPT_PL_FailedCallTcpConnect,
        CPT_PL_FailedCallTcpClosed,
        CPT_PL_FailedCallUnexpectedMessage,
        CPT_PL_FailedCallCallRejected,
        CPT_PL_FailedCallCmdNotSent,
        CPT_PL_FailedCallRegexpDoesntMatch,
        CPT_PL_FailedCallRegexpShouldntMatch,
        CPT_PL_FailedCallRegexpHdrNotFound,
        CPT_PL_FailedOutboundCongestion,
        CPT_PL_FailedTimeoutOnRecv,
        CPT_PL_FailedTimeoutOnSend,
        CPT_PL_Retransmissions,

        E_NB_COUNTER,

        // Global Counters
        // Cumulative counters
        CPT_G_C_OutOfCallMsgs,
        CPT_G_C_DeadCallMsgs,
        CPT_G_C_FatalErrors,
        CPT_G_C_Warnings,
        CPT_G_C_WatchdogMajor,
        CPT_G_C_WatchdogMinor,
        CPT_G_C_AutoAnswered,
        // Periodic Display counter
        CPT_G_PD_OutOfCallMsgs,
        CPT_G_PD_DeadCallMsgs,
        CPT_G_PD_FatalErrors,
        CPT_G_PD_Warnings,
        CPT_G_PD_WatchdogMajor,
        CPT_G_PD_WatchdogMinor,
        CPT_G_PD_AutoAnswered, // must be last (RESET_PD_COUNTER)

        // Periodic logging counter
        CPT_G_PL_OutOfCallMsgs,
        CPT_G_PL_DeadCallMsgs,
        CPT_G_PL_FatalErrors,
        CPT_G_PL_Warnings,
        CPT_G_PL_WatchdogMajor,
        CPT_G_PL_WatchdogMinor,
        CPT_G_PL_AutoAnswered, // must be last (RESET_PL_COUNTER)

        E_NB_G_COUNTER,

    };

    /*
    ** exported methods
    */

    /**
     * Constructor.
     */
    CStat ();

    /**
     * Destructor.
     */
    ~CStat ();


    /**
     * Delete the single instance of the class.
     *
     * Only one instance of CStat exists in the component. This
     * instance is deleted when the close method is called.
     */
    void close ();

    /**
     * ComputeStat Methods are used to modify counter value
     * It's the main interface to update counter
     *
     * @return 0 if the action is known
     *        -1 else
     */
    int computeStat (E_Action P_action);
    int computeStat (E_Action P_action, unsigned long P_value);
    int computeStat (E_Action P_action, unsigned long P_value, int which);

    /* This works for global counters and does not require an instance. */
    static int globalStat (E_Action P_action);

    /**
     * ComputeRtt Methods are used to calculate the response time
     */
    void computeRtt ( unsigned long long P_start_time, unsigned long long P_stop_time, int which);

    /**
     * GetStat Method is used to retrieve a counter value
     *
     * @return the counter value
     **/
    unsigned long long GetStat (E_CounterName P_counter);

    /* Get the current start time. */
    void getStartTime(struct timeval *t);

    /**
     * formatTime.
     *
     * This method converts a struct timeval parameter into a printable string
     * in the format given in parameter.
     *
     * @param P_tv.
     * @return a pointer on a static string containing formated time
     */
    static char* formatTime (struct timeval* P_tv, bool with_epoch = false);

    /**
     * setRepartitionCallLength
     * - set the unsigned int table passed in parameter as the repartition table
     *   for call length. This is done by calling the initRepartition methode on
     *   the M_CallLengthRepartition variable.
     * - set the char* list of int (must be separeted with coma as the
     *   repartition table for call length
     *   This is done by calling the createIntegerTable to transform the char*
     *   list into unsigned int list. Then the initRepartition methode is
     *   call with the created unsigned int list and the M_CallLengthRepartition
     *   variable
     *
     * setRepartitionResponseTime
     *   Same than setRepartitionCallLength with the variable
     *  M_ResponseTimeRepartition variableinstead of M_CallLengthRepartition
     *  variable
     */
    void setRepartitionCallLength   (unsigned int* repartition, int nombre);
    void setRepartitionCallLength   (char * liste);
    void setRepartitionResponseTime (unsigned int* repartition, int nombre);
    void setRepartitionResponseTime (char * liste);

    /* define the file name to use to dump statistic in file */
    void setFileName(const char* name);
    void setFileName(const char* name, const char* extension);
    void initRtt(const char* name, const char* extension, unsigned long P_value);

    /**
     * Display data periodically updated on screen.
     */
    void displayData (FILE *f);
    void displayStat(FILE *f);
    void displayRepartition(FILE *f);
    void displayRtdRepartition (FILE *f, int which);

    /**
     * Dump data periodically in the file M_FileName
     */
    void dumpData ();

    void dumpDataRtt ();

    /**
     * initialize the class variable member
     */
    int init();

    /**
     * computeDiffTimeInMs.
     *
     * This method calculates elaped time in ms
     *
     * @param tf = final date
     * @param ti = initial date
     *
     * @return number of ms between the 2 dates
     */
    static long computeDiffTimeInMs (struct timeval* tf, struct timeval* ti);

    /**
     * msToHHMMSS.
     *
     * This converts an unsigned long containing a number of ms
     * into a string expressing the same value in format HH:MM:SS.
     *
     * @param P_ms.
     *
     * @return a pointer on a static string containing formated time
     */
    static char* msToHHMMSS (unsigned long P_ms);

    /**
     * msToHHMMSSmm.
     *
     * This converts an unsigned long containing a number of ms
     * into a string expressing the same value in format HH:MM:SS:mmm.
     *
     * @param P_ms.
     *
     * @return a pointer on a static string containing formated time
     */
    static char* msToHHMMSSus (unsigned long P_ms);

    /* Get a counter ID by name. */
    int findCounter(const char *counter, bool alloc);
    int findRtd(const char *name, bool start);
    void validateRtds();
    int nRtds();

private:
    unsigned long long        M_counters[E_NB_COUNTER];
    static unsigned long long M_G_counters[E_NB_G_COUNTER - E_NB_COUNTER];

#define GENERIC_C 0
#define GENERIC_PD 1
#define GENERIC_PL 2
#define GENERIC_TYPES 3
    unsigned long long           *M_genericCounters;

    str_int_map                   M_genericMap;
    int_str_map                   M_revGenericMap;
    int_str_map                   M_genericDisplay;

    str_int_map                   rtd_started;
    str_int_map                   rtd_stopped;

#define RTD_COUNT 0
#define RTD_SUM 1
#define RTD_SUMSQ 2
#define RTD_TYPES 3
    unsigned long long           *M_rtdInfo;
    str_int_map                   M_rtdMap;
    int_str_map                   M_revRtdMap;

    T_dynamicalRepartition** M_ResponseTimeRepartition;
    T_dynamicalRepartition*  M_CallLengthRepartition;
    int                      M_SizeOfResponseTimeRepartition;
    int                      M_SizeOfCallLengthRepartition;
    struct timeval           M_startTime;
    struct timeval           M_pdStartTime;
    struct timeval           M_plStartTime;

    bool                     M_headerAlreadyDisplayed;
    char*                    M_fileName;
    ofstream*                M_outputStream;

    bool                     M_headerAlreadyDisplayedRtt ;
    char*                    M_fileNameRtt               ;
    ofstream*                M_outputStreamRtt           ;
    double                   M_time_ref                  ;

    T_pValue_rtt             M_dumpRespTime              ;
    unsigned int             M_counterDumpRespTime       ;
    unsigned long            M_report_freq_dumpRtt       ;

    /**
     * initRepartition
     * This methode is used to create the repartition table with a table of
     * unsigned int the reparition is created like following, with Vi the given
     * value in the table
     * 0    <= x <  V1
     * V1   <= x <  V2
     *  ...
     * Vn-1 <= x <  Vn
     *         x >= Vn
     * So the repartition table have the size n+1 if the given table has a size
     * of n */
    void  initRepartition(unsigned int* repartition, int nombre,
                          T_dynamicalRepartition ** tabRepartition, int* nbTab);

    /**
     * createIntegerTable
     * this method try to create a table of unsigned int with the list of char*
     * passed in parameters
     * if it succed, it's return true (1)
     * else it's return false (0)
     */
    int  createIntegerTable(char * P_listeStr,
                            unsigned int ** listeInteger,
                            int * sizeOfList);

    /**
     * isWellFormed
     * this method check if the char* passed in parameter in really a list of
     * integer separated with comma.
     * if yes, it's return true (1)
     * else, it's return false (0)
     */
    int  isWellFormed(char * P_listeStr, int * nombre);

    /**
     * updateRepartition
     * The method looks for the place to set the value passed in parameter
     * Once found, the associated counter is incremented
     */
    void  updateRepartition( T_dynamicalRepartition* tabRepart,
                             int sizeOfTab,
                             unsigned long value);

    /**
     * resetRepartition
     * Zeros out all repartition counters.
     */
    void  resetRepartition(T_dynamicalRepartition* P_tabReport,
                           int P_sizeOfTab);
    /**
     * displayRepartition
     * Display the repartition passed in parameter at the screen
     */
    void  displayRepartition(FILE *f,
                             T_dynamicalRepartition * tabRepartition,
                             int sizeOfTab);

    /**
     * sRepartitionHeader
     * return a string with the range description of the given repartition
     */
    char* sRepartitionHeader(T_dynamicalRepartition * tabRepartition,
                             int sizeOfTab,
                             const char* P_repartitionName);

    /**
     * sRepartitionInfo
     * return a string with the number of value in the differente range of the
     * given repartition
     */
    char* sRepartitionInfo(T_dynamicalRepartition * tabRepartition,
                           int sizeOfTab);

    /**
     * UpdateAverageCounter
     * This methode compute the real moyenne with the passed value on the given
     * counter
     */
    void updateAverageCounter(E_CounterName P_SumCounter,
                              E_CounterName P_NbOfCallUsed,
                              E_CounterName P_Squares,
                              unsigned long P_value);

    /**
     * computeStdev
     * This method computes the standard deviation using our recorded mean
     * and recorded mean square.
     */
    double computeStdev(E_CounterName P_SumCounter,
                        E_CounterName P_NbOfCallUsed,
                        E_CounterName P_Squares);

    /**
     * computeMean
     * This method computes the recorded sum and count.
     */
    double computeMean(E_CounterName P_SumCounter,
                       E_CounterName P_NbOfCallUsed);

    double computeRtdMean(int which, int type);
    double computeRtdStdev(int which, int type);

    /**
     * Effective C++
     *
     * To prevent public copy ctor usage: no implementation
     */
    CStat (const CStat&);

    /**
     * Effective C++
     *
     * To prevent public operator= usage: no implementation
     */
    CStat& operator=(const CStat&);
};

/**
 * This abstract class provides the ability to sample from a distribution.
 */
class CSample
{
public:
    virtual double sample() = 0;
    virtual int textDescr(char *s, int len) = 0;
    virtual int timeDescr(char *s, int len) = 0;
    virtual double cdfInv(double percentile) = 0;
    virtual ~CSample();
private:
};

/* Always return a fixed value for the sample. */
class CFixed : public CSample
{
public:
    CFixed(double value);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
private:
    double value;
};

/* Return the default scenario duration. */
class CDefaultPause : public CSample
{
public:
    CDefaultPause();
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
private:
};

/* Uniform distribution. */
class CUniform : public CSample
{
public:
    CUniform(double min, double max);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
private:
    double min, max;
};

#ifdef HAVE_GSL
/* Normal distribution. */
class CNormal : public CSample
{
public:
    CNormal(double mean, double stdev);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
protected:
    double mean, stdev;
    gsl_rng *rng;
};

/* Lognormal distribution. */
class CLogNormal : public CNormal
{
public:
    CLogNormal(double mean, double stdev) : CNormal(mean, stdev) {};
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
};

/* Exponential distribution. */
class CExponential : public CSample
{
public:
    CExponential(double mean);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
private:
    double mean;
    gsl_rng *rng;
};

/* Weibull distribution. */
class CWeibull : public CSample
{
public:
    CWeibull(double lambda, double k);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
private:
    double lambda, k;
    gsl_rng *rng;
};

/* Pareto distribution. */
class CPareto : public CSample
{
public:
    CPareto(double k, double xsubm);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
protected:
    double k, xsubm;
    gsl_rng *rng;
};

/* Generalized Pareto distribution. */
class CGPareto : public CSample
{
public:
    CGPareto(double shape, double scale, double location);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
protected:
    double shape, scale, location;
    gsl_rng *rng;
};


/* Gamma distribution. */
class CGamma : public CSample
{
public:
    CGamma(double k, double theta);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
protected:
    double k, theta;
    gsl_rng *rng;
};

/* Negative Binomial distribution. */
class CNegBin : public CSample
{
public:
    CNegBin(double p, double n);
    double sample();
    int textDescr(char *s, int len);
    int timeDescr(char *s, int len);
    double cdfInv(double percentile);
protected:
    double p, n;
    gsl_rng *rng;
};
#endif

#endif // __STAT_H__
