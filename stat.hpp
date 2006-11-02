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
 *           
 */

#ifndef __STAT_H__
#define __STAT_H__


#define TIME_LENGTH 32
#define DEFAULT_FILE_NAME (char*)"dumpFile"
#define DEFAULT_EXTENSION (char*)".csv"

#define MAX_REPARTITION_HEADER_LENGTH 1024
#define MAX_REPARTITION_INFO_LENGTH   1024
#define MAX_CHAR_BUFFER_SIZE          1024

#include <ctime> 
#include <sys/time.h> 
#include <time.h> 
#include <iostream>
#include <fstream>
#include <stdio.h>

/* For MAX_RTD_INFO_LENGTH. */
#include "scenario.hpp"

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

class CStat {
public:

  /* 
   * This struct is used for repartition table
   * border max is the max value allow for this range
   * nbInThisBorder is the counter of value in this range
   */
  typedef struct _T_dynamicalRepartition
  {
    unsigned int  borderMax;
    unsigned long nbInThisBorder; 
  } T_dynamicalRepartition; 

  typedef struct _T_value_rtt 
  {
    double  date ;
    double  rtt  ;
  } T_value_rtt, *T_pValue_rtt ; 

  /**
   * Actions on counters
   */
  enum E_Action
  {
    E_CREATE_OUTGOING_CALL,
    E_CREATE_INCOMING_CALL,
    E_CALL_FAILED, 
    E_CALL_SUCCESSFULLY_ENDED,
    E_RESET_PD_COUNTERS,
    E_RESET_PL_COUNTERS,
    E_ADD_CALL_DURATION,
    E_ADD_RESPONSE_TIME_DURATION,
    E_FAILED_CANNOT_SEND_MSG,
    E_FAILED_MAX_UDP_RETRANS,
    E_FAILED_UNEXPECTED_MSG,
    E_FAILED_CALL_REJECTED,
    E_FAILED_CMD_NOT_SENT,
    E_FAILED_REGEXP_DOESNT_MATCH,
    E_FAILED_REGEXP_HDR_NOT_FOUND,
    E_FAILED_OUTBOUND_CONGESTION,
    E_FAILED_TIMEOUT_ON_RECV,
    E_OUT_OF_CALL_MSGS,
    E_AUTO_ANSWERED
  };
  /**
   * Counters management
   */
  enum E_CounterName
  {
  // Cumulative counters
  CPT_C_IncomingCallCreated,
  CPT_C_OutgoingCallCreated,
  CPT_C_SuccessfulCall,
  CPT_C_FailedCall,
  CPT_C_CurrentCall,
  CPT_C_NbOfCallUsedForAverageCallLength,
  CPT_C_AverageCallLength,
  CPT_C_NbOfCallUsedForAverageResponseTime,
  CPT_C_NbOfCallUsedForAverageResponseTime_2,
  CPT_C_NbOfCallUsedForAverageResponseTime_3,
  CPT_C_NbOfCallUsedForAverageResponseTime_4,
  CPT_C_NbOfCallUsedForAverageResponseTime_5, // This must match or exceed MAX_RTD_INFO
  CPT_C_AverageResponseTime,
  CPT_C_AverageResponseTime_2,
  CPT_C_AverageResponseTime_3,
  CPT_C_AverageResponseTime_4,
  CPT_C_AverageResponseTime_5, // This must match or exceed MAX_RTD_INFO
  CPT_C_FailedCallCannotSendMessage,
  CPT_C_FailedCallMaxUdpRetrans,
  CPT_C_FailedCallUnexpectedMessage,
  CPT_C_FailedCallCallRejected,
  CPT_C_FailedCallCmdNotSent,
  CPT_C_FailedCallRegexpDoesntMatch,
  CPT_C_FailedCallRegexpHdrNotFound,
  CPT_C_FailedOutboundCongestion,
  CPT_C_FailedTimeoutOnRecv,
  CPT_C_OutOfCallMsgs,
  CPT_C_AutoAnswered,

  // Periodic Display counter
  CPT_PD_IncomingCallCreated, // must be first (RESET_PD_COUNTER macro)
  CPT_PD_OutgoingCallCreated,
  CPT_PD_SuccessfulCall,
  CPT_PD_FailedCall,
  CPT_PD_NbOfCallUsedForAverageCallLength,
  CPT_PD_AverageCallLength,
  CPT_PD_NbOfCallUsedForAverageResponseTime,
  CPT_PD_NbOfCallUsedForAverageResponseTime_2, // This must match or exceed MAX_RTD_INFO
  CPT_PD_NbOfCallUsedForAverageResponseTime_3, // This must match or exceed MAX_RTD_INFO
  CPT_PD_NbOfCallUsedForAverageResponseTime_4, // This must match or exceed MAX_RTD_INFO
  CPT_PD_NbOfCallUsedForAverageResponseTime_5, // This must match or exceed MAX_RTD_INFO
  CPT_PD_AverageResponseTime,
  CPT_PD_AverageResponseTime_2,
  CPT_PD_AverageResponseTime_3,
  CPT_PD_AverageResponseTime_4,
  CPT_PD_AverageResponseTime_5,
  CPT_PD_FailedCallCannotSendMessage,
  CPT_PD_FailedCallMaxUdpRetrans,
  CPT_PD_FailedCallUnexpectedMessage,
  CPT_PD_FailedCallCallRejected,
  CPT_PD_FailedCallCmdNotSent,
  CPT_PD_FailedCallRegexpDoesntMatch,
  CPT_PD_FailedCallRegexpHdrNotFound,
  CPT_PD_FailedOutboundCongestion,
  CPT_PD_FailedTimeoutOnRecv,
  CPT_PD_OutOfCallMsgs,
  CPT_PD_AutoAnswered, // must be last (RESET_PD_COUNTER)

  // Periodic logging counter
  CPT_PL_IncomingCallCreated, // must be first (RESET_PL_COUNTER macro)
  CPT_PL_OutgoingCallCreated,
  CPT_PL_SuccessfulCall,
  CPT_PL_FailedCall,
  CPT_PL_NbOfCallUsedForAverageCallLength,
  CPT_PL_AverageCallLength,
  CPT_PL_NbOfCallUsedForAverageResponseTime,
  CPT_PL_NbOfCallUsedForAverageResponseTime_2,
  CPT_PL_NbOfCallUsedForAverageResponseTime_3,
  CPT_PL_NbOfCallUsedForAverageResponseTime_4,
  CPT_PL_NbOfCallUsedForAverageResponseTime_5,
  CPT_PL_AverageResponseTime,
  CPT_PL_AverageResponseTime_2,
  CPT_PL_AverageResponseTime_3,
  CPT_PL_AverageResponseTime_4,
  CPT_PL_AverageResponseTime_5,
  CPT_PL_FailedCallCannotSendMessage,
  CPT_PL_FailedCallMaxUdpRetrans,
  CPT_PL_FailedCallUnexpectedMessage,
  CPT_PL_FailedCallCallRejected,
  CPT_PL_FailedCallCmdNotSent,
  CPT_PL_FailedCallRegexpDoesntMatch,
  CPT_PL_FailedCallRegexpHdrNotFound,
  CPT_PL_FailedOutboundCongestion,
  CPT_PL_FailedTimeoutOnRecv,
  CPT_PL_OutOfCallMsgs,
  CPT_PL_AutoAnswered, // must be last (RESET_PL_COUNTER)

  E_NB_COUNTER
  };

  /*
  ** exported methods
  */
  /**
   * Get the single instance of the class.
   *
   * Only one instance of CStat exists in the component. This
   * instance is automatically created the first time the instance()
   * method is called.
   *
   * @return the single instance of the CStat class.
   */
  static CStat* instance (); 

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

  /**
   * ComputeRtt Methods are used to calculate the response time
   *
   * @return 0 if the action is known
   *        -1 else
   */
  int computeRtt ( unsigned long P_start_time, double P_stop_time);

  /**
   * Get_current_counter_call Methods is used to get the number of current call
   *
   * @return 0 if the action is known
   *        -1 else
   */
  int get_current_counter_call ();

  /**
   * GetStat Method is used to retrieve a counter value
   *
   * @return the counter value
   **/
  unsigned long  GetStat (E_CounterName P_counter);
  
  /**
   * formatTime.
   *
   * This method converts a struct timeval parameter into a printable string
   * in the format given in parameter.
   *
   * @param P_tv.
   * @return a pointer on a static string containing formated time
   */
  char* formatTime (struct timeval* P_tv);

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
  void setFileName                (char * name);
  void setFileName                (char * name, char * extension);
  void initRtt             (char * name, char * extension, unsigned long P_value);

  /**
   * Display data periodically updated on screen.
   */
  void displayData (FILE *f);
  void displayStat(FILE *f);
  void displayRepartition(FILE *f);
  void displaySecondaryRepartition (FILE *f, int which);


  /**
   * Dump data periodically in the file M_FileName
   */
  void dumpData ();

  void dumpDataRtt ();

  /**
   * initialize the class variable member
   */
  int init();

private:
   
  /** 
   * Constructor.
   *
   * Made private because this is a singleton class.
   */
  CStat ();

  /** 
   * Destructor.
   *
   * Made private because this is a singleton class.
   */
  ~CStat ();

  static CStat*            M_instance;
  unsigned long            M_counters[E_NB_COUNTER];
  T_dynamicalRepartition*  M_ResponseTimeRepartition[MAX_RTD_INFO_LENGTH];
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
  int                      M_counterDumpRespTime       ;
  unsigned long            M_report_freq_dumpRtt       ;

  unsigned long long       M_C_sumCallLength;
  unsigned long long       M_C_sumResponseTime[MAX_RTD_INFO_LENGTH];
  unsigned long long       M_PD_sumCallLength;
  unsigned long long       M_PD_sumResponseTime[MAX_RTD_INFO_LENGTH];
  unsigned long long       M_PL_sumCallLength;
  unsigned long long       M_PL_sumResponseTime[MAX_RTD_INFO_LENGTH];

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
   * The methode look for the place to set the value passed in parameter
   * Once found, the associeted counter is incremented
   */
  void  updateRepartition( T_dynamicalRepartition* tabRepart, 
                           int sizeOfTab, 
                           unsigned long value);

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
                           char* P_repartitionName);

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
  void updateAverageCounter(E_CounterName P_AverageCounter, 
                            E_CounterName P_NbOfCallUsed,
                            unsigned long long* P_sum, 
                            unsigned long P_value);

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
  long computeDiffTimeInMs (struct timeval* tf, struct timeval* ti);
  
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
  char* msToHHMMSS (unsigned long P_ms);
  
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
  char* msToHHMMSSmmm (unsigned long P_ms);
  
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

#endif // __STAT_H__
