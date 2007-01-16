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
 *            Wolfgang Beck
 *
 */

#include <iostream>
#include <fstream>
#include <iomanip>

#include "sipp.hpp"
#include "screen.hpp"

/*
** Local definitions (macros)
*/

/*
** Warning! All DISPLAY_ macros must be called where f FILE is
**          defined. This is to allow printing to stdout or a file. 
*/
#define DISPLAY_LINE()\
  fprintf(f," ------------------------------------------------------------------------------ \r\n")
#define DISPLAY_DLINE()\
  fprintf(f,"================================================================================\r\n")
#define DISPLAY_CROSS_LINE()\
  fprintf(f,"-------------------------+---------------------------+--------------------------\r\n")

#define DISPLAY_HEADER()\
  fprintf(f,"  Counter Name           | Periodic value            | Cumulative value\r\n")
#define DISPLAY_TXT_COL(T1, V1, V2)\
  fprintf(f,"  %-22.22s | %-25.25s |", T1, V1); fprintf(f," %-24.24s \r\n", V2)
#define DISPLAY_VAL_RATEF_COL(T1, V1, V2)\
  fprintf(f,"  %-22.22s | %8.3f cps              | %8.3f cps             \r\n", T1, V1, V2)
#define DISPLAY_2VAL(T1, V1, V2)\
  fprintf(f,"  %-22.22s | %8d                  | %8d                 \r\n", T1, V1, V2)
#define DISPLAY_CUMUL(T1, V1)\
  fprintf(f,"  %-22.22s |                           | %8d                 \r\n", T1, V1)
#define DISPLAY_PERIO(T1, V1)\
  fprintf(f,"  %-22.22s | %8d                  |                          \r\n", T1, V1)
#define DISPLAY_VALF(T1, V1)\
  fprintf(f,"  %-22.22s | %8.3f ms                                          \r\n", T1, V1)
#define DISPLAY_VAL_RATEF(T1, V1)\
  fprintf(f,"  %-22.22s | %8.3f cps                                         \r\n", T1, V1)
#define DISPLAY_VAL_RATE(T1, V1)\
  fprintf(f,"  %-22.22s | %8d cps                                         \r\n", T1, V1)
#define DISPLAY_VAL(T1, V1)\
  fprintf(f,"  %-22.22s : %8d                                             \r\n", T1, V1)
#define DISPLAY_2VALF(T1, V1, T2, V2)\
  fprintf(f,"  %-22.22s : %8.2f  | %-7.7s : %8.2f                       \r\n", T1, V1, T2, V2)
#define DISPLAY_3VAL(T1, V1, T2, V2, T3, V3)\
  fprintf(f,"  %-22.22s : %8d  | %-7.7s : %8d  | %-12.12s : %5d \r\n", T1, V1, T2, V2, T3, V3)
#define DISPLAY_3VALF(T1, V1, T2, V2, T3, V3)\
  fprintf(f,"  %-22.22s : %8.3f  | %-7.7s : %8.3f  | %-12.12s : %5.1f \r\n", T1, V1, T2, V2, T3, V3)
#define DISPLAY_TXT(T1, V1)\
  fprintf(f,"  %-22.22s | %-52.52s \r\n", T1, V1)
#define DISPLAY_INFO(T1)\
  fprintf(f,"  %-77.77s \r\n", T1)
#define DISPLAY_REPART(T1, T2, V1)\
  fprintf(f,"    %8d ms <= n <  %8d ms : %10d  %-29.29s \r\n", T1, T2, V1, "")
#define DISPLAY_LAST_REPART(T1, V1)\
  fprintf(f,"    %14.14s n >= %8d ms : %10d  %-29.29s \r\n", "", T1, V1, "")

#define RESET_COUNTERS(PT)\
  memset (PT, 0, CStat::E_NB_COUNTER * sizeof(unsigned long))

#define RESET_PD_COUNTERS(PT)                          \
{                                                      \
  int i;                                               \
  for (i=CStat::CPT_PD_IncomingCallCreated;            \
       i<=CStat::CPT_PD_AutoAnswered;                  \
       i++)                                            \
    PT[i] = (unsigned long) 0;                         \
}

#define RESET_PL_COUNTERS(PT)                          \
{                                                      \
  int i;                                               \
  for (i=CStat::CPT_PL_IncomingCallCreated;            \
       i<=CStat::CPT_PL_AutoAnswered;                  \
       i++)                                            \
    PT[i] = (unsigned long) 0;                         \
}

/*
  __________________________________________________________________________

  C L A S S    CS t a t
  __________________________________________________________________________
*/

CStat* CStat::instance()
{
  if ( M_instance == NULL ) M_instance = new CStat();
  return M_instance;
}


void CStat::close ()
{
  int i;

  for (i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    if (M_ResponseTimeRepartition[i] != NULL) {
      delete [] M_ResponseTimeRepartition[i];
    }
  }

  if (M_CallLengthRepartition != NULL)
    delete [] M_CallLengthRepartition;

  if(M_outputStream != NULL)
    {
      M_outputStream->close();
      delete M_outputStream;
    }

  if(M_fileName != NULL)
    delete [] M_fileName;

  if(M_outputStreamRtt != NULL)
    {
      M_outputStreamRtt->close();
      delete M_outputStreamRtt;
    }
  if(M_fileNameRtt != NULL)
    delete [] M_fileNameRtt;


   if(M_dumpRespTime != NULL)
     delete [] M_dumpRespTime ;


  M_SizeOfResponseTimeRepartition = 0;
  M_SizeOfCallLengthRepartition   = 0;
  M_CallLengthRepartition         = NULL;
  M_fileName                      = NULL;
  M_outputStream                  = NULL;

  M_outputStreamRtt               = NULL;
  M_fileNameRtt                   = NULL;
  M_dumpRespTime                  = NULL;

  for (i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    M_ResponseTimeRepartition[i]  = NULL;
  }

  // On last position
  if (M_instance != NULL)
    delete M_instance;
  M_instance                      = NULL;
}


int CStat::init () 
{
  // reset of all counter
  RESET_COUNTERS(M_counters);
  GET_TIME (&M_startTime);
  memcpy   (&M_pdStartTime, &M_startTime, sizeof (struct timeval));
  memcpy   (&M_plStartTime, &M_startTime, sizeof (struct timeval));
  M_outputStream = NULL;
  M_headerAlreadyDisplayed = false;

  M_outputStreamRtt = NULL;
  M_headerAlreadyDisplayedRtt = false;

  return(1);
}


int CStat::isWellFormed(char * P_listeStr, 
                        int * nombre)
{
  char * ptr = P_listeStr;
  int sizeOf;
  bool isANumber;

  (*nombre) = 0; 
  sizeOf = strlen(P_listeStr);
  // getting the number 
  if(sizeOf > 0)
    {
      // is the string well formed ? [0-9] [,]
      isANumber = false;
      for(int i=0; i<=sizeOf; i++)
        {
          switch(ptr[i])
            {
            case ',':
              if(isANumber == false)
                {   
                  return(0);
                }
              else
                {
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
              if(isANumber == false)
                {   
                  return(0);
                }
              else
                {
                  (*nombre)++;
                } 
              break;
            default:
              return(0);
            }
        } // enf for
    }
  return(1);
}


int CStat::createIntegerTable(char * P_listeStr, 
                              unsigned int ** listeInteger, 
                              int * sizeOfList)
{
  int nb=0;
  char * ptr = P_listeStr;
  char * ptr_prev = P_listeStr;
  unsigned int current_int;
  int sizeOf;
  bool isANumber;
 
  if(isWellFormed(P_listeStr, sizeOfList) == 1)
    {
      (*listeInteger) = new unsigned int[(*sizeOfList)];
      while((*ptr) != ('\0'))
        {
          if((*ptr) == ',')
            {
              sscanf(ptr_prev, "%u", &current_int);
              if (nb<(*sizeOfList))
                (*listeInteger)[nb] = current_int;
              nb++;
              ptr_prev = ptr+1;
            }
          ptr++;
        }
      // on lit le dernier
      sscanf(ptr_prev, "%u", &current_int); 
      if (nb<(*sizeOfList))
        (*listeInteger)[nb] = current_int;
      nb++;
      return(1);
    }
  return(0);
}


void CStat::setFileName(char * P_name, char * P_extension)
{
  int sizeOf, sizeOfExtension; 

  if(P_name != NULL) 
    { 
      // +6 for PID
      sizeOf = strlen(P_name) + 6;
      if(sizeOf > 0)
        {
          if(P_extension != NULL)
            { 
              sizeOfExtension = strlen(P_extension); 
              if(sizeOfExtension > 0)
                {
                  if(M_fileName != NULL)
                    delete [] M_fileName;
                  sizeOf += sizeOfExtension;
                  M_fileName = new char[MAX_PATH];
                  sprintf(M_fileName, "%s_%d_", P_name, getpid()); 
                  strcat(M_fileName, P_extension);
                }
              else
                {
                  if(M_fileName != NULL)
                    delete [] M_fileName;
                  sizeOf += strlen(DEFAULT_EXTENSION);
                  M_fileName = new char[MAX_PATH];
                  sprintf(M_fileName, "%s_%d_", P_name, getpid()); 
                  strcat(M_fileName, DEFAULT_EXTENSION);
                }
            }
          else
            {
              if(M_fileName != NULL)
                delete [] M_fileName;
              sizeOf += strlen(DEFAULT_EXTENSION);
              M_fileName = new char[MAX_PATH];
              sprintf(M_fileName, "%s_%d_", P_name, getpid()); 
              strcat(M_fileName, DEFAULT_EXTENSION);
            }
        }
      else
        {
          cerr << "new file name length is null - "
                    << "keeping the default filename : "
                    << DEFAULT_FILE_NAME << endl;
        }
    }
  else
    {
      cerr << "new file name is NULL ! - keeping the default filename : " 
                << DEFAULT_FILE_NAME << endl;
    }
}


void CStat::setFileName(char * P_name)
{
  int sizeOf, sizeOfExtension; 

  if(P_name != NULL) 
    { 
      sizeOf = strlen(P_name);
      if(sizeOf > 0)
        {
          if(M_fileName != NULL)
            delete [] M_fileName;
          M_fileName = new char[sizeOf+1];
          strcpy(M_fileName, P_name);
        }
      else
        {
          cerr << "new file name length is null - "
            "keeping the default filename : "
                    << DEFAULT_FILE_NAME << endl;
        }
    }
  else
    {
      cerr << "new file name is NULL ! - keeping the default filename : " 
                << DEFAULT_FILE_NAME << endl;
    }
}


void CStat::initRtt(char * P_name, char * P_extension,
                    unsigned long P_report_freq_dumpRtt) {
  int sizeOf, sizeOfExtension, L_i; 

  if(P_name != NULL) { 
    sizeOf = strlen(P_name) ;
    if(sizeOf > 0) {
      //  4 for '_rtt' and 6 for pid 
      sizeOf += 10 ;
      sizeOfExtension = strlen(P_extension); 
      if(M_fileNameRtt != NULL)
      delete [] M_fileNameRtt;
      sizeOf += sizeOfExtension;
      M_fileNameRtt = new char[sizeOf+1];
      sprintf (M_fileNameRtt, "%s_%d_rtt%s", P_name, getpid(),P_extension);
    } else {
      cerr << "new file name length is null - "
          << "keeping the default filename : "
          << DEFAULT_FILE_NAME << endl;
    }
  } else {
    cerr << "new file name is NULL ! - keeping the default filename : " 
        << DEFAULT_FILE_NAME << endl;
  }

  // calculate M_time_ref 
  M_time_ref = (double)M_startTime.tv_sec*1000.0 + (double)M_startTime.tv_usec/1000.0 ;  
  
  // initiate the table dump response time
  M_report_freq_dumpRtt = P_report_freq_dumpRtt ;
  
  M_dumpRespTime = new T_value_rtt [P_report_freq_dumpRtt] ;
  
  if ( M_dumpRespTime == NULL ) {
    cerr << "Memory allocation failure" << endl;
    exit(EXIT_FATAL_ERROR);
  }
  
  for (L_i = 0 ; L_i < P_report_freq_dumpRtt; L_i ++) {
    M_dumpRespTime[L_i].date = 0.0;
    M_dumpRespTime[L_i].rtd_no = 0;
    M_dumpRespTime[L_i].rtt = 0.0;
  }
}

void CStat::setRepartitionCallLength(char * P_listeStr)
{
  unsigned int * listeInteger;
  int sizeOfListe;

  if(createIntegerTable(P_listeStr, &listeInteger, &sizeOfListe) == 1) {
    initRepartition(listeInteger, 
                    sizeOfListe, 
                    &M_CallLengthRepartition, 
                    &M_SizeOfCallLengthRepartition);
  } else {
    M_CallLengthRepartition         = NULL;
    M_SizeOfCallLengthRepartition   = 0;
  }
  delete [] listeInteger;
  listeInteger = NULL;
}

void CStat::setRepartitionResponseTime (char * P_listeStr)
{
  unsigned int * listeInteger;
  int sizeOfListe;
  int i;

  for (i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    if(createIntegerTable(P_listeStr, &listeInteger, &sizeOfListe) == 1) {
      initRepartition(listeInteger,
	  sizeOfListe,
	  &M_ResponseTimeRepartition[i],
	  &M_SizeOfResponseTimeRepartition);
    } else {
      M_CallLengthRepartition         = NULL;
      M_SizeOfCallLengthRepartition   = 0;
    }
  }
  delete [] listeInteger;
  listeInteger = NULL;
}


void CStat::setRepartitionCallLength(unsigned int* repartition, 
                                     int nombre)
{
  initRepartition(repartition, 
                  nombre, 
                  &M_CallLengthRepartition, 
                  &M_SizeOfCallLengthRepartition);
} 

void CStat::setRepartitionResponseTime(unsigned int* repartition, 
                                       int nombre)
{
  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    initRepartition(repartition,
                    nombre,
                    &M_ResponseTimeRepartition[i],
                    &M_SizeOfResponseTimeRepartition);
  }
}


void CStat::initRepartition(unsigned int* repartition, 
                            int nombre, 
                            T_dynamicalRepartition ** tabRepartition, 
                            int* tabNb)
{
  bool sortDone;
  int i;
  unsigned int swap;

  if((nombre <= 0) || (repartition == NULL) )
    {
      (*tabNb)          = 0;
      (*tabRepartition) = NULL;
      return;
    }

  (*tabNb)          = nombre + 1;
  (*tabRepartition) = new T_dynamicalRepartition[(*tabNb)];
 
  // copying the repartition table in the local table 
  for(i=0; i<nombre; i++)
    { 
      (*tabRepartition)[i].borderMax      = repartition[i];
      (*tabRepartition)[i].nbInThisBorder = 0;
    } 
  
  // sorting the repartition table
  sortDone = false;
  while(!sortDone)
    { 
      sortDone = true;
      for(i=0; i<(nombre-1); i++)
        { 
          if((*tabRepartition)[i].borderMax > (*tabRepartition)[i+1].borderMax)
            {  
              // swapping this two value and setting sortDone to false
              swap = (*tabRepartition)[i].borderMax;
              (*tabRepartition)[i].borderMax = 
                (*tabRepartition)[i+1].borderMax;
              (*tabRepartition)[i+1].borderMax = swap;
              sortDone = false;
            } 
        } 
    }
  // setting the range for max <= value < infinity
  (*tabRepartition)[nombre].borderMax =
    (*tabRepartition)[nombre-1].borderMax;
  (*tabRepartition)[nombre].nbInThisBorder = 0;
}


int CStat::computeStat (E_Action P_action)
{
  switch (P_action)
    {
    case E_CREATE_OUTGOING_CALL :
      M_counters [CPT_C_OutgoingCallCreated]++;
      M_counters [CPT_PD_OutgoingCallCreated]++;
      M_counters [CPT_PL_OutgoingCallCreated]++;
      M_counters [CPT_C_CurrentCall]++;
      break;

    case E_CREATE_INCOMING_CALL :
      M_counters [CPT_C_IncomingCallCreated]++;
      M_counters [CPT_PD_IncomingCallCreated]++;
      M_counters [CPT_PL_IncomingCallCreated]++;
      M_counters [CPT_C_CurrentCall]++;
      break;

    case E_CALL_FAILED :
      M_counters [CPT_C_FailedCall]++;
      M_counters [CPT_PD_FailedCall]++;
      M_counters [CPT_PL_FailedCall]++;
      M_counters [CPT_C_CurrentCall]--;
      break;

    case E_CALL_SUCCESSFULLY_ENDED :
      M_counters [CPT_C_SuccessfulCall]++;
      M_counters [CPT_PD_SuccessfulCall]++;
      M_counters [CPT_PL_SuccessfulCall]++;
      M_counters [CPT_C_CurrentCall]--;
      break;

    case E_FAILED_CANNOT_SEND_MSG :
      M_counters [CPT_C_FailedCallCannotSendMessage]++;
      M_counters [CPT_PD_FailedCallCannotSendMessage]++;
      M_counters [CPT_PL_FailedCallCannotSendMessage]++;
      break;

    case E_FAILED_MAX_UDP_RETRANS :
      M_counters [CPT_C_FailedCallMaxUdpRetrans]++;
      M_counters [CPT_PD_FailedCallMaxUdpRetrans]++;
      M_counters [CPT_PL_FailedCallMaxUdpRetrans]++;
      break;

    case E_FAILED_UNEXPECTED_MSG :
      M_counters [CPT_C_FailedCallUnexpectedMessage]++;
      M_counters [CPT_PD_FailedCallUnexpectedMessage]++;
      M_counters [CPT_PL_FailedCallUnexpectedMessage]++;
      break;

    case E_FAILED_CALL_REJECTED :
      M_counters [CPT_C_FailedCallCallRejected]++;
      M_counters [CPT_PD_FailedCallCallRejected]++;
      M_counters [CPT_PL_FailedCallCallRejected]++;
      break;

    case E_FAILED_CMD_NOT_SENT :
      M_counters [CPT_C_FailedCallCmdNotSent]++;
      M_counters [CPT_PD_FailedCallCmdNotSent]++;
      M_counters [CPT_PL_FailedCallCmdNotSent]++;
      break;

    case E_FAILED_REGEXP_DOESNT_MATCH :
      M_counters [CPT_C_FailedCallRegexpDoesntMatch]++;
      M_counters [CPT_PD_FailedCallRegexpDoesntMatch]++;
      M_counters [CPT_PL_FailedCallRegexpDoesntMatch]++;
      break;

    case E_FAILED_REGEXP_HDR_NOT_FOUND :
      M_counters [CPT_C_FailedCallRegexpHdrNotFound]++;
      M_counters [CPT_PD_FailedCallRegexpHdrNotFound]++;
      M_counters [CPT_PL_FailedCallRegexpHdrNotFound]++;
      break;

    case E_FAILED_OUTBOUND_CONGESTION :
      M_counters [CPT_C_FailedOutboundCongestion]++;
      M_counters [CPT_PD_FailedOutboundCongestion]++;
      M_counters [CPT_PL_FailedOutboundCongestion]++;
      break;

    case E_FAILED_TIMEOUT_ON_RECV :
      M_counters [CPT_C_FailedTimeoutOnRecv]++;
      M_counters [CPT_PD_FailedTimeoutOnRecv]++;
      M_counters [CPT_PL_FailedTimeoutOnRecv]++;
      break;

    case E_OUT_OF_CALL_MSGS :
      M_counters [CPT_C_OutOfCallMsgs]++;
      M_counters [CPT_PD_OutOfCallMsgs]++;
      M_counters [CPT_PL_OutOfCallMsgs]++;
      break;

    case E_RETRANSMISSION :
      M_counters [CPT_C_Retransmissions]++;
      M_counters [CPT_PD_Retransmissions]++;
      M_counters [CPT_PL_Retransmissions]++;
      break;


    case E_AUTO_ANSWERED :
      // Let's count the automatic answered calls
      M_counters [CPT_C_AutoAnswered]++;
      M_counters [CPT_PD_AutoAnswered]++;
      M_counters [CPT_PL_AutoAnswered]++;
      break;

    case E_RESET_PD_COUNTERS :
      //DEBUG (C_Debug::E_LEVEL_4, "ENTER CASE", "%s", 
      //       "CStat::computeStat : RESET_PD_COUNTERS");
      RESET_PD_COUNTERS (M_counters);
      GET_TIME (&M_pdStartTime);
      break;

    case E_RESET_PL_COUNTERS :
      //DEBUG (C_Debug::E_LEVEL_4, "ENTER CASE", "%s", 
      //       "C_Stat::computeStat : RESET_PL_COUNTERS");
      RESET_PL_COUNTERS (M_counters);
      GET_TIME (&M_plStartTime);
      break;
     
    default :
      ERROR_P1("CStat::ComputeStat() - Unrecognized Action %d\n", P_action);
      return (-1);
    } /* end switch */
  return (0);
}

int CStat::computeRtt (unsigned long P_start_time, double P_stop_time, int which) {
  M_dumpRespTime[M_counterDumpRespTime].date =  (P_stop_time - M_time_ref) ;
  M_dumpRespTime[M_counterDumpRespTime].rtd_no = which;
  M_dumpRespTime[M_counterDumpRespTime].rtt = ( P_stop_time - (P_start_time + M_time_ref));
  M_counterDumpRespTime++ ;

  if (M_counterDumpRespTime > (M_report_freq_dumpRtt - 1)) {
    dumpDataRtt () ;
  }
  return (0);
}

int CStat::get_current_counter_call (){
  return (M_counters[CPT_C_CurrentCall]);

}

unsigned long CStat::GetStat (E_CounterName P_counter)
{
  return M_counters [P_counter];
}

/* Use the short form standard deviation formula given our average square and
 * the average.  */
unsigned long CStat::computeStdev(E_CounterName P_AverageCounter,
			 E_CounterName P_NbOfCallUsed,
			 E_CounterName P_Squares) {
	return (unsigned long)sqrt((double)(M_counters[P_Squares] - (M_counters[P_AverageCounter] * M_counters[P_AverageCounter])));
}

void CStat::updateAverageCounter(E_CounterName P_AverageCounter, 
                                 E_CounterName P_NbOfCallUsed,
                                 E_CounterName P_Squares,
                                 unsigned long long* P_sum, 
                                 unsigned long long* P_sq,
                                 unsigned long P_value)
{
  if (M_counters [P_NbOfCallUsed] <= 0)
    {
      M_counters [P_NbOfCallUsed] ++;
      *(P_sum) = M_counters [P_AverageCounter] = P_value;
      *(P_sq) = M_counters [P_Squares] = (P_value * P_value);
    }
  else
    {
      (*P_sum) = P_value + (*P_sum);
      (*P_sq) = (P_value * P_value)  + (*P_sq);

      M_counters [P_AverageCounter] = (*P_sum) /
        (M_counters [P_NbOfCallUsed] + 1);

      M_counters [P_Squares] = (*P_sq) /
        (M_counters [P_NbOfCallUsed] + 1);

      M_counters [P_NbOfCallUsed] ++;
    }
}

int CStat::computeStat (E_Action P_action,
                        unsigned long P_value) {
  return computeStat(P_action, P_value, 0);
}

int CStat::computeStat (E_Action P_action,
                        unsigned long P_value,
			int which)
{
  switch (P_action)
    {
    case E_ADD_CALL_DURATION :
      // Updating Cumulative Counter
      updateAverageCounter(CPT_C_AverageCallLength, 
                           CPT_C_NbOfCallUsedForAverageCallLength,
			   CPT_C_AverageCallLength_Squares,
                           &M_C_sumCallLength,
			   &M_C_sumCallLength_Square, P_value);
      updateRepartition(M_CallLengthRepartition, 
                        M_SizeOfCallLengthRepartition, P_value);
      // Updating Periodical Diplayed counter
      updateAverageCounter(CPT_PD_AverageCallLength, 
                           CPT_PD_NbOfCallUsedForAverageCallLength,
			   CPT_PD_AverageCallLength_Squares,
                           &M_PD_sumCallLength,
                           &M_PD_sumCallLength_Square, P_value);
      // Updating Periodical Logging counter
      updateAverageCounter(CPT_PL_AverageCallLength, 
                           CPT_PL_NbOfCallUsedForAverageCallLength,
			   CPT_PL_AverageCallLength_Squares,
                           &M_PL_sumCallLength,
			   &M_PL_sumCallLength_Square, P_value);
      break;


    case E_ADD_GENERIC_COUNTER :
      M_counters [CPT_C_Generic + which] += P_value;
      M_counters [CPT_PD_Generic + which] += P_value;
      M_counters [CPT_PL_Generic + which] += P_value;
      break;

    case E_ADD_RESPONSE_TIME_DURATION :
      // Updating Cumulative Counter
      updateAverageCounter((E_CounterName)(CPT_C_AverageResponseTime + which), 
                           (E_CounterName)(CPT_C_NbOfCallUsedForAverageResponseTime + which),
                           (E_CounterName)(CPT_C_AverageResponseTime_Squares + which),
                           &M_C_sumResponseTime[which], &M_C_sumResponseTime_Square[which], P_value);
      updateRepartition(M_ResponseTimeRepartition[which], 
                        M_SizeOfResponseTimeRepartition, P_value);
      // Updating Periodical Diplayed counter
      updateAverageCounter((E_CounterName)(CPT_PD_AverageResponseTime + which), 
                           (E_CounterName)(CPT_PD_NbOfCallUsedForAverageResponseTime + which),
                           (E_CounterName)(CPT_PD_AverageResponseTime_Squares + which),
                           &M_PD_sumResponseTime[which], &M_PD_sumResponseTime_Square[which], P_value);
      // Updating Periodical Logging counter
      updateAverageCounter((E_CounterName)(CPT_PL_AverageResponseTime + which), 
                           (E_CounterName)(CPT_PL_NbOfCallUsedForAverageResponseTime + which),
                           (E_CounterName)(CPT_PL_AverageResponseTime_Squares + which),
                           &M_PL_sumResponseTime[which], &M_PL_sumResponseTime_Square[which], P_value);
      break;

    default :
      ERROR_P1("CStat::ComputeStat() - Unrecognized Action %d\n", P_action);
      return (-1);
    } /* end switch */
  return (0);
}


void CStat::updateRepartition(T_dynamicalRepartition* P_tabReport, 
                              int P_sizeOfTab, 
                              unsigned long P_value)
{
  bool found;
  int i;

  if(P_tabReport != NULL)
    {
      i = P_sizeOfTab-2;
      found = false;
      while((found == false) && (i>=1))
        {
          if( (P_value < P_tabReport[i].borderMax) &&
              (P_tabReport[i-1].borderMax <= P_value) )
            {
              found = true;
              P_tabReport[i].nbInThisBorder ++;
            }
          i--;
        }
    
      if(!found)
        {
          if(P_value < P_tabReport[0].borderMax)
            {
              P_tabReport[0].nbInThisBorder ++;
            }
          else if(P_value >= P_tabReport[P_sizeOfTab-1].borderMax)
            {
              P_tabReport[P_sizeOfTab-1].nbInThisBorder ++;
            }
          else
            {
              // ERROR !!!!
              printf("\n ERROR - Unable to sort this Value in "
                     "the repartition table! %d \n", P_value);
            }
        }
    }
}


CStat::CStat ()
{
  size_t L_size = 0;
  L_size += strlen(DEFAULT_FILE_NAME) ;
  L_size += strlen(DEFAULT_EXTENSION) ;
  L_size += 1 ;
  M_fileName = new char[L_size];
  strcpy(M_fileName, DEFAULT_FILE_NAME);
  strcat(M_fileName, DEFAULT_EXTENSION);
  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    M_ResponseTimeRepartition[i] = NULL;
  }
  M_CallLengthRepartition   = NULL;
  M_SizeOfResponseTimeRepartition = 0;
  M_SizeOfCallLengthRepartition   = 0;
  M_fileNameRtt = NULL;
  M_time_ref = 0.0                   ;
  M_dumpRespTime = NULL              ;
  M_counterDumpRespTime = 0          ; 
  M_dumpRespTime = NULL;
  M_fileNameRtt  = NULL;

  init();
}


CStat::~CStat ()
{



}

char* CStat::sRepartitionHeader(T_dynamicalRepartition * tabRepartition, 
                                int sizeOfTab, 
                                char * P_repartitionName)
{
  static char  repartitionHeader[MAX_REPARTITION_HEADER_LENGTH];
  char buffer[MAX_CHAR_BUFFER_SIZE];

  if(tabRepartition != NULL)
    {
      sprintf(repartitionHeader, "%s%s", P_repartitionName, stat_delimiter);
      for(int i=0; i<(sizeOfTab-1); i++)
        {   
          sprintf(buffer, "<%d%s", tabRepartition[i].borderMax, stat_delimiter);
          strcat(repartitionHeader, buffer);
        }
      sprintf(buffer, ">=%d%s", tabRepartition[sizeOfTab-1].borderMax, stat_delimiter);
      strcat(repartitionHeader, buffer);
    }
  else
    {
      sprintf(repartitionHeader, "");
    }

  return(repartitionHeader);
}

char* CStat::sRepartitionInfo(T_dynamicalRepartition * tabRepartition, 
                              int sizeOfTab)
{
  static char repartitionInfo[MAX_REPARTITION_INFO_LENGTH];
  char buffer[MAX_CHAR_BUFFER_SIZE];

  if(tabRepartition != NULL)
    {
      // if a repartition is present, this field match the repartition name
      sprintf(repartitionInfo, stat_delimiter);
      for(int i=0; i<(sizeOfTab-1); i++)
        {   
          sprintf(buffer, "%d%s", tabRepartition[i].nbInThisBorder, stat_delimiter);
          strcat(repartitionInfo, buffer);
        }
      sprintf(buffer, "%d%s", tabRepartition[sizeOfTab-1].nbInThisBorder, stat_delimiter);
      strcat(repartitionInfo, buffer);
    }
  else
    {
      sprintf(repartitionInfo, "");
    }

  return(repartitionInfo);
}


void CStat::displayRepartition(FILE *f,
                               T_dynamicalRepartition * tabRepartition, 
                               int sizeOfTab)
{
  if(tabRepartition != NULL) {
    for(int i=0; i<(sizeOfTab-1); i++) {   
      if(i==0) {
        DISPLAY_REPART(0, tabRepartition[i].borderMax, 
                        tabRepartition[i].nbInThisBorder);
      } else {
        DISPLAY_REPART(tabRepartition[i-1].borderMax, 
                       tabRepartition[i].borderMax, 
                       tabRepartition[i].nbInThisBorder);
      }
    }
    DISPLAY_LAST_REPART (tabRepartition[sizeOfTab-1].borderMax, 
                         tabRepartition[sizeOfTab-1].nbInThisBorder);
  } else {
    DISPLAY_INFO ("  <No repartion defined>");
  }
}

void CStat::displayData (FILE *f)
{
  char   buf1 [64], buf2 [64], buf3 [64];
  long   localElapsedTime, globalElapsedTime ;
  struct timeval currentTime;
  float  averageCallRate;
  float  realInstantCallRate;
  unsigned long numberOfCall;

  GET_TIME (&currentTime);
  // computing the real call rate
  globalElapsedTime   = computeDiffTimeInMs (&currentTime, &M_startTime);
  localElapsedTime    = computeDiffTimeInMs (&currentTime, &M_pdStartTime);

  // the call rate is for all the call : incoming and outgoing
  numberOfCall        = M_counters[CPT_C_IncomingCallCreated] + 
    M_counters[CPT_C_OutgoingCallCreated];
  averageCallRate     = (globalElapsedTime > 0 ? 
                         1000*(float)numberOfCall/(float)globalElapsedTime 
                         : 0.0);
  numberOfCall        = (M_counters[CPT_PD_IncomingCallCreated] + 
                         M_counters[CPT_PD_OutgoingCallCreated]);
  realInstantCallRate = (localElapsedTime  > 0 ? 
                         1000*(float)numberOfCall / (float)localElapsedTime :
                         0.0);

  // display info
  DISPLAY_DLINE ();
  // build and display header info
  DISPLAY_TXT ("Start Time  ", formatTime(&M_startTime));
  DISPLAY_TXT ("Last Reset Time", formatTime(&M_pdStartTime));
  DISPLAY_TXT ("Current Time", formatTime(&currentTime));

  // printing the header in the middle
  DISPLAY_CROSS_LINE();
  DISPLAY_HEADER();
  DISPLAY_CROSS_LINE();

  DISPLAY_TXT_COL ("Elapsed Time", 
                   msToHHMMSSmmm(localElapsedTime),   
                   msToHHMMSSmmm(globalElapsedTime));

  DISPLAY_VAL_RATEF_COL ("Call Rate",  
                         realInstantCallRate, 
                         averageCallRate);
  DISPLAY_CROSS_LINE ();

  DISPLAY_2VAL  ("Incoming call created", 
                 M_counters[CPT_PD_IncomingCallCreated],
                 M_counters[CPT_C_IncomingCallCreated]);
  DISPLAY_2VAL  ("OutGoing call created", 
                 M_counters[CPT_PD_OutgoingCallCreated],
                 M_counters[CPT_C_OutgoingCallCreated]);
  DISPLAY_CUMUL ("Total Call created", M_counters[CPT_C_IncomingCallCreated] +
                 M_counters[CPT_C_OutgoingCallCreated]);
  DISPLAY_PERIO ("Current Call",       M_counters[CPT_C_CurrentCall]);

  bool first = true;
  for (int i = 0; i < MAX_COUNTER; i++) {
    char s[20];

    if (M_counters[CPT_C_Generic + i] == 0) {
      continue;
    }

    if (first) {
      DISPLAY_CROSS_LINE ();
      first = false;
    }

    sprintf(s, "Generic counter %d", i + 1);

    DISPLAY_2VAL(s, M_counters[CPT_PD_Generic + i], M_counters[CPT_C_Generic + i]);
  }

  DISPLAY_CROSS_LINE ();
  DISPLAY_2VAL  ("Successful call", 
                 M_counters[CPT_PD_SuccessfulCall], 
                 M_counters[CPT_C_SuccessfulCall]);
  DISPLAY_2VAL  ("Failed call",      
                 M_counters[CPT_PD_FailedCall], 
                 M_counters[CPT_C_FailedCall]);
  // DISPLAY_2VAL  ("Unexpected msg",   
  //                 M_counters[CPT_PD_UnexpectedMessage], 
  //                 M_counters[CPT_C_UnexpectedMessage]);

  DISPLAY_CROSS_LINE ();
  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    char s[15];

    if (M_counters[CPT_C_NbOfCallUsedForAverageResponseTime +i ] == 0) {
      continue;
    }

    sprintf(s, "Response Time %d", i + 1);
    DISPLAY_TXT_COL (s,
	msToHHMMSSmmm( M_counters [CPT_PD_AverageResponseTime + i] ),
	msToHHMMSSmmm( M_counters [CPT_C_AverageResponseTime + i] ));
  }
  DISPLAY_TXT_COL ("Call Length", 
                   msToHHMMSSmmm( M_counters [CPT_PD_AverageCallLength] ), 
                   msToHHMMSSmmm( M_counters [CPT_C_AverageCallLength] ));
  DISPLAY_CROSS_LINE ();

  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    char s[50];

    if (M_counters[CPT_C_AverageResponseTime + i] == 0) {
      continue;
    }

    sprintf(s, "Average Response Time Repartition, %d", i + 1);
    DISPLAY_INFO(s);
    displayRepartition(f, M_ResponseTimeRepartition[i], M_SizeOfResponseTimeRepartition);
  }
  DISPLAY_INFO("Average Call Length Repartition");
  displayRepartition(f, M_CallLengthRepartition, M_SizeOfCallLengthRepartition);

  //  DISPLAY_VAL ("NbCall Average RT(P)",
  //                 M_counters[CPT_PD_NbOfCallUsedForAverageResponseTime]);
  //  DISPLAY_VAL ("NbCall Average RT",
  //                 M_counters[CPT_C_NbOfCallUsedForAverageResponseTime]);
  //  DISPLAY_VAL ("NbCall Average CL",
  //                 M_counters[CPT_C_NbOfCallUsedForAverageCallLength]);
  //  DISPLAY_VAL ("NbCall Average CL(P)",
  //                 M_counters[CPT_PD_NbOfCallUsedForAverageCallLength]);
  DISPLAY_DLINE ();
} /* end of displayData () */


void CStat::displayStat (FILE *f)
{
  char   buf1 [64], buf2 [64], buf3 [64];
  long   localElapsedTime, globalElapsedTime ;
  struct timeval currentTime;
  float  averageCallRate;
  float  realInstantCallRate;
  unsigned long numberOfCall;

  GET_TIME (&currentTime);
  // computing the real call rate
  globalElapsedTime   = computeDiffTimeInMs (&currentTime, &M_startTime);
  localElapsedTime    = computeDiffTimeInMs (&currentTime, &M_pdStartTime);
  // the call rate is for all the call : incoming and outgoing
  numberOfCall        = (M_counters[CPT_C_IncomingCallCreated] + 
                         M_counters[CPT_C_OutgoingCallCreated]);
  averageCallRate     = (globalElapsedTime > 0 ? 
                         1000*(float)numberOfCall/(float)globalElapsedTime :
                         0.0);
  numberOfCall        = (M_counters[CPT_PD_IncomingCallCreated] + 
                         M_counters[CPT_PD_OutgoingCallCreated]);
  realInstantCallRate = (localElapsedTime  > 0 ? 
                         1000*(float)numberOfCall / (float)localElapsedTime :
                         0.0);

  // build and display header info
  DISPLAY_TXT ("Start Time  ", formatTime(&M_startTime));
  DISPLAY_TXT ("Last Reset Time", formatTime(&M_pdStartTime));
  DISPLAY_TXT ("Current Time", formatTime(&currentTime));

  // printing the header in the middle
  DISPLAY_CROSS_LINE();
  DISPLAY_HEADER();
  DISPLAY_CROSS_LINE();

  DISPLAY_TXT_COL ("Elapsed Time", 
                   msToHHMMSSmmm(localElapsedTime),   
                   msToHHMMSSmmm(globalElapsedTime));

  DISPLAY_VAL_RATEF_COL ("Call Rate",  realInstantCallRate, averageCallRate);
  DISPLAY_CROSS_LINE ();

  DISPLAY_2VAL  ("Incoming call created", 
                 M_counters[CPT_PD_IncomingCallCreated],
                 M_counters[CPT_C_IncomingCallCreated]);
  DISPLAY_2VAL  ("OutGoing call created", 
                 M_counters[CPT_PD_OutgoingCallCreated],
                 M_counters[CPT_C_OutgoingCallCreated]);
  DISPLAY_CUMUL ("Total Call created", M_counters[CPT_C_IncomingCallCreated] +
                 M_counters[CPT_C_OutgoingCallCreated]);
  DISPLAY_PERIO ("Current Call",
                 M_counters[CPT_C_CurrentCall]);

  bool first = true;
  for (int i = 0; i < MAX_COUNTER; i++) {
    char s[20];

    if (M_counters[CPT_C_Generic + i] == 0) {
      continue;
    }

    if (first) {
      DISPLAY_CROSS_LINE ();
      first = false;
    }

    sprintf(s, "Generic counter %d", i + 1);

    DISPLAY_2VAL(s, M_counters[CPT_PD_Generic + i], M_counters[CPT_C_Generic + i]);
  }

  DISPLAY_CROSS_LINE ();
  DISPLAY_2VAL  ("Successful call",
                 M_counters[CPT_PD_SuccessfulCall], 
                 M_counters[CPT_C_SuccessfulCall]);
  DISPLAY_2VAL  ("Failed call",
                 M_counters[CPT_PD_FailedCall],
                 M_counters[CPT_C_FailedCall]);
  //DISPLAY_2VAL  ("Unexpected msg",   
  //               M_counters[CPT_PD_UnexpectedMessage], 
  //               M_counters[CPT_C_UnexpectedMessage]);

  DISPLAY_CROSS_LINE ();
  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    char s[20];

    if (M_counters[CPT_C_NbOfCallUsedForAverageResponseTime + i] == 0) {
      continue;
    }


    sprintf(s, "Response Time %d", i + 1);
    DISPLAY_TXT_COL (s,
	msToHHMMSSmmm( M_counters [CPT_PD_AverageResponseTime + i] ),
	msToHHMMSSmmm( M_counters [CPT_C_AverageResponseTime + i] ));
  }
  DISPLAY_TXT_COL ("Call Length", 
                   msToHHMMSSmmm( M_counters [CPT_PD_AverageCallLength] ), 
                   msToHHMMSSmmm( M_counters [CPT_C_AverageCallLength] ));
}

void CStat::displayRepartition (FILE *f)
{
  DISPLAY_INFO("Average Response Time Repartition");
  displayRepartition(f,
                     M_ResponseTimeRepartition[0], 
                     M_SizeOfResponseTimeRepartition);
  DISPLAY_INFO("Average Call Length Repartition");
  displayRepartition(f,
                     M_CallLengthRepartition, 
                     M_SizeOfCallLengthRepartition);
}

void CStat::displaySecondaryRepartition (FILE *f, int which)
{
  DISPLAY_INFO("Average Response Time Repartition");
  displayRepartition(f,
                     M_ResponseTimeRepartition[which],
                     M_SizeOfResponseTimeRepartition);
}


void CStat::dumpData ()
{
  long   localElapsedTime, globalElapsedTime ;
  struct timeval currentTime;
  float  averageCallRate;
  float  realInstantCallRate;
  unsigned long numberOfCall;

  // computing the real call rate
  GET_TIME (&currentTime);
  globalElapsedTime   = computeDiffTimeInMs (&currentTime, &M_startTime);
  localElapsedTime    = computeDiffTimeInMs (&currentTime, &M_plStartTime);

  // the call rate is for all the call : incoming and outgoing
  numberOfCall        = (M_counters[CPT_C_IncomingCallCreated] + 
                         M_counters[CPT_C_OutgoingCallCreated]);
  averageCallRate     = (globalElapsedTime > 0 ? 
                         1000*(float)numberOfCall/(float)globalElapsedTime : 
                         0.0);
  numberOfCall        = (M_counters[CPT_PL_IncomingCallCreated] + 
                         M_counters[CPT_PL_OutgoingCallCreated]);
  realInstantCallRate = (localElapsedTime  > 0 ?
                         1000*(float)numberOfCall / (float)localElapsedTime :
                         0.0);

  if(M_outputStream == NULL) {
    // if the file is still not opened, we opened it now
    M_outputStream = new ofstream(M_fileName);
    M_headerAlreadyDisplayed = false;
    
    if(M_outputStream == NULL) {
      cerr << "Unable to open stat file '" << M_fileName << "' !" << endl;
      exit(EXIT_FATAL_ERROR);
    }

#ifndef __osf__
    if(!M_outputStream->is_open())
      {
        cerr << "Unable to open stat file '" << M_fileName << "' !" << endl;
        exit(EXIT_FATAL_ERROR);
      }
#endif

  }

  if(M_headerAlreadyDisplayed == false) {
    // header - it's dump in file only one time at the beginning of the file
    (*M_outputStream) << "StartTime" << stat_delimiter
                      << "LastResetTime" << stat_delimiter
                      << "CurrentTime" << stat_delimiter
                      << "ElapsedTime(P)" << stat_delimiter
                      << "ElapsedTime(C)" << stat_delimiter
                      << "CallRate(P)" << stat_delimiter
                      << "CallRate(C)" << stat_delimiter
                      << "IncomingCall(P)" << stat_delimiter
                      << "IncomingCall(C)" << stat_delimiter
                      << "OutgoingCall(P)" << stat_delimiter
                      << "OutgoingCall(C)" << stat_delimiter
                      << "TotalCallCreated" << stat_delimiter
                      << "CurrentCall" << stat_delimiter
                      << "SuccessfulCall(P)" << stat_delimiter
                      << "SuccessfulCall(C)" << stat_delimiter
                      << "FailedCall(P)" << stat_delimiter
                      << "FailedCall(C)" << stat_delimiter
                      << "FailedCannotSendMessage(P)" << stat_delimiter
                      << "FailedCannotSendMessage(C)" << stat_delimiter
                      << "FailedMaxUDPRetrans(P)" << stat_delimiter
                      << "FailedMaxUDPRetrans(C)" << stat_delimiter
                      << "FailedUnexpectedMessage(P)" << stat_delimiter
                      << "FailedUnexpectedMessage(C)" << stat_delimiter
                      << "FailedCallRejected(P)" << stat_delimiter
                      << "FailedCallRejected(C)" << stat_delimiter
                      << "FailedCmdNotSent(P)" << stat_delimiter
                      << "FailedCmdNotSent(C)" << stat_delimiter
                      << "FailedRegexpDoesntMatch(P)" << stat_delimiter
                      << "FailedRegexpDoesntMatch(C)" << stat_delimiter
                      << "FailedRegexpHdrNotFound(P)" << stat_delimiter
                      << "FailedRegexpHdrNotFound(C)" << stat_delimiter
                      << "FailedOutboundCongestion(P)" << stat_delimiter
                      << "FailedOutboundCongestion(C)" << stat_delimiter
                      << "FailedTimeoutOnRecv(P)" << stat_delimiter
                      << "FailedTimeoutOnRecv(C)" << stat_delimiter
                      << "OutOfCallMsgs(P)" << stat_delimiter
                      << "OutOfCallMsgs(C)" << stat_delimiter
                      << "Retransmissions(P)" << stat_delimiter
                      << "Retransmissions(C)" << stat_delimiter
                      << "AutoAnswered(P)" << stat_delimiter
                      << "AutoAnswered(C)" << stat_delimiter;

    for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
      char s_P[30];
      char s_C[30];

      sprintf(s_P, "ResponseTime%d(P)%s", i + 1, stat_delimiter);
      sprintf(s_C, "ResponseTime%d(C)%s", i + 1, stat_delimiter);

      (*M_outputStream) << s_P << s_C;

      sprintf(s_P, "ResponseTime%dStDev(P)%s", i + 1, stat_delimiter);
      sprintf(s_C, "ResponseTime%dStDev(C)%s", i + 1, stat_delimiter);

      (*M_outputStream) << s_P << s_C;
    }

    (*M_outputStream) << "CallLength(P)" << stat_delimiter
                      << "CallLength(C)" << stat_delimiter;
    (*M_outputStream) << "CallLengthStDev(P)" << stat_delimiter
                      << "CallLengthStDev(C)" << stat_delimiter;
    for (int i = 0; i < MAX_COUNTER; i++) {
      (*M_outputStream) << "GenericCounter" << (i + 1) << "(P)" << stat_delimiter;
      (*M_outputStream) << "GenericCounter" << (i + 1) << "(C)" << stat_delimiter;
    }
    for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
      char s[30];
      sprintf(s, "ResponseTimeRepartition%d", i + 1);
      (*M_outputStream) << sRepartitionHeader(M_ResponseTimeRepartition[i],
					      M_SizeOfResponseTimeRepartition,
					      s);
    }
    (*M_outputStream) << sRepartitionHeader(M_CallLengthRepartition, 
                                            M_SizeOfCallLengthRepartition,
                                            (char*) "CallLengthRepartition");
    (*M_outputStream) << endl;
    M_headerAlreadyDisplayed = true;
  }
  
  // content
  (*M_outputStream) << formatTime(&M_startTime)               << stat_delimiter;
  (*M_outputStream) << formatTime(&M_plStartTime)             << stat_delimiter;
  (*M_outputStream) << formatTime(&currentTime)               << stat_delimiter
                    << msToHHMMSS(localElapsedTime)           << stat_delimiter;
  (*M_outputStream) << msToHHMMSS(globalElapsedTime)          << stat_delimiter
                    << realInstantCallRate                    << stat_delimiter
                    << averageCallRate                        << stat_delimiter
                    << M_counters[CPT_PL_IncomingCallCreated] << stat_delimiter
                    << M_counters[CPT_C_IncomingCallCreated]  << stat_delimiter
                    << M_counters[CPT_PL_OutgoingCallCreated] << stat_delimiter
                    << M_counters[CPT_C_OutgoingCallCreated]  << stat_delimiter
                    << (M_counters[CPT_C_IncomingCallCreated]+ 
                        M_counters[CPT_C_OutgoingCallCreated])<< stat_delimiter
                    << M_counters[CPT_C_CurrentCall]          << stat_delimiter
                    << M_counters[CPT_PL_SuccessfulCall]      << stat_delimiter
                    << M_counters[CPT_C_SuccessfulCall]       << stat_delimiter
                    << M_counters[CPT_PL_FailedCall]          << stat_delimiter
                    << M_counters[CPT_C_FailedCall]           << stat_delimiter
                    << M_counters[CPT_PL_FailedCallCannotSendMessage]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallCannotSendMessage]    << stat_delimiter
                    << M_counters[CPT_PL_FailedCallMaxUdpRetrans]       << stat_delimiter
                    << M_counters[CPT_C_FailedCallMaxUdpRetrans     ]   << stat_delimiter
                    << M_counters[CPT_PL_FailedCallUnexpectedMessage]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallUnexpectedMessage]    << stat_delimiter
                    << M_counters[CPT_PL_FailedCallCallRejected]        << stat_delimiter
                    << M_counters[CPT_C_FailedCallCallRejected]         << stat_delimiter
                    << M_counters[CPT_PL_FailedCallCmdNotSent]          << stat_delimiter
                    << M_counters[CPT_C_FailedCallCmdNotSent]           << stat_delimiter
                    << M_counters[CPT_PL_FailedCallRegexpDoesntMatch]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallRegexpDoesntMatch]    << stat_delimiter
                    << M_counters[CPT_PL_FailedCallRegexpHdrNotFound]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallRegexpHdrNotFound]    << stat_delimiter
                    << M_counters[CPT_PL_FailedOutboundCongestion]      << stat_delimiter
                    << M_counters[CPT_C_FailedOutboundCongestion]       << stat_delimiter
                    << M_counters[CPT_PL_FailedTimeoutOnRecv]           << stat_delimiter
                    << M_counters[CPT_C_FailedTimeoutOnRecv]            << stat_delimiter
                    << M_counters[CPT_PL_OutOfCallMsgs]                 << stat_delimiter
                    << M_counters[CPT_C_OutOfCallMsgs]                  << stat_delimiter
                    << M_counters[CPT_PL_Retransmissions]               << stat_delimiter
                    << M_counters[CPT_C_Retransmissions]                << stat_delimiter
                    << M_counters[CPT_PL_AutoAnswered]                  << stat_delimiter
                    << M_counters[CPT_C_AutoAnswered]                   << stat_delimiter;

  // SF917289 << M_counters[CPT_C_UnexpectedMessage]    << stat_delimiter;
  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    (*M_outputStream) 
      << msToHHMMSSmmm( M_counters [CPT_PL_AverageResponseTime + i] ) << stat_delimiter;
    (*M_outputStream) 
      << msToHHMMSSmmm( M_counters [CPT_C_AverageResponseTime  + i] ) << stat_delimiter;

    (*M_outputStream)
      << msToHHMMSSmmm( computeStdev((E_CounterName)(CPT_PL_AverageResponseTime + i),
				     (E_CounterName)(CPT_PL_NbOfCallUsedForAverageResponseTime + i),
				     (E_CounterName)(CPT_PL_AverageResponseTime_Squares + i)) ) << stat_delimiter;
    (*M_outputStream)
      << msToHHMMSSmmm( computeStdev((E_CounterName)(CPT_C_AverageResponseTime + i),
				     (E_CounterName)(CPT_C_NbOfCallUsedForAverageResponseTime + i),
				     (E_CounterName)(CPT_C_AverageResponseTime_Squares + i)) ) << stat_delimiter;
  }
  (*M_outputStream) 
    << msToHHMMSSmmm( M_counters [CPT_PL_AverageCallLength  ] ) << stat_delimiter;
  (*M_outputStream) 
    << msToHHMMSSmmm( M_counters [CPT_C_AverageCallLength   ] ) << stat_delimiter;
  (*M_outputStream)
    << msToHHMMSSmmm( computeStdev(CPT_PL_AverageCallLength,
				   CPT_PL_NbOfCallUsedForAverageCallLength,
				   CPT_PL_AverageCallLength_Squares )) << stat_delimiter;
  (*M_outputStream)
    << msToHHMMSSmmm( computeStdev(CPT_C_AverageCallLength,
				   CPT_C_NbOfCallUsedForAverageCallLength,
				   CPT_C_AverageCallLength_Squares )) << stat_delimiter;

  for (int i = 0; i < MAX_COUNTER; i++) {
    (*M_outputStream) << M_counters[CPT_PL_Generic + i] << stat_delimiter;
    (*M_outputStream) << M_counters[CPT_C_Generic + i] << stat_delimiter;
  }

  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    (*M_outputStream) 
      << sRepartitionInfo(M_ResponseTimeRepartition[i], 
                          M_SizeOfResponseTimeRepartition);
  }
  (*M_outputStream) 
    << sRepartitionInfo(M_CallLengthRepartition, 
                        M_SizeOfCallLengthRepartition);
  (*M_outputStream) << endl;

  // flushing the output file to let the tail -f working !
  (*M_outputStream).flush();

} /* end of logData () */

void CStat::dumpDataRtt ()
{
  int L_i ;

  if(M_outputStreamRtt == NULL) {
    // if the file is still not opened, we opened it now
    M_outputStreamRtt = new ofstream(M_fileNameRtt);
    M_headerAlreadyDisplayedRtt = false;
    
    if(M_outputStreamRtt == NULL) {
      cerr << "Unable to open rtt file '" << M_fileNameRtt << "' !" << endl;
      exit(EXIT_FATAL_ERROR);
    }

#ifndef __osf__
    if(!M_outputStreamRtt->is_open())
      {
        cerr << "Unable to open rtt file '" << M_fileNameRtt << "' !" << endl;
        exit(EXIT_FATAL_ERROR);
      }
#endif
  }
  
  if(M_headerAlreadyDisplayedRtt == false) {
    (*M_outputStreamRtt) << "Date_ms" << stat_delimiter
      << "response_time_ms" << stat_delimiter
      << "rtd_no" << endl;
    M_headerAlreadyDisplayedRtt = true;
  }

  for (L_i = 0; L_i < M_counterDumpRespTime ; L_i ++) {
    (*M_outputStreamRtt) <<  M_dumpRespTime[L_i].date   << stat_delimiter ;
    (*M_outputStreamRtt) <<  M_dumpRespTime[L_i].rtt    << stat_delimiter ;
    (*M_outputStreamRtt) <<  M_dumpRespTime[L_i].rtd_no << endl;
    (*M_outputStreamRtt).flush();
    M_dumpRespTime[L_i].date = 0.0;
    M_dumpRespTime[L_i].rtt = 0.0;
    M_dumpRespTime[L_i].rtd_no = 0;
  }
      
  // flushing the output file
  (*M_outputStreamRtt).flush();
        
  M_counterDumpRespTime = 0;
}


/* Time Gestion */
char* CStat::msToHHMMSS (unsigned long P_ms)
{
  static char L_time [TIME_LENGTH];
  unsigned long hh, mm, ss;
        
  P_ms = P_ms / 1000;
  hh = P_ms / 3600;
  mm = (P_ms - hh * 3600) / 60;
  ss = P_ms - (hh * 3600) - (mm * 60);
  sprintf (L_time, "%2.2d:%2.2d:%2.2d", hh, mm, ss);
  return (L_time);
} /* end of msToHHMMSS */

char* CStat::msToHHMMSSmmm (unsigned long P_ms)
{
  static char L_time [TIME_LENGTH];
  unsigned long sec, hh, mm, ss, mmm;

  sec  = P_ms / 1000;
  hh   = sec / 3600;
  mm   = (sec - hh * 3600) / 60;
  ss   = sec - (hh * 3600) - (mm * 60);
  mmm  = P_ms - (hh * 3600000) - (mm * 60000) - (ss*1000);
  sprintf (L_time, "%2.2d:%2.2d:%2.2d:%3.3d", hh, mm, ss, mmm);
  return (L_time);
} /* end of msToHHMMSS */



char* CStat::formatTime (struct timeval* P_tv)
{
  static char L_time [TIME_LENGTH];
  struct tm * L_currentDate;

  // Get the current date and time
  L_currentDate = localtime ((const time_t *)&P_tv->tv_sec);

  // Format the time
  if (L_currentDate == NULL)
    {
      memset (L_time, 0, TIME_LENGTH);
    } 
  else
    {
      // SF917230 sprintf(L_time, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d:%3.3d", 
      sprintf(L_time, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d", 
              L_currentDate->tm_year + 1900,
              L_currentDate->tm_mon + 1,
              L_currentDate->tm_mday,
              L_currentDate->tm_hour,
              L_currentDate->tm_min,
              L_currentDate->tm_sec);
      // SF917230 (int) (P_tv->tv_usec)/1000);
    }
  return (L_time);
} /* end of formatTime */

long CStat::computeDiffTimeInMs (struct timeval* tf, struct timeval* ti)
{
  long v1, v2;

  v1 = tf->tv_sec - ti->tv_sec;
  v2 = tf->tv_usec - ti->tv_usec;
  if (v2 < 0) v2 += 1000000, v1--;
  return (v1*1000 + v2/1000);
}


CStat* CStat::M_instance = NULL;
