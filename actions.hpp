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

#ifndef _CACTIONS
#define _CACTIONS

#include "variables.hpp"
class CSample;

#ifdef PCAPPLAY
#include "prepare_pcap.h"
#endif

class CAction
{
  public:
    enum T_ActionType
    {
      E_AT_NO_ACTION = 0,
      E_AT_ASSIGN_FROM_REGEXP,
      E_AT_CHECK,
      E_AT_ASSIGN_FROM_VALUE,
      E_AT_ASSIGN_FROM_SAMPLE,
      E_AT_ASSIGN_FROM_STRING,
      E_AT_LOG_TO_FILE,
      E_AT_EXECUTE_CMD,
      E_AT_EXEC_INTCMD,
      E_AT_VAR_ADD,
      E_AT_VAR_SUBTRACT,
      E_AT_VAR_MULTIPLY,
      E_AT_VAR_DIVIDE,
      E_AT_VAR_TEST,
      E_AT_VAR_TO_DOUBLE,
      E_AT_VAR_STRCMP,
#ifdef PCAPPLAY
      E_AT_PLAY_PCAP_AUDIO,
      E_AT_PLAY_PCAP_VIDEO,
#endif
      E_AT_NB_ACTION
    };

    enum T_LookingPlace
    {
      E_LP_MSG = 0,
      E_LP_HDR,
      E_LP_NB_LOOKING_PLACE
    };

    enum T_Comparator
    {
      E_C_EQ,
      E_C_NE,
      E_C_GT,
      E_C_LT,
      E_C_GEQ,
      E_C_LEQ,
      E_C_NB_COMPARATOR
    };

    enum T_IntCmdType
    {
      E_INTCMD_INVALID = 0,
      E_INTCMD_STOPCALL,
      E_INTCMD_STOP_ALL,
      E_INTCMD_STOP_NOW
    };

    typedef struct _T_Action
    {
    } T_Action;

    void afficheInfo();
    const char *comparatorToString(T_Comparator comp);
    bool compare(CCallVariable *variableTable[]);

    T_ActionType   getActionType();
    T_VarType      getVarType();
    T_LookingPlace getLookingPlace();
    T_Comparator   getComparator();
    bool           getCheckIt();
    bool           getCaseIndep();
    bool           getHeadersOnly();
    int            getVarId();
    int            getVarInId();
    int            getOccurence();
    char*          getLookingChar();
    char*          getMessage();  /* log specific function  */
    char*          getCmdLine();  /* exec specific function */
    T_IntCmdType   getIntCmd();   /* exec specific function */
#ifdef PCAPPLAY
    pcap_pkts     *getPcapPkts(); /* send_packets specific function */
#endif

    void setActionType   (T_ActionType   P_value);
    void setLookingPlace (T_LookingPlace P_value);
    void setComparator   (T_Comparator   P_value);
    void setCheckIt      (bool           P_value);
    void setVarId        (int            P_value);
    void setVarInId      (int            P_value);
    void setLookingChar  (char*          P_value);
    void setAction       (CAction        P_action);
    void setCaseIndep    (bool           P_action);
    void setOccurence   (int            P_value);
    void setHeadersOnly  (bool           P_value);
    void setMessage      (char*          P_value);  /* log specific function  */
    void setCmdLine      (char*          P_value);  /* exec specific function */
    void setIntCmd       (T_IntCmdType   P_type );  /* exec specific function */
    void setDistribution (CSample *      P_value);  /* sample specific function  */
    void setDoubleValue  (double         P_value);  /* assign value specific function  */
    void setStringValue  (char *         P_value);  /* strcmp value specific function  */
#ifdef PCAPPLAY
    void setPcapArgs     (char *         P_value);  /* send_packets specific function */
    void setPcapArgs     (pcap_pkts   *  P_value);  /* send_packets specific function */
#endif

    void setSubVarId     (int P_value);
    int  getSubVarId     (int P_index);
    void setNbSubVarId   (int P_value);
    int  getNbSubVarId   ();
    int* getSubVarId() ;
    CSample *getDistribution ();  /* sample specific function  */
    double getDoubleValue ();  /* assign value specific function  */
    char * getStringValue ();  /* strcmp specific function  */

    CAction();
    ~CAction();

  private:
      T_ActionType   M_action;
      T_LookingPlace M_lookingPlace;
      T_Comparator   M_comp;
      bool           M_checkIt;
      bool           M_caseIndep;
      bool           M_headersOnly;
      int            M_varId;
      int            M_varInId;
      int            M_occurence;
      int            M_nbSubVarId;
      int            M_maxNbSubVarId;
      int *          M_subVarId;

      char*          M_lookingChar;
      /* log specific member  */
      char*          M_message;
      /* exec specific member */
      char*          M_cmdLine;
      T_IntCmdType   M_IntCmd;
      /* sample specific member. */
      CSample	     *M_distribution;
      /* assign value specific member. */
      double         M_doubleValue;
      /* strcmp specific member. */
      char *         M_stringValue;
#ifdef PCAPPLAY
      /* pcap specific member */
      pcap_pkts  *   M_pcapArgs;
#endif
};

class CActions
{
  public:
    void afficheInfo();
    void setAction(CAction *P_action);
    void reset();
    int  getActionSize();
    CAction* getAction(int i);
    CActions();
    ~CActions();
  
  private:
    CAction ** M_actionList;
    int        M_nbAction;
    int        M_currentSettedAction;
};

#endif
