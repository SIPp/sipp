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
      E_AT_LOG_TO_FILE,
      E_AT_EXECUTE_CMD,
      E_AT_EXEC_INTCMD,
#ifdef PCAPPLAY
      E_AT_PLAY_PCAP_AUDIO,
      E_AT_PLAY_PCAP_VIDEO,
#endif
      E_AT_NB_ACTION
    };

    enum T_VarType
    {
      E_VT_REGEXP = 0,
      E_VT_CONST,
      E_VT_UNDEFINED,
      E_VT_NB_VAR_TYPE
    };

    enum T_LookingPlace
    {
      E_LP_MSG = 0,
      E_LP_HDR,
      E_LP_NB_LOOKING_PLACE
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

    T_ActionType   getActionType();
    T_VarType      getVarType();  
    T_LookingPlace getLookingPlace();
    bool           getCheckIt();
    int            getVarId();
    char*          getLookingChar();
    char*          getMessage();  /* log specific function  */
    char*          getCmdLine();  /* exec specific function */
    T_IntCmdType   getIntCmd();   /* exec specific function */
#ifdef PCAPPLAY
    pcap_pkts     *getPcapPkts(); /* send_packets specific function */
#endif

    void setActionType   (T_ActionType   P_value);
    void setVarType      (T_VarType      P_value);  
    void setLookingPlace (T_LookingPlace P_value);
    void setCheckIt      (bool           P_value);
    void setVarId        (int            P_value);
    void setLookingChar  (char*          P_value);
    void setAction       (CAction        P_action);
    void setMessage      (char*          P_value);  /* log specific function  */
    void setCmdLine      (char*          P_value);  /* exec specific function */
    void setIntCmd       (T_IntCmdType   P_type );  /* exec specific function */
#ifdef PCAPPLAY
    void setPcapArgs     (char *         P_value);  /* send_packets specific function */
    void setPcapArgs     (pcap_pkts   *  P_value);  /* send_packets specific function */
#endif

    void setSubVarId     (int P_value);
    int  getSubVarId     (int P_index);
    void setNbSubVarId   (int P_value);
    int  getNbSubVarId   ();
    int* getSubVarId() ;
    
    CAction(const CAction &P_Action);
    CAction();
    ~CAction();
  
  private:
      T_ActionType   M_action;
      T_VarType      M_varType;
      T_LookingPlace M_lookingPlace;
      bool           M_checkIt;
      int            M_varId;

      int            M_nbSubVarId;
      int            M_maxNbSubVarId;
      int *          M_subVarId;

      char*          M_lookingChar;
      /* log specific member  */
      char*          M_message;
      /* exec specific member */
      char*          M_cmdLine;
      T_IntCmdType   M_IntCmd;
#ifdef PCAPPLAY
      /* pcap specific member */
      pcap_pkts  *   M_pcapArgs;
#endif
};

class CActions
{
  public:
    void afficheInfo();
    void setAction(CAction P_action);
    void reset();
    int  getUsedAction();
    int  getMaxSize();
    CAction* getAction(int i);
    CActions(const CActions &P_Actions);
    CActions(int P_nbAction);
    ~CActions();
  
  private:
    CAction*   M_actionList;
    int        M_nbAction;
    int        M_currentSettedAction;
};

#endif
