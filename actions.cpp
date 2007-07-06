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
 *            Guillaume Teissier from FTR&D
 */

#include "sipp.hpp"
#include <assert.h>
#ifdef PCAPPLAY
#include "prepare_pcap.h"
#endif

static const char* strIntCmd(CAction::T_IntCmdType type)
{
    switch (type)
    {
        case CAction::E_INTCMD_STOPCALL:
            return "stop_call";
        case CAction::E_INTCMD_STOP_ALL:
            return "stop_gracefully";
        case CAction::E_INTCMD_STOP_NOW:
            return "stop_now";

        default:
        case CAction::E_INTCMD_INVALID:
            return "invalid";
    }
    return "invalid";
}

const char * CAction::comparatorToString(T_Comparator comp) {
   switch(comp) {
     case E_C_EQ:
       return "==";
     case E_C_NE:
       return "!=";
     case E_C_GT:
       return ">";
     case E_C_LT:
       return "<";
     case E_C_GEQ:
       return ">=";
     case E_C_LEQ:
       return "<=";
     default:
       return "invalid";
   }
}

bool CAction::compare(CCallVariable *variableTable[]) {
  double lhs = variableTable[M_varInId] ? variableTable[M_varInId]->getDouble() : 0.0;
  double rhs = M_doubleValue;

  switch(M_comp) {
    case E_C_EQ:
      return lhs == rhs;
    case E_C_NE:
      return lhs != rhs;
    case E_C_GT:
      return lhs > rhs;
    case E_C_LT:
      return lhs < rhs;
    case E_C_GEQ:
      return lhs >= rhs;
    case E_C_LEQ:
      return lhs <= rhs;
    default:
      ERROR_P1("Internal error: Invalid comparison type %d", M_comp);
      return false; /* Shut up warning. */
  }
}

void CAction::afficheInfo()
{
  if (M_action == E_AT_ASSIGN_FROM_REGEXP) {
    if(M_lookingPlace == E_LP_MSG) {
      printf("Type[%d] - where[%s] - checkIt[%d] - varId[%d]",
             M_action,
             "Full Msg",
             M_checkIt,
		       M_varId);
    } else {
      printf("Type[%d] - where[%s-%s] - checkIt[%d] - varId[%d]",
             M_action,
             "Header",
             M_lookingChar,
             M_checkIt,
		       M_varId);
    }
  } else if (M_action == E_AT_EXECUTE_CMD) {
    if (M_cmdLine) {
        printf("Type[%d] - command[%-32.32s]", M_action, M_cmdLine);
    }
  } else if (M_action == E_AT_EXEC_INTCMD) {
      printf("Type[%d] - intcmd[%-32.32s]", M_action, strIntCmd(M_IntCmd));
  } else if (M_action == E_AT_LOG_TO_FILE) {
      printf("Type[%d] - message[%-32.32s]", M_action, M_message);
  } else if (M_action == E_AT_ASSIGN_FROM_SAMPLE) {
      char tmp[40];
      M_distribution->textDescr(tmp, sizeof(tmp));
      printf("Type[%d] - sample varId[%d] %s", M_action, M_varId, tmp);
  } else if (M_action == E_AT_ASSIGN_FROM_VALUE) {
      printf("Type[%d] - assign varId[%d] %lf", M_action, M_varId, M_doubleValue);
  } else if (M_action == E_AT_ASSIGN_FROM_STRING) {
      printf("Type[%d] - string assign varId[%d] [%-32.32s]", M_action, M_varId, M_message);
  } else if (M_action == E_AT_VAR_ADD) {
      printf("Type[%d] - add varId[%d] %lf", M_action, M_varId, M_doubleValue);
  } else if (M_action == E_AT_VAR_MULTIPLY) {
      printf("Type[%d] - multiply varId[%d] %lf", M_action, M_varId, M_doubleValue);
  } else if (M_action == E_AT_VAR_DIVIDE) {
      printf("Type[%d] - divide varId[%d] %lf", M_action, M_varId, M_doubleValue);
  } else if (M_action == E_AT_VAR_TEST) {
      printf("Type[%d] - divide varId[%d] varInId[%d] %s %lf", M_action, M_varId, M_varInId, comparatorToString(M_comp), M_doubleValue);
  } else if (M_action == E_AT_VAR_TO_DOUBLE) {
      printf("Type[%d] - toDouble varId[%d]", M_action, M_varId);
#ifdef PCAPPLAY
  } else if ((M_action == E_AT_PLAY_PCAP_AUDIO) || (M_action == E_AT_PLAY_PCAP_VIDEO)) {
      printf("Type[%d] - file[%s]", M_action, M_pcapArgs->file);
#endif
  }
}


CAction::T_ActionType   CAction::getActionType()   { return(M_action);       }
CAction::T_LookingPlace CAction::getLookingPlace() { return(M_lookingPlace); }
CAction::T_IntCmdType   CAction::getIntCmd ()      { return(M_IntCmd);       }
CAction::T_Comparator   CAction::getComparator ()  { return(M_comp);	     }

bool           CAction::getCheckIt()      { return(M_checkIt);      }
bool           CAction::getCaseIndep()    { return(M_caseIndep);    }
bool           CAction::getHeadersOnly()  { return(M_headersOnly);  }
int            CAction::getOccurence()    { return(M_occurence);    }
int            CAction::getVarId()        { return(M_varId);        }
int            CAction::getVarInId()      { return(M_varInId);      }
char*          CAction::getLookingChar()  { return(M_lookingChar);  }
char*          CAction::getMessage()      { return(M_message);      }
char*          CAction::getCmdLine()      { return(M_cmdLine);      }
CSample*       CAction::getDistribution() { return(M_distribution); }
double         CAction::getDoubleValue()  { return(M_doubleValue);  }
char*          CAction::getStringValue()  { return(M_stringValue);  }
#ifdef PCAPPLAY
pcap_pkts  *   CAction::getPcapPkts()     { return(M_pcapArgs);     }
#endif

void CAction::setActionType   (CAction::T_ActionType   P_value) 
{ M_action       = P_value; }  
void CAction::setLookingPlace (CAction::T_LookingPlace P_value) 
{ M_lookingPlace = P_value; }
void CAction::setCheckIt      (bool           P_value) 
{ M_checkIt      = P_value; }
void CAction::setVarId        (int            P_value) 
{ M_varId        = P_value; }
void CAction::setVarInId      (int            P_value)
{ M_varInId        = P_value; }
void CAction::setCaseIndep    (bool           P_value)
{ M_caseIndep    = P_value; }
void CAction::setOccurence   (int            P_value) 
{ M_occurence    = P_value; }
void CAction::setHeadersOnly  (bool           P_value)
{ M_headersOnly  = P_value; }
void CAction::setIntCmd       (T_IntCmdType P_type)
{ M_IntCmd       = P_type;  }
void CAction::setComparator   (T_Comparator P_value)
{ M_comp         = P_value; }

/* sample specific function. */
void CAction::setDistribution (CSample *P_value)
{ M_distribution       = P_value; }
/* assign from value specific function. */
void CAction::setDoubleValue (double P_value)
{ M_doubleValue       = P_value;  }

/* strcmp specific function. */
void CAction::setStringValue (char *P_value)
{ M_stringValue       = P_value;  }

void CAction::setSubVarId (int    P_value) {
   if ( M_nbSubVarId < M_maxNbSubVarId ) {
     M_subVarId[M_nbSubVarId] = P_value;
     M_nbSubVarId++;
   }
}

int  CAction::getSubVarId(int P_index) {
    return(M_subVarId[P_index]);
}

int*  CAction::getSubVarId() {
    return(M_subVarId);
}

void CAction::setNbSubVarId (int            P_value) {
   M_maxNbSubVarId        = P_value; 
   if(M_subVarId != NULL) {
     delete [] M_subVarId;
     M_subVarId      = NULL;
   }
   M_subVarId = new int[M_maxNbSubVarId] ;
   M_nbSubVarId = 0 ;
}
int  CAction::getNbSubVarId () {
    return(M_nbSubVarId);        
}


void CAction::setLookingChar  (char*          P_value)
{
  if(M_lookingChar != NULL)
  {
    delete [] M_lookingChar;
    M_lookingChar = NULL;
  }

  if(P_value != NULL)
  { 
    M_lookingChar = new char[strlen(P_value)+1];
    strcpy(M_lookingChar, P_value);
  }
}

void CAction::setMessage  (char*          P_value)
{
  if(M_message != NULL)
  {
    delete [] M_message;
    M_message = NULL;
  }

  if(P_value != NULL)
  { 
    M_message = new char[strlen(P_value)+1];
    strcpy(M_message, P_value);
  }
}

void CAction::setCmdLine  (char*          P_value)
{
  if(M_cmdLine != NULL)
  {
    delete [] M_cmdLine;
    M_cmdLine = NULL;
  }

  if(P_value != NULL)
  { 
    M_cmdLine = new char[strlen(P_value)+1];
    strcpy(M_cmdLine, P_value);
  }
}

#ifdef PCAPPLAY
void CAction::setPcapArgs (pcap_pkts  *  P_value)
{
  if(M_pcapArgs != NULL)
  {
    free(M_pcapArgs);
    M_pcapArgs = NULL;
  }

  if(P_value != NULL)
  { 
    M_pcapArgs = (pcap_pkts *)malloc(sizeof(*M_pcapArgs));
    memcpy(M_pcapArgs, P_value, sizeof(*M_pcapArgs));
  }
}

void CAction::setPcapArgs (char*        P_value)
{
  if(M_pcapArgs != NULL)
  {
    free(M_pcapArgs);
    M_pcapArgs = NULL;
  }

  if(P_value != NULL)
  { 
    M_pcapArgs = (pcap_pkts *) malloc(sizeof(*M_pcapArgs));
    if (parse_play_args(P_value, M_pcapArgs) == -1)
    {
      ERROR("Play pcap error");
    }
    if (access(M_pcapArgs->file, F_OK)) {
      ERROR_P1("Cannot read file %s\n", M_pcapArgs->file);
    }
  }
}
#endif

void CAction::setAction(CAction P_action)
{
  if (P_action.getActionType() == CAction::E_AT_ASSIGN_FROM_SAMPLE) {
    assert(P_action.getDistribution() != NULL);
  }
  int L_i;
  setActionType   ( P_action.getActionType()   );
  setLookingPlace ( P_action.getLookingPlace() );
  setVarId        ( P_action.getVarId()        );
  setVarInId      ( P_action.getVarInId()      );
  setDoubleValue  ( P_action.getDoubleValue()  );
  setDistribution ( P_action.getDistribution() );

  setNbSubVarId   ( P_action.getNbSubVarId()   );
  for (L_i = 0; L_i < P_action.getNbSubVarId() ; L_i++ ) {
    setSubVarId (P_action.getSubVarId(L_i));
  }

  setLookingChar  ( P_action.getLookingChar()  );
  setCheckIt      ( P_action.getCheckIt()      );
  setCaseIndep    ( P_action.getCaseIndep()    ); 
  setOccurence    ( P_action.getOccurence()   );
  setHeadersOnly  ( P_action.getHeadersOnly()  );
  setMessage      ( P_action.M_message         );
  setCmdLine      ( P_action.M_cmdLine         );
  setIntCmd       ( P_action.M_IntCmd          );
#ifdef PCAPPLAY
  setPcapArgs     ( P_action.M_pcapArgs        );
#endif
}

CAction::CAction()
{
  M_action       = E_AT_NO_ACTION;
  M_varId        = 0;
  M_varInId        = 0;

  M_nbSubVarId    = 0;
  M_maxNbSubVarId = 0;
  M_subVarId      = NULL;

  M_checkIt      = false;
  M_lookingPlace = E_LP_MSG;
  M_lookingChar  = NULL;
  M_caseIndep    = false;
  M_occurence    = 1;
  M_headersOnly  = true;   
  M_message      = NULL;
  M_cmdLine      = NULL;
  M_IntCmd       = E_INTCMD_INVALID;
  M_doubleValue  = 0;
  M_stringValue  = NULL;
  M_distribution = NULL;
#ifdef PCAPPLAY
  M_pcapArgs     = NULL;
#endif
}

CAction::~CAction()
{
  if(M_lookingChar != NULL)
  {
    delete [] M_lookingChar;
    M_lookingChar = NULL;
  }
  if(M_message != NULL)
  {
    delete [] M_message;
    M_message = NULL;
  }
  if(M_cmdLine != NULL)
  {
    delete [] M_cmdLine;
    M_cmdLine = NULL;
  }
  if(M_subVarId != NULL)
  {
    delete [] M_subVarId;
    M_subVarId      = NULL;
  }
  if(M_stringValue != NULL)
  {
    delete [] M_stringValue;
    M_stringValue      = NULL;
  }
#ifdef PCAPPLAY
  if (M_pcapArgs != NULL) {
    free(M_pcapArgs);
    M_pcapArgs = NULL;
  }
#endif
}

/****************************** CActions class ************************/

void CActions::afficheInfo()
{
  printf("Action Size = [%d]\n", M_nbAction);
  for(int i=0; i<M_nbAction; i++)
  {
    printf("actionlist[%d] : \n", i);
    M_actionList[i]->afficheInfo();
  }
}

void CActions::reset()
{
  for (int i = 0; i < M_nbAction; i++) {
    delete M_actionList[i];
    M_actionList[i] = NULL;
  }
  M_nbAction = 0;
}

int CActions::getActionSize()
{
  return(M_nbAction);
}

void CActions::setAction(CAction *P_action)
{
  CAction **newActions = new CAction*[M_nbAction + 1];
  if (!newActions) {
    ERROR("Could not allocate new action list.");
  }
  for (int i = 0; i < M_nbAction; i++) {
	newActions[i] = M_actionList[i];
  }
  if (M_actionList) {
    delete [] M_actionList;
  }
  M_actionList = newActions;
  M_actionList[M_nbAction] = P_action;
  M_nbAction++;
}

CAction* CActions::getAction(int i)
{
  if(i < M_nbAction)
  {
    return(M_actionList[i]);
  }
  else
    return(NULL);
}


CActions::CActions()
{
  M_nbAction = 0;
  M_actionList = NULL;
}


CActions::~CActions()
{
  for (int i = 0; i < M_nbAction; i++) {
	delete M_actionList[i];
  }
  delete [] M_actionList;
  M_actionList = NULL;
}
