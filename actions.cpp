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

bool CAction::compare(VariableTable *variableTable) {
  double lhs = variableTable->getVar(M_varInId)->getDouble();
  double rhs = M_varIn2Id ? variableTable->getVar(M_varIn2Id)->getDouble() : M_doubleValue;

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
      ERROR("Internal error: Invalid comparison type %d", M_comp);
      return false; /* Shut up warning. */
  }
}

void CAction::afficheInfo()
{
  if (M_action == E_AT_ASSIGN_FROM_REGEXP) {
    if(M_lookingPlace == E_LP_MSG) {
            printf("Type[%d] - regexp[%s] where[%s] - checkIt[%d] - checkItInverse[%d] - $%s",
             M_action,
	     M_regularExpression,
             "Full Msg",
             M_checkIt,
                   M_checkItInverse,
		       display_scenario->allocVars->getName(M_varId));
    } else {
            printf("Type[%d] - regexp[%s] where[%s-%s] - checkIt[%d] - checkItInverse[%d] - $%s",
             M_action,
	     M_regularExpression,
             "Header",
             M_lookingChar,
                   M_checkIt,
                   M_checkItInverse, display_scenario->allocVars->getName(M_varId));
    }
  } else if (M_action == E_AT_EXECUTE_CMD) {
    printf("Type[%d] - command[%-32.32s]", M_action, M_message_str[0]);
  } else if (M_action == E_AT_EXEC_INTCMD) {
      printf("Type[%d] - intcmd[%-32.32s]", M_action, strIntCmd(M_IntCmd));
  } else if (M_action == E_AT_LOG_TO_FILE) {
      printf("Type[%d] - message[%-32.32s]", M_action, M_message_str[0]);
  } else if (M_action == E_AT_LOG_WARNING) {
      printf("Type[%d] - warning[%-32.32s]", M_action, M_message_str[0]);
  } else if (M_action == E_AT_LOG_ERROR) {
      printf("Type[%d] - error[%-32.32s]", M_action, M_message_str[0]);
  } else if (M_action == E_AT_ASSIGN_FROM_SAMPLE) {
      char tmp[40];
      M_distribution->textDescr(tmp, sizeof(tmp));
      printf("Type[%d] - sample varId[%s] %s", M_action, display_scenario->allocVars->getName(M_varId), tmp);
  } else if (M_action == E_AT_ASSIGN_FROM_VALUE) {
      printf("Type[%d] - assign varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
  } else if (M_action == E_AT_ASSIGN_FROM_INDEX) {
      printf("Type[%d] - assign index[%s]", M_action, display_scenario->allocVars->getName(M_varId));
  } else if (M_action == E_AT_ASSIGN_FROM_GETTIMEOFDAY) {
      printf("Type[%d] - assign gettimeofday[%s, %s]", M_action, display_scenario->allocVars->getName(M_varId), display_scenario->allocVars->getName(M_subVarId[0]));
  } else if (M_action == E_AT_ASSIGN_FROM_STRING) {
      printf("Type[%d] - string assign varId[%s] [%-32.32s]", M_action, display_scenario->allocVars->getName(M_varId), M_message_str[0]);
  } else if (M_action == E_AT_JUMP) {
      printf("Type[%d] - jump varInId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varInId), M_doubleValue);
  } else if (M_action == E_AT_PAUSE_RESTORE) {
      printf("Type[%d] - restore pause varInId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varInId), M_doubleValue);
  } else if (M_action == E_AT_VAR_ADD) {
      printf("Type[%d] - add varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
  } else if (M_action == E_AT_VAR_MULTIPLY) {
      printf("Type[%d] - multiply varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
  } else if (M_action == E_AT_VAR_DIVIDE) {
      printf("Type[%d] - divide varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
  } else if (M_action == E_AT_VAR_TRIM) {
      printf("Type[%d] - trim varId[%s]", M_action, display_scenario->allocVars->getName(M_varId));
  } else if (M_action == E_AT_VAR_TEST) {
      printf("Type[%d] - divide varId[%s] varInId[%s] %s %lf", M_action, display_scenario->allocVars->getName(M_varId), display_scenario->allocVars->getName(M_varInId), comparatorToString(M_comp), M_doubleValue);
  } else if (M_action == E_AT_VAR_TO_DOUBLE) {
      printf("Type[%d] - toDouble varId[%s]", M_action, display_scenario->allocVars->getName(M_varId));
#ifdef PCAPPLAY
  } else if ((M_action == E_AT_PLAY_PCAP_AUDIO) || (M_action == E_AT_PLAY_PCAP_VIDEO)) {
      printf("Type[%d] - file[%s]", M_action, M_pcapArgs->file);
#endif
  } else {
      printf("Type[%d] - unknown action type ... ", M_action);
  }
}


CAction::T_ActionType   CAction::getActionType()   { return(M_action);       }
CAction::T_LookingPlace CAction::getLookingPlace() { return(M_lookingPlace); }
CAction::T_IntCmdType   CAction::getIntCmd ()      { return(M_IntCmd);       }
CAction::T_Comparator   CAction::getComparator ()  { return(M_comp);	     }

bool           CAction::getCheckIt()      { return(M_checkIt);      }
bool           CAction::getCheckItInverse() { return(M_checkItInverse);      }
bool           CAction::getCaseIndep()    { return(M_caseIndep);    }
bool           CAction::getHeadersOnly()  { return(M_headersOnly);  }
int            CAction::getOccurence()    { return(M_occurence);    }
int            CAction::getVarId()        { return(M_varId);        }
int            CAction::getVarInId()      { return(M_varInId);      }
int            CAction::getVarIn2Id()      { return(M_varIn2Id);      }
char*          CAction::getLookingChar()  { return(M_lookingChar);  }
SendingMessage *CAction::getMessage(int n)      { return(M_message[n]);      }
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
void CAction::setCheckItInverse      (bool           P_value) 
{ M_checkItInverse      = P_value; }
void CAction::setVarId        (int            P_value) 
{ M_varId        = P_value; }
void CAction::setVarInId      (int            P_value)
{ M_varInId        = P_value; }
void CAction::setVarIn2Id      (int            P_value)
{ M_varIn2Id        = P_value; }
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

void CAction::setMessage  (char*          P_value, int n)
{
  if(M_message[n] != NULL)
  {
    delete M_message[n];
    M_message[n] = NULL;
  }
  free(M_message_str[n]);
  M_message_str[n] = NULL;

  if(P_value != NULL)
  { 
    M_message_str[n] = strdup(P_value);
    M_message[n] = new SendingMessage(M_scenario, P_value, true /* skip sanity */);
  }
}

void CAction::setRegExp(char *P_value) {
  int errorCode;

  M_regularExpression = strdup(P_value);
  M_regExpSet = true;

  errorCode = regcomp(&(M_internalRegExp), M_regularExpression, REGEXP_PARAMS);
  if(errorCode != 0)
  {
    char buffer[MAX_HEADER_LEN];
    regerror(errorCode, &M_internalRegExp, buffer, sizeof(buffer));
    ERROR("recomp error : regular expression '%s' - error '%s'\n", M_regularExpression, buffer);
  }
}

char *CAction::getRegularExpression() {
  if (!M_regExpSet) {
    ERROR("Trying to get a regular expression for an action that does not have one!");
  }
  return M_regularExpression;
}

int CAction::executeRegExp(char* P_string, VariableTable *P_callVarTable)
{
  regmatch_t pmatch[10];
  int error;
  int nbOfMatch = 0;
  char* result = NULL ;

  if (!M_regExpSet) {
    ERROR("Trying to perform regular expression match on action that does not have one!");
  }

  if (getNbSubVarId() > 9) {
    ERROR("You can only have nine sub expressions!");
  }

  memset((void*)pmatch, 0, sizeof(regmatch_t)*10);

  error = regexec(&(M_internalRegExp), P_string, 10, pmatch, REGEXP_PARAMS);
  if ( error == 0) {
    CCallVariable* L_callVar = P_callVarTable->getVar(getVarId());

    for(int i = 0; i <= getNbSubVarId(); i++) {
      if(pmatch[i].rm_eo == -1) break ;

      setSubString(&result, P_string, pmatch[i].rm_so, pmatch[i].rm_eo);
      L_callVar->setMatchingValue(result);

      if (i == getNbSubVarId())
	break ;

      L_callVar = P_callVarTable->getVar(getSubVarId(i));
    }
  }
  return(nbOfMatch);
}

void CAction::setSubString(char** P_target, char* P_source, int P_start, int P_stop)
{
  int sizeOf;

  if(P_source != NULL) {
    sizeOf = P_stop - P_start;
    (*P_target) = new char[sizeOf + 1];

    if (sizeOf > 0) {
      memcpy((*P_target), &(P_source[P_start]), sizeOf);
    }

    (*P_target)[sizeOf] = '\0';
  } else {
    *P_target = NULL ;
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
      ERROR("Cannot read file %s\n", M_pcapArgs->file);
    }
  }
}
#endif

void CAction::setScenario(scenario *     P_scenario) {
  M_scenario = P_scenario;
}

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
  setScenario     ( P_action.M_scenario        );

  setNbSubVarId   ( P_action.getNbSubVarId()   );
  for (L_i = 0; L_i < P_action.getNbSubVarId() ; L_i++ ) {
    setSubVarId (P_action.getSubVarId(L_i));
  }

  setLookingChar  ( P_action.getLookingChar()  );
  setCheckIt      ( P_action.getCheckIt()      );
    setCheckItInverse      ( P_action.getCheckItInverse()      );
  setCaseIndep    ( P_action.getCaseIndep()    ); 
  setOccurence    ( P_action.getOccurence()   );
  setHeadersOnly  ( P_action.getHeadersOnly()  );
  for (L_i = 0; L_i < MAX_ACTION_MESSAGE; L_i++) {
    setMessage(P_action.M_message_str[L_i], L_i);
  }
  setRegExp       ( P_action.M_regularExpression);
  setIntCmd       ( P_action.M_IntCmd          );
#ifdef PCAPPLAY
  setPcapArgs     ( P_action.M_pcapArgs        );
#endif
}

CAction::CAction(scenario *scenario)
{
  M_action       = E_AT_NO_ACTION;
  M_varId        = 0;
  M_varInId        = 0;
  M_varIn2Id        = 0;

  M_nbSubVarId    = 0;
  M_maxNbSubVarId = 0;
  M_subVarId      = NULL;

  M_checkIt      = false;
    M_checkItInverse      = false;
  M_lookingPlace = E_LP_MSG;
  M_lookingChar  = NULL;
  M_caseIndep    = false;
  M_occurence    = 1;
  M_headersOnly  = true;   
  for (int i = 0; i < MAX_ACTION_MESSAGE; i++) {
    M_message[i]   = NULL;
    M_message_str[i] = NULL;
  }
  M_IntCmd       = E_INTCMD_INVALID;
  M_doubleValue  = 0;
  M_stringValue  = NULL;
  M_distribution = NULL;
#ifdef PCAPPLAY
  M_pcapArgs     = NULL;
#endif
  M_scenario     = scenario;
  M_regExpSet    = false;
  M_regularExpression = NULL;
}

CAction::~CAction()
{
  if(M_lookingChar != NULL)
  {
    delete [] M_lookingChar;
    M_lookingChar = NULL;
  }
  for (int i = 0; i < MAX_ACTION_MESSAGE; i++) {
    if(M_message[i] != NULL)
    {
      delete M_message[i];
      M_message[i] = NULL;
    }
    free(M_message_str[i]);
    M_message_str[i] = NULL;
  }
  if(M_subVarId != NULL)
  {
    delete [] M_subVarId;
    M_subVarId      = NULL;
  }
  free(M_stringValue);
#ifdef PCAPPLAY
  if (M_pcapArgs != NULL) {
    free(M_pcapArgs);
    M_pcapArgs = NULL;
  }
#endif
  if (M_regExpSet) {
    regfree(&M_internalRegExp);
    free(M_regularExpression);
  }
  if (M_distribution) {
    delete M_distribution;
  }
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
