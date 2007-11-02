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

#include "sipp.hpp"

/*
__________________________________________________________________________

              C L A S S    C C a l l V a r i a b l e
__________________________________________________________________________
*/

bool CCallVariable::isSet()
{
  if (M_type == E_VT_REGEXP) {
    if(M_nbOfMatchingValue >= 1)
      return(true);
    else
      return(false);
  } else if (M_type == E_VT_BOOL) {
    return M_bool;
  }
  return (M_type != E_VT_UNDEFINED);
}

bool CCallVariable::isDouble()
{
  return (M_type == E_VT_DOUBLE);
}

bool CCallVariable::isBool()
{
  return (M_type == E_VT_BOOL);
}

bool CCallVariable::isRegExp()
{
  return (M_type == E_VT_REGEXP);
}

bool CCallVariable::isString()
{
  return (M_type == E_VT_STRING);
}

// WARNING : setMatchingValue does't allocate the memory for the matching value
// but the destructor free the memory
void CCallVariable::setMatchingValue(char* P_matchingVal)
{
  M_type = E_VT_REGEXP;
  if(M_matchingValue != NULL) {
    delete [] M_matchingValue;    
  }
  M_matchingValue     = P_matchingVal;
  M_nbOfMatchingValue++;
}

char* CCallVariable::getMatchingValue()
{
  if (M_type != E_VT_REGEXP) {
    return NULL;
  }
  return(M_matchingValue);
}

void CCallVariable::setDouble(double val)
{
  M_type = E_VT_DOUBLE;
  M_double = val;
}

double CCallVariable::getDouble()
{
  if (M_type != E_VT_DOUBLE) {
    return 0.0;
  }
  return(M_double);
}

void CCallVariable::setString(char *P_val)
{
  M_type = E_VT_STRING;
  if(M_stringValue != NULL) {
    delete [] M_stringValue;
  }
  M_stringValue     = P_val;
}

char *CCallVariable::getString()
{
  if (M_type == E_VT_STRING) {
    return(M_stringValue);
  } else if (M_type == E_VT_REGEXP && M_matchingValue) {
    return(M_matchingValue);
  } else {
    return "";
  }
}

/* Convert this variable to a double. Returns true on success, false on failure. */
bool CCallVariable::toDouble(double *newValue)
{
  char *p;

  switch(M_type) {
  case E_VT_REGEXP:
    if(M_nbOfMatchingValue < 1) {
      return false;
    }
    *newValue = strtod(M_matchingValue, &p);
    if (*p) {
      return false;
    }
    break;
  case E_VT_STRING:
    *newValue = strtod(M_stringValue, &p);
    if (*p) {
      return false;
    }
    break;
  case E_VT_DOUBLE:
    *newValue = getDouble();
    break;
  case E_VT_BOOL:
    *newValue = (double)getBool();
    break;
  default:
    return false;
  }
  return true;
}

void CCallVariable::setBool(bool val)
{
  M_type = E_VT_BOOL;
  M_bool = val;
}

bool CCallVariable::getBool()
{
  if (M_type != E_VT_BOOL) {
    return false;
  }
  return(M_bool);
}

// Constuctor and destructor
CCallVariable::CCallVariable()
{
  M_matchingValue     = NULL;
  M_stringValue     = NULL;
  M_nbOfMatchingValue = 0;
  M_type = E_VT_UNDEFINED;
}

CCallVariable::~CCallVariable()
{
  if(M_matchingValue != NULL) {
    delete [] M_matchingValue;
  }
  M_matchingValue = NULL;
  if(M_stringValue != NULL) {
    delete [] M_stringValue;
  }
}

/*
__________________________________________________________________________

              C L A S S    C V a r i a b l e
__________________________________________________________________________
*/

bool CVariable::matchRegularExpression(char* P_string)
{
  if(M_regExpWellFormed) {
    if(regexec(&(M_internalRegExp), P_string, 0, NULL, 0) == 0) {
      return(true);
    } else {
      return(false);
    }
  } else {
    return(false);
  }
}

void CVariable::setSubString(char** P_target, char* P_source, int P_start, int P_stop)
{
  int sizeOf;
  int sourceLength;
  size_t L_size = 0;

  if(P_source != NULL) {
    sizeOf = P_stop - P_start;
    if(sizeOf > 0) {
      L_size = (size_t) sizeOf;
      L_size += 1;
      (*P_target) = new char[L_size];
      sourceLength = strlen(P_source);
     
      memcpy((*P_target), &(P_source[P_start]), sizeOf);

      (*P_target)[sizeOf] = '\0';
	 }
  } else {
    *P_target = NULL ;
  }
}


int CVariable::executeRegExp(char* P_string, 
                             CCallVariable** P_callVarTable,
                	     int  P_varId,
			     int  P_nbSubVar,
                             int  * P_subVarIdTable)
{
   regmatch_t pmatch[10];
  int error;
   int nbOfMatch = 0;
   int L_i ;
   CCallVariable* L_callVar ;
   char* result = NULL ;
   int   L_currentSubIdx = 0 ;


   memset((void*)pmatch, 0, sizeof(regmatch_t)*10);

  if(M_regExpWellFormed) {
     error = regexec(&(M_internalRegExp), P_string, 10, pmatch, REGEXP_PARAMS);
     if ( error == 0) {
        L_callVar = P_callVarTable[P_varId] ;
        for(L_i=0; L_i < 10; L_i++) {
          if(pmatch[L_i].rm_eo == -1) break ;
 	  setSubString(&result, P_string, 
                       pmatch[L_i].rm_so, pmatch[L_i].rm_eo);
          L_callVar->setMatchingValue(result);
          if (L_currentSubIdx == P_nbSubVar) break ;
          L_callVar = P_callVarTable[P_subVarIdTable[L_currentSubIdx]] ;
	  L_currentSubIdx ++ ;

	  /* 
            printf(" the pmatch %d %d  \n", L_i, pmatch[L_i].rm_eo);
            printf(" the pmatch %d %d  \n", L_i, pmatch[L_i].rm_so);
            int L_k ;

            for(L_k = pmatch[L_i].rm_so; L_k <= pmatch[L_i].rm_eo; L_k++) {
                    printf("%c", P_string[L_k]);
            }
            printf("\n");
          */

		}
	 }
  }
  return(nbOfMatch);

}

bool CVariable::extractAllMatchedExpression(char* P_string, 
                                            char *** P_result, 
                                            int* P_number)
{
  regmatch_t pmatch;
  int error;
  char tmpTab[MAX_MATCHING_EXPR][BUFFER_SIZE];
  char* strBuff;
  int currentStop;
  int maxLength;
  
  if(M_regExpWellFormed) {

    currentStop = 0;
    maxLength = strlen(P_string);
    error = regexec(&(M_internalRegExp), P_string, 1, &pmatch, REGEXP_PARAMS);
    (*P_number) = 0;

    while(error == 0) {
      setSubString(&strBuff, P_string+currentStop, 
                   pmatch.rm_so, pmatch.rm_eo);
      if (strlen(strBuff) > BUFFER_SIZE) {
        ERROR_P2("Regular expression match size (%zu) is bigger than buffer size (%d). Change BUFFER_SIZE in call.hpp and recompile SIPp.", strlen(strBuff), BUFFER_SIZE);
      }
      strcpy(tmpTab[(*P_number)], strBuff);
      delete(strBuff);
      (*P_number)++;
      currentStop += pmatch.rm_eo;
      if((currentStop >= maxLength) || ((*P_number) >= MAX_MATCHING_EXPR))
        break;
      error = regexec(&(M_internalRegExp), 
                      P_string+currentStop, 1, 
                      &pmatch, REGEXP_PARAMS);
      if(pmatch.rm_eo == pmatch.rm_so)
        break;
    }
    if((*P_number) > 0) {
      (*P_result) = (char**) malloc(sizeof(char*)*(*P_number));
      for(int i=0; i<(*P_number); i++)
        {
          (*P_result)[i] = (char*) malloc(sizeof(char)*(maxLength+1));
          strcpy((*P_result)[i], tmpTab[i]);
        }
      return(true);
    } else {
      return(false);
    }
  } else {
    return(false);
  }
}

// selecteur et accesseur
bool CVariable::isRegExpWellFormed()
{
  return(M_regExpWellFormed);
}

char* CVariable::getRegularExpression()
{
  return(M_regularExpression);
}


// Constuctor and destructor
CVariable::CVariable(char* P_regularExpression)
{
  int sizeOf;
  int errorCode;

  if(P_regularExpression != NULL)
  {
    sizeOf = strlen(P_regularExpression);
    M_regularExpression = new char[sizeOf+1];
    strcpy(M_regularExpression, P_regularExpression);
  }

  // we must call regcomp to avoid a coredump on the regfree. Even if the char* P_regularExpression is null
  errorCode = regcomp(&(M_internalRegExp), M_regularExpression, REGEXP_PARAMS);
  if(errorCode != 0)
  {
    /* regerror(errorCode, &M_internalRegExp, buffer, sizeof(buffer));
       printf("recomp error : regular expression '%s' - error '%s'\n", 
                  M_regularExpression, 
                  buffer); */
    M_regExpWellFormed = false;
   }
   else
   {
     M_regExpWellFormed = true;
   }
}

CVariable::~CVariable()
{
  if(M_regularExpression != NULL)
    delete [] M_regularExpression;
  M_regularExpression = NULL;

  regfree(&(M_internalRegExp)); 
}
