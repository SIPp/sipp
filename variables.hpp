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

#ifndef _CVARIABLE
#define _CVARIABLE

#include <sys/types.h>
#include <regex.h>

#define SCEN_MAX_MESSAGES  500

#define BUFFER_SIZE 512
#define MAX_MATCHING_EXPR 50
#define REGEXP_PARAMS REG_EXTENDED

enum T_VarType
{
  E_VT_REGEXP = 0,
  E_VT_DOUBLE,
  E_VT_BOOL,
  E_VT_STRING,
  E_VT_UNDEFINED
};

class CCallVariable
{
public:
  bool isSet();
  bool isDouble();
  bool isBool();
  bool isRegExp();
  bool isString();

  // WARNING : setMatchingValue does't allocate the memory for the matching value
  // but the destructor free the memory
  void setMatchingValue(char* P_matchingValue);
  char* getMatchingValue();

  /* When the variable is used for a string, these functions should be called. */
  // WARNING : setString does't allocate the memory for the matching value
  // but the destructor free the memory
  void setString(char *s);
  char *getString();

  /* When the variable is used for a double, these functions should be called. */
  void setDouble(double val);
  double getDouble();

  /* When the variable is used for a bool, these functions should be called. */
  void setBool(bool val);
  bool getBool();

  /* Cast this to a double variable, return the result in newValue. */
  bool toDouble(double *newValue);

  // constructor and destructor
  CCallVariable();
  ~CCallVariable();

private:
  T_VarType	M_type;
  char*		M_matchingValue;
  int		M_nbOfMatchingValue;
  double	M_double;
  char*		M_stringValue;
  bool		M_bool;
};

/**
 * This class provides some means to store the global regexp
 ***/

class CVariable
{
public:

  enum E_CallVariableAction
  {
    E_CV_CHECK,
    E_CV_STORE /* TODO : define list of actions */
  };

  bool matchRegularExpression(char* P_string);
  bool extractAllMatchedExpression(char* P_String, char *** P_Result, int* P_number);

  int executeRegExp(char* P_string, 
                    CCallVariable** P_callVarTable,
                    int  P_varId,
                    int  P_nbSubVar,
                    int  * P_subVarIdTable);

  bool isRegExpWellFormed();
  char* getRegularExpression();

  // constructor and destructor
  CVariable(char* P_RegularExpression);
  ~CVariable();

private:
  
  char*    M_regularExpression;
  regex_t  M_internalRegExp;
  bool     M_regExpWellFormed;
  void setSubString(char** P_target, char* P_source, int start, int stop);
}; 

#endif
