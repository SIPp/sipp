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
    } else if (M_type == E_VT_DOUBLE) {
        return M_double;
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
    free(M_stringValue);
    M_stringValue     = P_val;
}

char *CCallVariable::getString()
{
    if (M_type == E_VT_STRING) {
        return(M_stringValue);
    } else if (M_type == E_VT_REGEXP && M_matchingValue) {
        return(M_matchingValue);
    } else {
        return const_cast<char*>(""); /* BUG BUT NOT SO SERIOUS */
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
    free(M_stringValue);
}

#define LEVEL_BITS 8

VariableTable::VariableTable(VariableTable *parent, int size)
{
    if (parent) {
        level = parent->level + 1;
        assert(level < (1 << LEVEL_BITS));
        this->parent = parent->getTable();
    } else {
        level = 0;
        this->parent = NULL;
    }

    count = 1;
    this->size = size;
    if (size == 0) {
        variableTable = NULL;
        return;
    }
    variableTable = (CCallVariable **)malloc(size * sizeof(CCallVariable *));
    if (!variableTable) {
        ERROR("Could not allocate variable table!");
    }
    for (int i = 0; i < size; i++) {
        variableTable[i] = new CCallVariable();
        if (variableTable[i] == NULL) {
            ERROR ("Call variable allocation failed");
        }
    }
}

VariableTable::VariableTable(AllocVariableTable *src)
{
    count = 1;
    this->level = src->level;
    if (src->parent) {
        this->parent = src->parent->getTable();
    } else {
        this->parent = NULL;
    }
    if (level > 0) {
        assert(this->parent);
    }
    this->size = src->size;
    if (size == 0) {
        variableTable = NULL;
        return;
    }

    variableTable = (CCallVariable **)malloc(size * sizeof(CCallVariable *));
    if (!variableTable) {
        ERROR("Could not allocate variable table!");
    }

    for (int i = 0; i < size; i++) {
        variableTable[i] = new CCallVariable();
        if (variableTable[i] == NULL) {
            ERROR ("Call variable allocation failed");
        }
    }
}

void VariableTable::expand(int size)
{
    assert(size > this->size);
    if (size == this->size) {
        return;
    }

    variableTable = (CCallVariable **)realloc(variableTable, size * sizeof(CCallVariable *));
    if (!variableTable) {
        ERROR("Could not expand variable table!");
    }

    for (int i = this->size; i < size; i++) {
        variableTable[i] = new CCallVariable();
        if (variableTable[i] == NULL) {
            ERROR ("Call variable allocation failed");
        }
    }

    this->size = size;
}

VariableTable::~VariableTable()
{
    if (parent) {
        parent->putTable();
    }
    for (int i = 0; i < size; i++) {
        delete variableTable[i];
    }
    free(variableTable);
}

VariableTable *VariableTable::getTable()
{
    count++;
    return this;
}

void VariableTable::putTable()
{
    if (--count == 0) {
        delete this;
    }
}

CCallVariable *VariableTable::getVar(int i)
{
    int thisLevel  = i & ((1 << LEVEL_BITS) - 1);
    assert(thisLevel <= level);
    if (thisLevel == level) {
        i = i >> LEVEL_BITS;
        assert(i > 0);
        assert(i <= size );
        return variableTable[i - 1];
    }
    assert(parent);
    return parent->getVar(i);
}

AllocVariableTable::AllocVariableTable(AllocVariableTable *av_parent) : VariableTable((VariableTable *)av_parent, 0)
{
    this->av_parent = av_parent;
}

AllocVariableTable::~AllocVariableTable()
{
    clear_str_int(variableMap);
    clear_int_str(variableRevMap);
    clear_int_int(variableReferences);
}

int AllocVariableTable::find(const char *varName, bool allocate)
{
    /* If this variable has already been used, then we have nothing to do. */
    str_int_map::iterator var_it = variableMap.find(varName);
    if (var_it != variableMap.end()) {
        variableReferences[var_it->second]++;
        return var_it->second;
    }
    if (av_parent) {
        int ret = av_parent->find(varName, false);
        if (ret > 0) {
            return ret;
        }
    }

    if (allocate) {
        int varNum = size + 1;
        expand(varNum);
        varNum = (varNum << LEVEL_BITS) | level;
        variableMap[varName] = varNum;
        variableReferences[varNum] = 1;
        variableRevMap[varNum] = strdup(varName);
        return varNum;
    }

    return -1;
}

char *AllocVariableTable::getName(int i)
{
    int thisLevel  = i & ((1 << LEVEL_BITS) - 1);
    assert(thisLevel <= level);
    if (thisLevel == level) {
        return variableRevMap[i];
    }
    assert(av_parent);
    return av_parent->getName(i);
}

void AllocVariableTable::dump()
{
    if (av_parent) {
        av_parent->dump();
    }
    WARNING("%zu level %d variables:", variableMap.size(), level);
    for (str_int_map::iterator i = variableMap.begin(); i != variableMap.end(); i++) {
        WARNING("%s", i->first.c_str());
    }
}

void AllocVariableTable::validate()
{
    for (str_int_map::iterator var_it = variableMap.begin(); var_it != variableMap.end(); var_it++) {
        if (variableReferences[var_it->second] < 2) {
            const char *varName = var_it->first.c_str();
            int varRef = variableReferences[var_it->second];
            if (strcmp(varName, "_") != 0) {
                ERROR("Variable $%s is referenced %d times!\n", varName, varRef);
            }
        }
    }
    if (av_parent) {
        av_parent->validate();
    }
}
