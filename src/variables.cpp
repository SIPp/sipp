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

void CCallVariable::setMatchingValue(std::string_view P_matchingVal)
{
    M_type = E_VT_REGEXP;
    assign_exact(M_value, P_matchingVal.data(), P_matchingVal.size());
    M_nbOfMatchingValue++;
}

const char *CCallVariable::getMatchingValue()
{
    if (M_type != E_VT_REGEXP) {
        return nullptr;
    }
    return M_value.c_str();
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

void CCallVariable::setString(std::string P_val)
{
    M_type = E_VT_STRING;
    P_val.resize(strlen(P_val.c_str()));
    /* Kept in a buffer of about its size */
    if (P_val.capacity() < P_val.size() + 32) {
        M_value = std::move(P_val);
    } else {
        assign_exact(M_value, P_val.data(), P_val.size());
    }
}

const char *CCallVariable::getString()
{
    if (M_type == E_VT_STRING || M_type == E_VT_REGEXP) {
        return M_value.c_str();
    }
    return ""; /* BUG BUT NOT SO SERIOUS */
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
        *newValue = strtod(M_value.c_str(), &p);
        if (p == M_value.c_str() || *p) {
            return false;
        }
        break;
    case E_VT_STRING:
        *newValue = strtod(M_value.c_str(), &p);
        if (p == M_value.c_str() || *p) {
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

// Constructor
CCallVariable::CCallVariable()
{
    M_nbOfMatchingValue = 0;
    M_double = 0;
    M_type = E_VT_UNDEFINED;
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
        this->parent = nullptr;
    }

    count = 1;
    this->size = size;
    if (size == 0) {
        return;
    }
    variableTable.resize(size);
    for (int i = 0; i < size; i++) {
        variableTable[i] = new CCallVariable();
    }
}

VariableTable::VariableTable(AllocVariableTable *src)
{
    count = 1;
    this->level = src->level;
    if (src->parent) {
        this->parent = src->parent->getTable();
    } else {
        this->parent = nullptr;
    }
    if (level > 0) {
        assert(this->parent);
    }
    this->size = src->size;
    if (size == 0) {
        return;
    }

    variableTable.resize(size);
    for (int i = 0; i < size; i++) {
        variableTable[i] = new CCallVariable();
    }
}

void VariableTable::expand(int size)
{
    assert(size > this->size);
    if (size == this->size) {
        return;
    }

    variableTable.resize(size);

    for (int i = this->size; i < size; i++) {
        variableTable[i] = new CCallVariable();
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
        variableRevMap[varNum] = varName;
        return varNum;
    }

    return -1;
}

const char *AllocVariableTable::getName(int i)
{
    int thisLevel  = i & ((1 << LEVEL_BITS) - 1);
    assert(thisLevel <= level);
    if (thisLevel == level) {
        return variableRevMap[i].c_str();
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
                ERROR("Variable $%s is referenced %d times!", varName, varRef);
            }
        }
    }
    if (av_parent) {
        av_parent->validate();
    }
}
