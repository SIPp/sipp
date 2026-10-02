/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Lua scripting for scenarios, after the idea of pull request #577 by
 * Nathan Franzmeier (nfranzmeier).
 */

#include <sstream>

#include "luascript.hpp"
#include "logger.hpp"

#ifdef USE_LUA

#include <lua.hpp>

static lua_State *L;
/* The variables of the call that runs a function, for sipp.get/set */
static VariableTable *call_vars;
static AllocVariableTable *var_names;

static CCallVariable *find_var(lua_State *state)
{
    const char *name = luaL_checkstring(state, 1);
    int id = var_names->find(name, false);
    if (id < 0 || !call_vars) {
        luaL_error(state, "unknown SIPp variable '%s'", name);
    }
    return call_vars->getVar(id);
}

/* sipp.get(name): the variable's value, or nil if it has none */
static int sipp_get(lua_State *state)
{
    CCallVariable *var = find_var(state);
    if (var->isDouble()) {
        lua_pushnumber(state, var->getDouble());
    } else if (var->isBool()) {
        lua_pushboolean(state, var->getBool());
    } else if (var->isString() || var->isSet()) {
        lua_pushstring(state, var->isString() ? var->getString() : var->getMatchingValue());
    } else {
        lua_pushnil(state);
    }
    return 1;
}

/* sipp.set(name, value): value is a string, a number or a boolean */
static int sipp_set(lua_State *state)
{
    CCallVariable *var = find_var(state);
    switch (lua_type(state, 2)) {
    case LUA_TSTRING:
        var->setString(lua_tostring(state, 2));
        break;
    case LUA_TNUMBER:
        var->setDouble(lua_tonumber(state, 2));
        break;
    case LUA_TBOOLEAN:
        var->setBool(lua_toboolean(state, 2));
        break;
    default:
        luaL_error(state, "SIPp variables hold a string, a number or a boolean");
    }
    return 0;
}

/* sipp.log(message): to the -trace_logs file, as <log> does. print()
 * would write over SIPp's screen. */
static int sipp_log(lua_State *state)
{
    LOG_MSG("%s\n", luaL_checkstring(state, 1));
    return 0;
}

static void lua_script_init()
{
    L = luaL_newstate();
    if (!L) {
        ERROR("Could not create a Lua state");
    }
    luaL_openlibs(L);
    lua_newtable(L);
    lua_pushcfunction(L, sipp_get);
    lua_setfield(L, -2, "get");
    lua_pushcfunction(L, sipp_set);
    lua_setfield(L, -2, "set");
    lua_pushcfunction(L, sipp_log);
    lua_setfield(L, -2, "log");
    lua_setglobal(L, "sipp");
}

void lua_script_load(const char *file)
{
    if (!L) {
        lua_script_init();
    }
    if (luaL_dofile(L, file)) {
        ERROR("Lua file %s: %s", file, lua_tostring(L, -1));
    }
}

void lua_script_exec(const std::string &command, VariableTable *vars, AllocVariableTable *names)
{
    std::istringstream words(command);
    std::string function;
    words >> function;
    if (!L || function.empty()) {
        ERROR("<exec lua=\"%s\"> needs a function name, and a Lua file with it given with -lua_file", command.c_str());
    }

    lua_getglobal(L, function.c_str());
    if (!lua_isfunction(L, -1)) {
        ERROR("Lua function %s is not defined", function.c_str());
    }
    int args = 0;
    for (std::string arg; words >> arg; args++) {
        lua_pushstring(L, arg.c_str());
    }

    call_vars = vars;
    var_names = names;
    int ret = lua_pcall(L, args, 0, 0);
    call_vars = nullptr;
    var_names = nullptr;
    if (ret) {
        ERROR("Lua function %s: %s", function.c_str(), lua_tostring(L, -1));
    }
}

#else

void lua_script_load(const char *)
{
    ERROR("-lua_file given, but this version of SIPp does not have Lua support");
}

void lua_script_exec(const std::string &, VariableTable *, AllocVariableTable *)
{
    ERROR("Scenario specifies a lua action, but this version of SIPp does not have Lua support");
}

#endif
