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

#ifndef __SIPP_LUASCRIPT_H__
#define __SIPP_LUASCRIPT_H__

#include <string>

#include "variables.hpp"

/* Run the Lua file given with -lua_file. Ends SIPp on an error. */
void lua_script_load(const char *file);

/* <exec lua="function arg ..."/>: call the global Lua function with the
 * arguments, which can read and write the call's variables. Ends SIPp on
 * an error. */
void lua_script_exec(const std::string &command, VariableTable *vars, AllocVariableTable *names);

#endif
