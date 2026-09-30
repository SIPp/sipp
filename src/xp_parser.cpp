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
 *  Copyright (C) 2003 - The Authors
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <pugixml.hpp>

#include "xp_parser.h"

static pugi::xml_document xp_doc;
static std::vector<pugi::xml_node> xp_stack;
static std::string xp_value_buffer;
static std::string xp_cdata_buffer;
static char xp_elem_name[256];
static int xp_invalid_line = 0;

static std::string xp_error;

/* pugi::parse_ws_pcdata preserves whitespace in text nodes (CDATA).
 * pugi::parse_declaration skips <?xml ...?> declarations. */
static const unsigned int xp_flags = pugi::parse_default |
                                     pugi::parse_ws_pcdata |
                                     pugi::parse_declaration;

/* Deep enough for any real scenario, low enough to stop a loop. */
#define XP_MAX_INCLUDE_DEPTH 16

static bool xp_expand_includes(pugi::xml_node node, const std::string &dir,
                               int depth);

/* Replace <xi:include href="file"/> with the content of file: the
 * children of its <scenario> root, or else its root element. */
static bool xp_include(pugi::xml_node include, const std::string &dir,
                       int depth)
{
    const char *href = include.attribute("href").value();
    if (!*href) {
        xp_error = "<xi:include> without an href";
        return false;
    }

    std::string path = href[0] == '/' ? href : dir + href;
    if (depth >= XP_MAX_INCLUDE_DEPTH) {
        xp_error = "cannot include '" + path + "': more than " +
                   std::to_string(XP_MAX_INCLUDE_DEPTH) + " nested includes";
        return false;
    }

    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file(path.c_str(), xp_flags);
    if (!result) {
        xp_error = "cannot include '" + path + "': " + result.description();
        return false;
    }

    size_t slash = path.rfind('/');
    std::string included_dir = slash == std::string::npos ? "" :
                               path.substr(0, slash + 1);
    if (!xp_expand_includes(doc, included_dir, depth + 1))
        return false;

    pugi::xml_node parent = include.parent();
    pugi::xml_node root = doc.document_element();
    if (!strcmp(root.name(), "scenario")) {
        for (pugi::xml_node child = root.first_child(); child;
             child = child.next_sibling()) {
            parent.insert_copy_before(child, include);
        }
    } else {
        parent.insert_copy_before(root, include);
    }
    parent.remove_child(include);
    return true;
}

static bool xp_expand_includes(pugi::xml_node node, const std::string &dir,
                               int depth)
{
    pugi::xml_node child = node.first_child();
    while (child) {
        pugi::xml_node next = child.next_sibling();
        if (!strcmp(child.name(), "xi:include")) {
            if (!xp_include(child, dir, depth))
                return false;
        } else if (!xp_expand_includes(child, dir, depth)) {
            return false;
        }
        child = next;
    }
    return true;
}

/* Expand the includes of the loaded document, relative to dir. */
static bool xp_loaded(const std::string &dir)
{
    if (!xp_expand_includes(xp_doc, dir, 0))
        return false;

    /* Push the document root so xp_open_element(0) finds the first element */
    xp_stack.push_back(xp_doc);
    return true;
}

static bool xp_load(const char *xml_text)
{
    xp_stack.clear();
    xp_invalid_line = 0;
    xp_error.clear();

    pugi::xml_parse_result result = xp_doc.load_string(xml_text, xp_flags);

    if (!result) {
        /* Compute line number from byte offset */
        int line = 1;
        for (ptrdiff_t i = 0; i < result.offset && xml_text[i]; ++i) {
            if (xml_text[i] == '\n')
                ++line;
        }
        xp_invalid_line = line;
        return false;
    }

    return xp_loaded("");
}

int xp_set_xml_buffer_from_string(const char *str)
{
    if (!str || !*str)
        return 0;

    return xp_load(str) ? 1 : 0;
}

int xp_set_xml_buffer_from_file(const char *filename)
{
    xp_stack.clear();
    xp_invalid_line = 0;
    xp_error.clear();

    pugi::xml_parse_result result = xp_doc.load_file(filename, xp_flags);

    if (!result) {
        xp_invalid_line = result.offset > 0 ? 1 : 0;
        return 0;
    }

    const char *slash = strrchr(filename, '/');
    return xp_loaded(slash ? std::string(filename, slash + 1 - filename) : "");
}

const char *xp_get_error(void)
{
    return xp_error.c_str();
}

/* Process backslash escapes in attribute values for backward compatibility.
 * The old parser handled: \\, \", \n, \t, \r */
static const char *xp_process_escapes(const char *input)
{
    xp_value_buffer.clear();
    xp_value_buffer.reserve(strlen(input));

    const char *p = input;
    while (*p) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
            case '\\': xp_value_buffer += '\\'; break;
            case '"':  xp_value_buffer += '"';  break;
            case 'n':  xp_value_buffer += '\n'; break;
            case 't':  xp_value_buffer += '\t'; break;
            case 'r':  xp_value_buffer += '\r'; break;
            default:
                xp_value_buffer += '\\';
                xp_value_buffer += *p;
                break;
            }
        } else {
            xp_value_buffer += *p;
        }
        p++;
    }

    return xp_value_buffer.c_str();
}

char *xp_open_element(int index)
{
    if (xp_stack.empty())
        return nullptr;

    pugi::xml_node parent = xp_stack.back();
    int i = 0;

    for (pugi::xml_node child = parent.first_child(); child;
         child = child.next_sibling()) {
        if (child.type() != pugi::node_element)
            continue;
        if (i == index) {
            xp_stack.push_back(child);
            strncpy(xp_elem_name, child.name(), sizeof(xp_elem_name) - 1);
            xp_elem_name[sizeof(xp_elem_name) - 1] = '\0';
            return xp_elem_name;
        }
        ++i;
    }

    return nullptr;
}

void xp_close_element()
{
    if (xp_stack.size() <= 1) {
        xp_invalid_line = -1;
        return;
    }
    xp_stack.pop_back();
}

int xp_is_invalid(void)
{
    return xp_invalid_line != 0;
}

int xp_get_invalid_line(void)
{
    return xp_invalid_line;
}

const char *xp_get_value(const char *name)
{
    if (xp_stack.empty())
        return nullptr;

    pugi::xml_node node = xp_stack.back();
    pugi::xml_attribute attr = node.attribute(name);

    if (!attr)
        return nullptr;

    return xp_process_escapes(attr.value());
}

char *xp_get_cdata(void)
{
    if (xp_stack.empty())
        return nullptr;

    pugi::xml_node node = xp_stack.back();

    for (pugi::xml_node child = node.first_child(); child;
         child = child.next_sibling()) {
        if (child.type() == pugi::node_cdata) {
            xp_cdata_buffer = child.value();
            return const_cast<char *>(xp_cdata_buffer.c_str());
        }
    }

    return nullptr;
}
