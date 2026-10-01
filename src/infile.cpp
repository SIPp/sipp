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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 *           Charles P. Wright from IBM Research
 */

#include "sipp.hpp"
#include "screen.hpp"
#include "stat.hpp"
#include "infile.hpp"
#include <algorithm>
#include <iostream>
#include <assert.h>

/* Reads the number of a "key=number" entry of an input file's first line.
 * Only the whole key matches: PRINTF is not the start of PRINTFOFFSET. */
static bool get_printf_param(const char *line, const char *key,
                             const char *fileName, unsigned long *value)
{
    size_t len = strlen(key);
    const char *p = line;
    while ((p = strstr(p, key)) && isalnum((unsigned char)p[len])) {
        p += len;
    }
    if (!p) {
        return false;
    }
    p += len;
    if (*p != '=') {
        ERROR("Invalid %s specification (requires =) for %s:%s", key, fileName, line);
    }
    char *endptr;
    *value = strtoul(p + 1, &endptr, 0);
    if (*endptr && *endptr != ',') {
        ERROR("Invalid %s specification (invalid end character '%c') for %s:%s",
              key, *endptr, fileName, line);
    }
    return true;
}

/* Read MAX_CHAR_BUFFER_SIZE size lines from the "fileName" and populate it in
 * the fileContents vector. Each line should be terminated with a '\n'
 */
FileContents::FileContents(const char *fileName)
{
    std::ifstream inFile(fileName);
    int virtualLines = 0;

    if (!inFile.good()) {
        ERROR("Unable to open file %s", fileName);
    }

    this->fileName = fileName;

    realLinesInFile = lineCounter = numLinesInFile = 0;
    /* Initialize printf info. */
    printfFile = false;
    printfOffset = 0;
    printfMultiple = 1;


    std::string lineStr;
    std::getline(inFile, lineStr);
    if (!lineStr.empty() && *lineStr.rbegin() == '\r') {
        lineStr.pop_back();
    }
    const char* line = lineStr.c_str();

    if (nullptr != strstr(line, "RANDOM")) {
        usage = InputFileRandomOrder;
    } else if (nullptr != strstr(line, "SEQUENTIAL")) {
        usage = InputFileSequentialOrder;
    } else if (nullptr != strstr(line, "USER")) {
        usage = InputFileUser;
    } else {
        ERROR("Unknown file type (valid values are RANDOM, SEQUENTIAL, and USER) for %s:%s", fileName, line);
    }

    unsigned long value;
    if (get_printf_param(line, "PRINTF", fileName, &value)) {
        /* We are going to operate in printf mode, which uses the line as a format
         * string for printf with the line number. */
        virtualLines = value;
        if (virtualLines == 0) {
            ERROR("A printf file must have at least one virtual line %s:%s", fileName, line);
        }
        printfFile = true;
    }
    if (get_printf_param(line, "PRINTFOFFSET", fileName, &value)) {
        printfOffset = value;
    }
    if (get_printf_param(line, "PRINTFMULTIPLE", fileName, &value)) {
        printfMultiple = value;
    }

    while (!inFile.eof()) {
        lineStr.clear();
        std::getline(inFile, lineStr);
        if (!lineStr.empty()) {
            if ('#' != lineStr[0]) {
                if(*lineStr.rbegin() == '\r') {
                    lineStr.pop_back();
                }
                fileLines.push_back(lineStr);
                realLinesInFile++; /* this counts number of valid data lines */
            }
        } else {
            break;
        }
    }

    if (realLinesInFile == 0) {
        ERROR("Input file has zero lines: %s", fileName);
    }

    if (printfFile) {
        numLinesInFile = virtualLines;
    } else {
        numLinesInFile = realLinesInFile;
    }

    indexField = -1;
}

const std::string &FileContents::getLine(int line)
{
    if (printfFile) {
        line %= realLinesInFile;
    }
    return fileLines[line];
}

/* Expands a PRINTF injection field: each "%[-][0][width][.precision]d" is
 * replaced by value, and "%%" by "%". The conversion is parsed here and
 * printed with a constant format string, so text from the file is never
 * used as a format. Width and precision are capped, as the output cannot
 * be longer than a message anyway. */
static std::string expand_printf_field(const std::string &field, long long value)
{
    const char *s = field.c_str();
    size_t l = field.length();
    std::string out;
    size_t i = 0;

    while (i < l) {
        if (s[i] != '%') {
            out += s[i++];
            continue;
        }
        if (s[i + 1] == '%') {
            out += '%';
            i += 2;
            continue;
        }

        bool left_align = false, zero_pad = false;
        int width = 0, precision = -1;
        i++;
        while (s[i] == '-' || s[i] == '0') {
            if (s[i] == '-') {
                left_align = true;
            } else {
                zero_pad = true;
            }
            i++;
        }
        while (isdigit((unsigned char)s[i])) {
            width = std::min(width * 10 + (s[i] - '0'), SIPP_MAX_MSG_SIZE);
            i++;
        }
        if (s[i] == '.') {
            precision = 0;
            i++;
            while (isdigit((unsigned char)s[i])) {
                precision = std::min(precision * 10 + (s[i] - '0'), SIPP_MAX_MSG_SIZE);
                i++;
            }
        }
        if (i == l) {
            ERROR("Invalid printf injection field (ran off end of line): %s", s);
        }
        if (s[i] != 'd') {
            ERROR("Invalid printf injection field (only decimal values allowed '%c'): %s", s[i], s);
        }
        i++;

        /* Room for the padding plus the widest long long. */
        std::string piece(std::max(width, precision) + 32, '\0');
        int n;
        if (left_align) {
            if (precision < 0) {
                n = snprintf(&piece[0], piece.size(), "%-*lld", width, value);
            } else {
                n = snprintf(&piece[0], piece.size(), "%-*.*lld", width, precision, value);
            }
        } else if (precision >= 0) {
            n = snprintf(&piece[0], piece.size(), "%*.*lld", width, precision, value);
        } else if (zero_pad) {
            n = snprintf(&piece[0], piece.size(), "%0*lld", width, value);
        } else {
            n = snprintf(&piece[0], piece.size(), "%*lld", width, value);
        }
        if (n > 0) {
            out.append(piece, 0, std::min<size_t>(n, piece.size() - 1));
        }
    }
    return out;
}

std::string FileContents::getField(int lineNum, int field)
{
    int curfield = field;
    int curline = lineNum;

    if (lineNum < 0 || lineNum >= numLinesInFile) {
        return "";
    }

    if (printfFile) {
        curline %= realLinesInFile;
    }
    const std::string & line = fileLines[curline];

    size_t pos(0), oldpos(0);

    do {
        oldpos = pos;
        size_t localpos = line.find(';', oldpos);

        if (localpos != std::string::npos) {
            pos = localpos + 1;
        } else {
            pos = localpos;
            break;
        }

        if (curfield == 0) {
            break;
        }

        curfield --;
    } while (oldpos != std::string::npos);


    if (curfield) {
        WARNING("Field %d not found in the file %s", field, fileName);
        return "";
    }


    if (std::string::npos == oldpos) {
        return "";
    }

    if (std::string::npos != pos) {
        // should not be decremented for fieldN
        pos -= (oldpos + 1);
    }

    std::string x = line.substr(oldpos, pos);
    if (printfFile) {
        long long value = (long long)printfOffset + (long long)lineNum * printfMultiple;
        return expand_printf_field(x, value);
    }
    return x;
}

int FileContents::numLines()
{
    return numLinesInFile;
}

int FileContents::nextLine(int userId, bool advance)
{
    switch(usage) {
    case InputFileRandomOrder:
        return rand() % numLinesInFile;
    case InputFileSequentialOrder: {
        int ret = lineCounter;
        if (advance) {
            lineCounter = (lineCounter + 1) % numLinesInFile;
        }
        return ret;
    }
    case InputFileUser:
        if (userId == 0) {
            return -1;
        }
        if ((userId  - 1) >= numLinesInFile) {
            ERROR("%s has only %d lines, yet user %d was requested.", fileName, numLinesInFile, userId);
        }
        return userId - 1;
    default:
        ERROR("Internal error: unknown file usage mode!");
        return -1;
    }
}

void FileContents::dump(void)
{
    WARNING("Line choosing strategy is [%s]. m_counter [%d] numLinesInFile [%d] realLinesInFile [%d]",
            usage == InputFileSequentialOrder ? "SEQUENTIAL" :
            usage == InputFileRandomOrder ? "RANDOM" :
            usage == InputFileUser ? "USER" : "UNKNOWN",
            lineCounter, numLinesInFile, realLinesInFile);

    for (int i = 0; i < realLinesInFile && fileLines[i][0]; i++) {
        WARNING("%s:%d reads [%s]", fileName, i, fileLines[i].c_str());
    }
}

void FileContents::index(int field)
{
    this->indexField = field;

    indexMap.clear();
    for (int line = 0; line < numLines(); line++) {
        reIndex(line);
    }
}

int FileContents::lookup(const std::string &key)
{
    if (indexField == -1) {
        ERROR("Invalid Index File: %s", fileName);
    }

    str_int_map::iterator index_it = indexMap.find(key);
    if (index_it == indexMap.end()) {
        return -1;
    }
    return index_it->second;
}


void FileContents::insert(const std::string &value)
{
    if (printfFile) {
        ERROR("Can not insert or replace into a printf file: %s", fileName);
    }
    fileLines.push_back(value);
    realLinesInFile++;
    numLinesInFile++;
    if (indexField != -1) {
        reIndex(realLinesInFile - 1);
    }
}

void FileContents::replace(int line, const std::string &value)
{
    if (printfFile) {
        ERROR("Can not insert or replace into a printf file: %s", fileName);
    }
    if (line >= realLinesInFile || line < 0) {
        ERROR("Invalid line number (%d) for file: %s (%d lines)", line, fileName, realLinesInFile);
    }
    deIndex(line);
    fileLines[line] = value;
    reIndex(line);
}

void FileContents::reIndex(int line)
{
    if (indexField == -1) {
        return;
    }
    assert(line >= 0);
    assert(line < realLinesInFile);

    /* The line now has the key, whichever had it before */
    indexMap[getField(line, indexField)] = line;
}

void FileContents::deIndex(int line)
{
    if (indexField == -1) {
        return;
    }
    assert(line >= 0);
    assert(line < realLinesInFile);

    str_int_map::iterator index_it = indexMap.find(getField(line, indexField));
    if (index_it != indexMap.end()) {
        if (index_it->second == line) {
            indexMap.erase(index_it);
        }
    }
}

#ifdef GTEST
#include "gtest/gtest.h"
#include <fstream>

TEST(infile, get_field_is_whole)
{
    std::string path = testing::TempDir() + "sipp_infile_get_field.csv";
    {
        std::ofstream out(path);
        out << "SEQUENTIAL\n"
            << "short;" << std::string(100000, 'x') << ";last\n";
    }
    FileContents contents(path.c_str());

    EXPECT_EQ("short", contents.getField(0, 0));
    EXPECT_EQ(std::string(100000, 'x'), contents.getField(0, 1));
    EXPECT_EQ("last", contents.getField(0, 2));
    EXPECT_EQ("", contents.getField(1, 0));

    remove(path.c_str());
}

TEST(infile, printf_get_field_is_whole)
{
    std::string path = testing::TempDir() + "sipp_infile_printf_get_field.csv";
    {
        std::ofstream out(path);
        out << "SEQUENTIAL,PRINTF=10\n"
            << "user%010d" << std::string(100, 'y') << ";\n";
    }
    FileContents contents(path.c_str());

    EXPECT_EQ("user0000000003" + std::string(100, 'y'), contents.getField(3, 0));

    remove(path.c_str());
}

TEST(infile, index)
{
    std::string path = testing::TempDir() + "sipp_infile_index.csv";
    {
        std::ofstream out(path);
        out << "SEQUENTIAL\n"
            << "alice;1;\n"
            << "bob;2;\n";
    }
    FileContents contents(path.c_str());

    EXPECT_DEATH(contents.lookup("bob"), "Invalid Index File: ");
    contents.index(0);
    EXPECT_EQ(1, contents.lookup("bob"));
    EXPECT_EQ(-1, contents.lookup("carol"));
    contents.insert("carol;3;");
    EXPECT_EQ(2, contents.lookup("carol"));
    EXPECT_EQ("carol;3;", contents.getLine(2));
    contents.replace(0, "dave;4;");
    EXPECT_EQ(-1, contents.lookup("alice"));
    EXPECT_EQ(0, contents.lookup("dave"));
    /* Indexing again starts over */
    contents.index(1);
    EXPECT_EQ(-1, contents.lookup("dave"));
    EXPECT_EQ(1, contents.lookup("2"));

    remove(path.c_str());
}

TEST(infile, printf_get_field_matches_printf) {
    /* Each field uses one of the accepted conversion forms; the result
     * must be what printf() itself produces for the line number. */
    static const char *const specs[] = {
        "%d", "%5d", "%-5d", "%05d", "%.3d", "%8.3d", "%-8.3d", "%-05d",
        "50%%", "%%%d",
    };
    std::string path = testing::TempDir() + "sipp_infile_printf_matches.csv";
    {
        std::ofstream out(path);
        out << "SEQUENTIAL,PRINTF=100,PRINTFOFFSET=1000\n";
        for (const char *spec : specs) {
            out << "<" << spec << ">;";
        }
        out << "\n";
    }
    FileContents contents(path.c_str());

    for (int field = 0; field < (int)(sizeof(specs) / sizeof(specs[0])); field++) {
        char expected[64];
        std::string fmt = std::string("<") + specs[field] + ">";
        snprintf(expected, sizeof(expected), fmt.c_str(), 1042);

        EXPECT_EQ(expected, contents.getField(42, field)) << "spec " << specs[field];
    }

    remove(path.c_str());
}

TEST(infile, printf_keys_match_whole) {
    /* PRINTF is not the start of PRINTFOFFSET or PRINTFMULTIPLE, in any
     * order. */
    std::string path = testing::TempDir() + "sipp_infile_printf_keys.csv";
    {
        std::ofstream out(path);
        out << "SEQUENTIAL,PRINTFMULTIPLE=2,PRINTFOFFSET=100,PRINTF=10\n"
            << "user%d;\n";
    }
    FileContents contents(path.c_str());

    EXPECT_EQ(10, contents.numLines());
    EXPECT_EQ("user106", contents.getField(3, 0));

    {
        std::ofstream out(path);
        out << "SEQUENTIAL,PRINTF=10,PRINTFMULTIPLE=2x\n"
            << "user%d;\n";
    }
    EXPECT_DEATH(FileContents bad(path.c_str()),
                 "Invalid PRINTFMULTIPLE specification \\(invalid end character 'x'\\) for ");

    remove(path.c_str());
}
#endif
