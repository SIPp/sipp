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
 *	     Charles P. Wright from IBM Research
 */

#include "sipp.hpp"
#include "screen.hpp"
#include "stat.hpp"
#include "infile.hpp"
#include <iostream>
#include <assert.h>

/* Read MAX_CHAR_BUFFER_SIZE size lines from the "fileName" and populate it in
 * the fileContents vector. Each line should be terminated with a '\n'
 */
FileContents::FileContents(const char *fileName)
{
    ifstream *inFile    = new ifstream(fileName);
    char      line[MAX_CHAR_BUFFER_SIZE];
    int virtualLines = 0;

    if (!inFile->good()) {
        ERROR("Unable to open file %s", fileName);
    }

    this->fileName = fileName;

    realLinesInFile = lineCounter = numLinesInFile = 0;
    /* Initialize printf info. */
    printfFile = false;
    printfOffset = 0;
    printfMultiple = 1;


    line[0] = '\0';
    inFile->getline(line, MAX_CHAR_BUFFER_SIZE);

    if (NULL != strstr(line, "RANDOM")) {
        usage = InputFileRandomOrder;
    } else if (NULL != strstr(line, "SEQUENTIAL")) {
        usage = InputFileSequentialOrder;
    } else if (NULL != strstr(line, "USER")) {
        usage = InputFileUser;
    } else {
        ERROR("Unknown file type (valid values are RANDOM, SEQUENTIAL, and USER) for %s:%s\n", fileName, line);
    }

    char *useprintf;
    if ((useprintf = strstr(line, "PRINTF"))) {
        /* We are going to operate in printf mode, which uses the line as a format
         * string for printf with the line number. */
        useprintf += strlen("PRINTF");
        if (*useprintf != '=') {
            ERROR("Invalid file printf specification (requires =) for %s:%s\n", fileName, line);
        }
        useprintf++;
        char *endptr;
        virtualLines = strtoul(useprintf, &endptr, 0);
        if (*endptr && *endptr != '\r' && *endptr != '\n' && *endptr != ',') {
            ERROR("Invalid file printf specification for (invalid end character '%c') %s:%s\n", *endptr, fileName, line);
        }
        if (virtualLines == 0) {
            ERROR("A printf file must have at least one virtual line %s:%s\n", fileName, line);
        }
        printfFile = true;
    }

    if ((useprintf = strstr(line, "PRINTFOFFSET"))) {
        useprintf += strlen("PRINTFOFFSET");
        if (*useprintf != '=') {
            ERROR("Invalid file PRINTFOFFSET specification (requires =) for %s:%s\n", fileName, line);
        }
        useprintf++;
        char *endptr;
        printfOffset = strtoul(useprintf, &endptr, 0);
        if (*endptr && *endptr != '\n' && *endptr != ',') {
            ERROR("Invalid PRINTFOFFSET specification for (invalid end character '%c') %s:%s\n", *endptr, fileName, line);
        }
    }

    if ((useprintf = strstr(line, "PRINTFMULTIPLE"))) {
        useprintf += strlen("PRINTFMULTIPLE");
        if (*useprintf != '=') {
            ERROR("Invalid PRINTFMULTIPLE specification (requires =) for %s:%s\n", fileName, line);
        }
        useprintf++;
        char *endptr;
        printfMultiple = strtoul(useprintf, &endptr, 0);
        if (*endptr && *endptr != '\n' && *endptr != ',') {
            ERROR("Invalid PRINTFOFFSET specification for (invalid end character '%c') %s:%s\n", *endptr, fileName, line);
        }
    }

    while (!inFile->eof()) {
        line[0] = '\0';
        inFile->getline(line, MAX_CHAR_BUFFER_SIZE);
        if (line[0]) {
            if ('#' != line[0]) {
                fileLines.push_back(line);
                realLinesInFile++; /* this counts number of valid data lines */
            }
        } else {
            break;
        }
    }

    if (realLinesInFile == 0) {
        ERROR("Input file has zero lines: %s\n", fileName);
    }

    if (printfFile) {
        numLinesInFile = virtualLines;
    } else {
        numLinesInFile = realLinesInFile;
    }

    delete inFile;

    indexMap = NULL;
    indexField = -1;
}

int FileContents::getLine(int line, char *dest, int len)
{
    if (printfFile) {
        line %= realLinesInFile;
    }
    return snprintf(dest, len, "%s", fileLines[line].c_str());
}

int FileContents::getField(int lineNum, int field, char *dest, int len)
{
    int curfield = field;
    int curline = lineNum;

    dest[0] = '\0';
    if (lineNum >= numLinesInFile) {
        return 0;
    }

    if (printfFile) {
        curline %= realLinesInFile;
    }
    const string & line = fileLines[curline];

    size_t pos(0), oldpos(0);

    do {
        oldpos = pos;
        size_t localpos = line.find(';', oldpos);

        if (localpos != string::npos) {
            pos = localpos + 1;
        } else {
            pos = localpos;
            break;
        }

        if (curfield == 0) {
            break;
        }

        curfield --;
    } while (oldpos != string::npos);


    if (curfield) {
        WARNING("Field %d not found in the file %s", field, fileName);
        return 0;
    }


    if (string::npos == oldpos) {
        return 0;
    }

    if (string::npos != pos) {
        // should not be decremented for fieldN
        pos -= (oldpos + 1);
    }

    string x = line.substr(oldpos, pos);
    if (x.length()) {
        if (printfFile) {
            const char *s = x.c_str();
            int l = strlen(s);
            int copied = 0;
            for (int i = 0; i < l; i++) {
                if (s[i] == '%') {
                    if (s[i + 1] == '%') {
                        dest[copied++] = s[i];
                    } else {
                        const char *format = s + i;
                        i++;
                        while (s[i] != 'd') {
                            if (i == l) {
                                ERROR("Invalid printf injection field (ran off end of line): %s", s);
                            }
                            if (!(isdigit(s[i]) || s[i] == '.' || s[i] == '-')) {
                                ERROR("Invalid printf injection field (only decimal values allowed '%c'): %s", s[i], s);
                            }
                            i++;
                        }
                        assert(s[i] == 'd');
                        char *tmp = (char *)malloc(s + i + 2 - format);
                        if (!tmp) {
                            ERROR("Out of memory!\n");
                        }
                        memcpy(tmp, format, s + i + 1 - format);
                        tmp[s + i + 1 - format] = '\0';
                        copied += sprintf(dest + copied, tmp, printfOffset + (lineNum * printfMultiple));
                        free(tmp);
                    }
                } else {
                    dest[copied++] = s[i];
                }
            }
            dest[copied] = '\0';
            return copied;
        } else {
            return snprintf(dest, len, "%s", x.c_str());
        }
    } else {
        return 0;
    }
}

int FileContents::numLines()
{
    return numLinesInFile;
}

int FileContents::nextLine(int userId)
{
    switch(usage) {
    case InputFileRandomOrder:
        return rand() % numLinesInFile;
    case InputFileSequentialOrder: {
        int ret = lineCounter;
        lineCounter = (lineCounter + 1) % numLinesInFile;
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

    indexMap = new str_int_map;
    for (int line = 0; line < numLines(); line++) {
        reIndex(line);
    }
}

int FileContents::lookup(char *key)
{
    if (indexField == -1) {
        ERROR("Invalid Index File: %s", fileName);
    }
    if (!indexMap) {
        ERROR("Invalid Index File: %s", fileName);
    }

    str_int_map::iterator index_it = indexMap->find(key);
    if (index_it == indexMap->end()) {
        return -1;
    }
    return index_it->second;
}


void FileContents::insert(char *value)
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
    char line[1024];
    getLine(realLinesInFile - 1, line, sizeof(line));
    char tmp[1024];
    getField(realLinesInFile - 1, 0, tmp, sizeof(tmp));
}

void FileContents::replace(int line, char *value)
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

    char tmp[SIPP_MAX_MSG_SIZE];
    getField(line, indexField, tmp, SIPP_MAX_MSG_SIZE);
    str_int_map::iterator index_it = indexMap->find(str_int_map::key_type(tmp));
    if (index_it != indexMap->end()) {
        indexMap->erase(index_it);
    }
    indexMap->insert(pair<str_int_map::key_type,int>(str_int_map::key_type(tmp), line));
}

void FileContents::deIndex(int line)
{
    if (indexField == -1) {
        return;
    }
    assert(line >= 0);
    assert(line < realLinesInFile);

    char tmp[SIPP_MAX_MSG_SIZE];
    getField(line, indexField, tmp, SIPP_MAX_MSG_SIZE);
    str_int_map::iterator index_it = indexMap->find(str_int_map::key_type(tmp));
    if (index_it != indexMap->end()) {
        if (index_it->second == line) {
            indexMap->erase(index_it);
        }
    }
}
