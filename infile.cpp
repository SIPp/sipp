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

/* Read MAX_CHAR_BUFFER_SIZE size lines from the "fileName" and populate it in
 * the fileContents vector. The file should not be more than MAX_LINES_IN_FILE
 * lines long and each line should be terminated with a '\n'
 */
FileContents::FileContents(const char *fileName) {
  ifstream *inFile    = new ifstream(fileName);
  char      line[MAX_CHAR_BUFFER_SIZE];

  if (!inFile->good()) {
    ERROR_P1("Unable to open file %s", fileName);
  }

  this->fileName = fileName;

  lineCounter = numLinesInFile = 0;

  line[0] = '\0';
  inFile->getline(line, MAX_CHAR_BUFFER_SIZE);

  if (NULL != strstr(line, "RANDOM")) {
      usage = InputFileRandomOrder;
  } else if (NULL != strstr(line, "SEQUENTIAL")) {
      usage = InputFileSequentialOrder;
  } else if (NULL != strstr(line, "USER")) {
      usage = InputFileUser;
  } else {
      ERROR_P2("Unknown file type (valid values are RANDOM, SEQUENTIAL, and USER) for %s:%s\n", fileName, line);
  }

  while (!inFile->eof()) {
    line[0] = '\0';
    inFile->getline(line, MAX_CHAR_BUFFER_SIZE);
    if (line[0]) {
      if ('#' != line[0]) {
        fileLines.push_back(line);
        numLinesInFile++; /* this counts number of valid data lines */
      }
    } else {
      break;
    }
  }

  if (numLinesInFile == 0) {
	ERROR_P1("Input file has zero lines: %s\n", fileName);
  }

  delete inFile;
}

int FileContents::getLine(int line, char *dest, int len) {
  return snprintf(dest, len, "%s", fileLines[line].c_str());
}

int FileContents::getField(int lineNum, int field, char *dest, int len) {
  int curfield = field;

  dest[0] = '\0';
  if (lineNum >= numLinesInFile) {
    return 0;
  }

  const string & line = fileLines[lineNum];

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
      WARNING_P2("Field %d not found in the file %s", field, fileName);
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
    return snprintf(dest, len, "%s", x.c_str());
  } else {
    return 0;
  }
}

int FileContents::numLines() {
  return numLinesInFile;
}

int FileContents::nextLine(int userId) {
  switch(usage) {
    case InputFileRandomOrder:
      return rand() % numLinesInFile;
    case InputFileSequentialOrder:
      {
	int ret = lineCounter;
	lineCounter = (lineCounter + 1) % numLinesInFile;
	return ret;
      }
    case InputFileUser:
      if (userId == 0) {
	return -1;
      }
      if ((userId  - 1) >= numLinesInFile) {
	ERROR_P3("%s has only %d lines, yet user %d was requested.", fileName, numLinesInFile, userId);
      }
      return userId - 1;
    default:
      ERROR("Internal error: unknown file usage mode!");
      return -1;
  }
}

void FileContents::dump(void)
{
    WARNING_P3("Line choosing strategy is [%s]. m_counter [%d] numLinesInFile [%d]",
               usage == InputFileSequentialOrder ? "SEQUENTIAL" :
		usage == InputFileRandomOrder ? "RANDOM" :
		usage == InputFileUser ? "USER" : "UNKNOWN",
               lineCounter, numLinesInFile);

    for (int i = 0; i < numLinesInFile && fileLines[i][0]; i++) {
        WARNING_P3("%s:%d reads [%s]", fileName, i, fileLines[i].c_str());
    }
}
