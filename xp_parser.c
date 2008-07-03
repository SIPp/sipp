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

/*
 * Mini xml parser:
 *
 * WARNING 1: Only supports printable
 * ASCII characters in xml files. '\0'
 * is not a valid character. Returned string are
 * NULL-terminated.
 *
 * WARNING 2: Does not supports multithreading. Works
 * with static buffer, no memory allocation.
 */

/*******************  Include files *********************/

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <xp_parser.h>

/************* Constants and Global variables ***********/

#define XP_MAX_NAME_LEN   256
#define XP_MAX_FILE_LEN   65536
#define XP_MAX_STACK_LEN  256

char   xp_file     [XP_MAX_FILE_LEN + 1];
char * xp_position [XP_MAX_STACK_LEN];
int    xp_stack    = 0;

/****************** Internal routines ********************/
int xp_replace(char *source, char *dest, char *search, char *replace)
{
  char *position;
  char *occurances;
  int number = 0;

  if (!source || !dest || !search || !replace) {
    return -1;
  }
  dest[0] = '\0';
  position = source;
  occurances = strstr(position, search);
  while (occurances) {
    strncat(dest, position, occurances - position);
    strcat(dest, replace); 
    position = occurances + strlen(search);
    occurances = strstr(position, search);
    number++;
  }
  strcat(dest, position);
  return number;
}

/* This finds the end of something like <send foo="bar">, and does not recurse
 * into other elements. */
char * xp_find_start_tag_end(char *ptr)
{
  while(*ptr) {
    if (*ptr == '<') {
      if ((strstr(ptr,"<!--") == ptr)) {
        char * comment_end = strstr(ptr, "-->");
        if(!comment_end) return NULL;
        ptr = comment_end + 3;
      } else {
	return NULL;
      }
    } else  if((*ptr == '/') && (*(ptr+1) == '>')) {
      return ptr;
    } else if (*ptr == '"') {
      ptr++;
      while(*ptr) {
	if (*ptr == '\\') {
	  ptr += 2;
	} else if (*ptr=='"') {
	  ptr++;
	  break;
	} else {
	  ptr++;
	}
      }
    } else if (*ptr == '>') {
      return ptr;
    } else {
      ptr++;
    }
  }
  return ptr;
}

char * xp_find_local_end()
{
  char * ptr = xp_position[xp_stack];
  int level = 0;
  
  while(*ptr) {
    if (*ptr == '<') {
      if ((*(ptr+1) == '!') && 
          (*(ptr+2) == '[') &&
          (strstr(ptr,"<![CDATA[") == ptr)) {
        char * cdata_end = strstr(ptr, "]]>");
        if(!cdata_end) return NULL;
        ptr = cdata_end + 3;
      } else if ((*(ptr+1) == '!') && 
          (*(ptr+2) == '-') &&
          (strstr(ptr,"<!--") == ptr)) {
        char * comment_end = strstr(ptr, "-->");
        if(!comment_end) return NULL;
        ptr = comment_end + 3;
      } else if(*(ptr+1) == '/') {
        level--;
        if(level < 0) return ptr;
      } else {
        level ++;
      }
    } else  if((*ptr == '/') && (*(ptr+1) == '>')) {
      level --;
      if(level < 0) return ptr;
    } else if (*ptr == '"') {
      ptr++;
      while(*ptr) {
	if (*ptr == '\\') {
	  ptr ++; /* Skip the slash. */
	} else if (*ptr=='"') {
	  break;
	}
	ptr++;
      }
    }
    ptr++;
  }
  return ptr;
}

/********************* Interface routines ********************/

int xp_set_xml_buffer_from_string(char * str)
{
  size_t len = strlen(str);

  if(len > XP_MAX_FILE_LEN) {
    return 0;
  }

  strcpy(xp_file, str);
  xp_stack = 0;
  xp_position[xp_stack] = xp_file;
  
  if(strstr(xp_position[xp_stack], "<?xml") != xp_position[xp_stack]) return 0;
  if(!strstr(xp_position[xp_stack], "?>")) return 0;
  xp_position[xp_stack] = xp_position[xp_stack] + 2;

  return 1;
}

int xp_set_xml_buffer_from_file(char * filename)
{
  FILE * f = fopen(filename, "rb");
  int index = 0;
  int c;

  if(!f) { return 0; }

  while((c = fgetc(f)) != EOF) {
    if(c == '\r') continue;
    xp_file[index++] = c;
    if(index >= XP_MAX_FILE_LEN) {
      xp_file[index++] = 0;
      xp_stack = 0;
      xp_position[xp_stack] = xp_file;
      return 0;
    }
  }
  xp_file[index++] = 0;
  fclose(f);

  xp_stack = 0;
  xp_position[xp_stack] = xp_file;

  if(strstr(xp_position[xp_stack], "<?xml") != xp_position[xp_stack]) return 0;
  if(!strstr(xp_position[xp_stack], "?>")) return 0;
  xp_position[xp_stack] = xp_position[xp_stack] + 2;

  return 1;
}

char * xp_open_element(int index)
{
  char * ptr = xp_position[xp_stack];
  int level = 0;
  static char name[XP_MAX_NAME_LEN];

  while(*ptr) {
    if (*ptr == '<') {
      if ((*(ptr+1) == '!') && 
          (*(ptr+2) == '[') &&
          (strstr(ptr,"<![CDATA[") == ptr)) {
        char * cdata_end = strstr(ptr, "]]>");
        if(!cdata_end) return NULL;
        ptr = cdata_end + 3;
      } else if ((*(ptr+1) == '!') && 
          (*(ptr+2) == '-') &&
          (strstr(ptr,"<!--") == ptr)) {
        char * comment_end = strstr(ptr, "-->");
        if(!comment_end) return NULL;
        ptr = comment_end + 3;
      } else if (strstr(ptr,"<!DOCTYPE") == ptr) {
        char * doctype_end = strstr(ptr, ">");
        if(!doctype_end) return NULL;
        ptr = doctype_end + 2;
      } else if(*(ptr+1) == '/') {
        level--;
        if(level < 0) return NULL;
      } else {
	if(level==0) {
	  if (index) {
	    index --;
	  } else {
	    char * end = xp_find_start_tag_end(ptr + 1);
	    char * p;
	    if(!end) return NULL;

	    p = strchr(ptr, ' ');
	    if(p && (p < end))  { end = p; }
	    p = strchr(ptr, '\t');
	    if(p && (p < end))  { end = p; }
	    p = strchr(ptr, '\r');
	    if(p && (p < end))  { end = p; }
	    p = strchr(ptr, '\n');
	    if(p && (p < end))  { end = p; }
	    p = strchr(ptr, '/');
	    if(p && (p < end))  { end = p; }

	    memcpy(name, ptr + 1, end-ptr-1);
	    name[end-ptr-1] = 0;

	    xp_position[++xp_stack] = end;
	    return name;
	  }
	}

	/* We want to skip over this particular element .*/
	ptr = xp_find_start_tag_end(ptr + 1);
	if (ptr) ptr--;
	level ++;
      }
    } else if((*ptr == '/') && (*(ptr+1) == '>')) {
      level --;
      if(level < 0) return NULL;
    }
    ptr++;
  }
  return NULL;
}

void xp_close_element()
{
  if(xp_stack) {
    xp_stack--;
  }
}

void xp_root()
{
  xp_stack = 0;
}

char * xp_get_value(const char * name)
{
  int         index = 0;
  static char buffer[XP_MAX_FILE_LEN + 1]; 
  char      * ptr, *end, *check;
  
  end = xp_find_start_tag_end(xp_position[xp_stack] + 1);
  if(!end) return NULL;

  ptr = xp_position[xp_stack];
  
  while(*ptr) {
    ptr = strstr(ptr, name);

    if(!ptr) return NULL;
    if(ptr > end) return NULL;
    // FIXME: potential BUG in parser: we must retrieve full word,
    // so the use of strstr as it is is not enough.
    // we should check that the retrieved word is not a piece of another one.
    check = ptr-1;
    if(check >= xp_position[xp_stack])
    {
      if((*check != '\r') && 
         (*check != '\n') && 
         (*check != '\t') && 
         (*check != ' ' )) { ptr += strlen(name); continue; }
    }
    else
      return(NULL);

    ptr += strlen(name);
    while((*ptr == '\r') || 
          (*ptr == '\n') || 
          (*ptr == '\t') || 
          (*ptr == ' ' )    ) { ptr ++; }
    if(*ptr != '=') continue;
    ptr ++;
    while((*ptr == '\r') || 
          (*ptr == '\n') || 
          (*ptr == '\t') || 
          (*ptr ==  ' ')    ) { ptr ++; }
    ptr++;
    if(*ptr) {
      while(*ptr) {
	if (*ptr == '\\') {
	  ptr++;
	  switch(*ptr) {
	    case '\\':
	      buffer[index++] = '\\';
	      break;
	    case '"':
	      buffer[index++] = '"';
	      break;
	    case 'n':
	      buffer[index++] = '\n';
	      break;
	    case 't':
	      buffer[index++] = '\t';
	      break;
	    case 'r':
	      buffer[index++] = '\r';
	      break;
	    default:
	      buffer[index++] = '\\';
	      buffer[index++] = *ptr;
	      break;
	  }
	  ptr++;
	} else if (*ptr=='"') {
	  break;
	} else {
	  buffer[index++] = *ptr++;
	}
        if(index > XP_MAX_FILE_LEN) return NULL;
      }
      buffer[index] = 0;
      return buffer;
    }
  }
  return NULL;
}

char * xp_get_cdata()
{
  static char buffer[XP_MAX_FILE_LEN + 1]; 
  char      * end = xp_find_local_end();
  char      * ptr;
  
  ptr = strstr(xp_position[xp_stack],"<![CDATA[");
  if(!ptr) { return NULL; }
  ptr += 9;
  if(ptr > end) return NULL;
  end = strstr(ptr, "]]>");
  if(!end) { return NULL; }
  if((end -ptr) > XP_MAX_FILE_LEN) return NULL;
  memcpy(buffer, ptr, (end-ptr));
  buffer[end-ptr] = 0;
  return buffer;
}

int xp_get_content_length(char * P_buffer) 
{
  char * L_ctl_hdr;
  int    L_content_length = -1 ; 
  unsigned char   short_form;

  short_form = 0;

  L_ctl_hdr = strstr(P_buffer, "\nContent-Length:");
  if(!L_ctl_hdr) {L_ctl_hdr = strstr(P_buffer, "\nContent-length:"); }
  if(!L_ctl_hdr) {L_ctl_hdr = strstr(P_buffer, "\ncontent-Length:"); }
  if(!L_ctl_hdr) {L_ctl_hdr = strstr(P_buffer, "\ncontent-length:"); }
  if(!L_ctl_hdr) {L_ctl_hdr = strstr(P_buffer, "\nCONTENT-LENGTH:"); }
  if(!L_ctl_hdr) {L_ctl_hdr = strstr(P_buffer, "\nl:"); short_form = 1;}

  if( L_ctl_hdr ){
    if (short_form) {
      L_ctl_hdr += 3;
    } else {
      L_ctl_hdr += 16;
    }
    while(isspace(*L_ctl_hdr)) L_ctl_hdr++;
    sscanf(L_ctl_hdr, "%d", &L_content_length);
  } 
  // L_content_length = -1 the message does not contain content-length
  return (L_content_length); 
}

