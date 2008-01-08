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
 *  Author : Gundu RAO - 16 Jul 2004
 *           From Hewlett Packard Company.
 */

#define SSL_MAIN
#include "sslcommon.h"

int init_OpenSSL(void) {
  if (!Thread_setup() || !SSL_library_init() ) {
    return (-1) ;
  }
  SSL_load_error_strings();
  return 1;
}


SSL_CTX *setup_ssl_context(SSL_METHOD *method) {
  SSL_CTX *ctx;

  if ((ctx = SSL_CTX_new(method)) == NULL) {
    SSL_ERROR();
  }

  return ctx;
}

int  SSL_ERROR(void) {
  int                   flags;
  int                   line;
  const char            *data;
  const char            *file;
  unsigned long         code;

  code = ERR_get_error_line_data(&file,&line,&data,&flags);
  while (code) {
    char temp_buffer[1024];

    sprintf(temp_buffer,"Error code: %lu in %s Line %d.\n",code,file,line);
    /*WARNING("SSL Error : %s\n",temp_buffer);*/

    if (data && (flags & ERR_TXT_STRING)) {
      sprintf(temp_buffer,"Error data : %s\n",data);
      /*WARNING("SSL Error : %s\n",temp_buffer);*/
    }
    code = ERR_get_error_line_data(&file,&line,&data,&flags);
  }
  return 1;
}

