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
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           Olivier Jacques
 *           From Hewlett Packard Company.
 *           Shriram Natarajan
 *           Peter Higginson
 *           Eric Miller
 *           Venkatesh
 *           Enrico Hartung
 *           Nasir Khan
 *           Lee Ballard
 *           Guillaume Teissier from FTR&D
 *           Wolfgang Beck
 *           Venkatesh
 *           Vlad Troyanker
 *           Charles P Wright from IBM Research
 *           Amit On from Followap
 *           Jan Andres from Freenet
 *           Ben Evans from Open Cloud
 *           Marc Van Diest from Belgacom
 */

#ifndef __MESSAGE__
#define __MESSAGE__

#include <vector>

struct MessageComponent;

typedef enum {
  E_Message_Literal,
  E_Message_Remote_IP,
  E_Message_Remote_Port,
  E_Message_Transport,
  E_Message_Local_IP,
  E_Message_Local_IP_Type,
  E_Message_Local_Port,
  E_Message_Server_IP,
  E_Message_Media_IP,
  E_Message_Auto_Media_Port,
  E_Message_Media_Port,
  E_Message_Media_IP_Type,
  E_Message_Call_Number,
  E_Message_Call_ID,
  E_Message_CSEQ,
  E_Message_PID,
  E_Message_Service,
  E_Message_Branch,
  E_Message_Index,
  E_Message_Next_Url,
  E_Message_Len,
  E_Message_Peer_Tag_Param,
  E_Message_Last_Peer_Tag_Param,
  E_Message_Routes,
  E_Message_Variable,
  E_Message_Fill,
  E_Message_Injection,
  E_Message_Last_Header,
  E_Message_Last_Request_URI,
  E_Message_TDM_Map,
  E_Message_Authentication,
  E_Message_ClockTick
} MessageCompType;

class SendingMessage {
  public:
    SendingMessage(char *msg, bool skip_sanity = false);
    ~SendingMessage();

    struct MessageComponent *getComponent(int);
    int numComponents();

    char *getMethod();
    int getCode();

    bool isResponse();
    bool isAck();
    bool isCancel();

    static void parseAuthenticationKeyword(struct MessageComponent *dst, char *keyword);
    static void freeMessageComponent(struct MessageComponent *comp);
  private:
    std::vector <struct MessageComponent *> messageComponents;

    char *method;
    int code;

    bool ack;
    bool cancel;
    bool response;

    // Get parameters from a [keyword]
    static void getQuotedParam(char * dest, char * src, int * len);
    static void getHexStringParam(char * dest, char * src, int * len);
    static void getKeywordParam(char * src, char * param, char * output);
};


struct MessageComponent {
  MessageCompType type;
  char *literal;
  int offset;
  int varId;
  union u {
    /* Authentication Parameters. */
    struct {
      char *auth_user;
      char *auth_pass;
      char *aka_OP;
      char *aka_AMF;
      char *aka_K;
    } auth_param;
    /* Field Substitution. */
    struct {
      char *filename;
      int field;
    } field_param;
  } comp_param;
};

#endif
