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
 * Description: This is a demo program demonstrating customizations to sipp via a plugin to support 
 *
 * 1. Running LUA inside of a sipp test script, sending values to lua from sipp
 * and returning values to local sipp variables. This includes the ability to utilize curl and mysql in the lua scripts
 *
 * 2. The capability to do RPC calls to a running sipp instance to get various call counts and enable/disable
 * logging on auto response messages
 *
 * 3. Processing some custom startup arguments to capture the running pid and to get the name of the lua file
 *
 *
 * Author: Nathan Franzmeier Sky Networks LLC 2022
 * Mail: Nathan.Franzmeier@sky-networks.com
 *
 */

#include <iterator>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
// Added for LUA support

#ifdef __cplusplus
  #include "lua.hpp"
#else
  #include "lua.h"
  #include "lualib.h"
  #include "lauxlib.h"
#endif


// Added for shared memory support
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <malloc.h>


#include <inttypes.h>
#include <errno.h>

#ifdef PCAPPLAY
#include "send_packets.h"
#endif
#include "sipp.hpp"
#include "auth.hpp"
#include "deadcall.hpp"
#include "config.h"
#include "version.h"
#include "apifunc.h"
#include "call.hpp"

// From call.hpp
  /* Automatic */
    enum T_AutoMode {
        E_AM_DEFAULT,
        E_AM_UNEXP_BYE,
        E_AM_UNEXP_CANCEL,
        E_AM_PING,
        E_AM_AA,
        E_AM_OOCALL
    };


// For CURL support

#include "curl.h"
#include "easy.h"

// For mysql thread support
#include "mysql.h"

// For rpc support
#include "sipp-rpc.h"
#include <rpc/pmap_clnt.h>

#define callDebug(...) do { if (useCallDebugf) { _callDebug( __VA_ARGS__ ); } } while (0)

#define MAXARGS 50 // Most argument pairs that can be passed into a lua script
extern  map<string, struct sipp_socket *>     map_perip_fd;
typedef struct tag_value {
	char tag[80];
	char value[2048];

}TAG_VAL;

typedef struct tv_array {

	int count;
	bool useThread;
	bool dataIsReady;  // Flag indicating data has been set
	pthread_t  myThread;
	TAG_VAL	element[MAXARGS];

} TV_ARRAY;


void bail(lua_State *L, char *msg){
//WARNING( "\nLUA ERROR:\n  %s: %s\n\n",
fprintf( stderr, "\nLUA ERROR:\n  %s: %s\n\n",
                msg, lua_tostring(L, -1));
}
typedef struct thread_data {
	char data_str[4096];
	char name[256]; // shared memory name
	int fd;
	lua_State *L;

} THREAD_DATA;

void do_lua_thread(THREAD_DATA *thread_data);
void do_lua_thread_detached(THREAD_DATA *thread_data); 
void rpc_thread(void* param);

pthread_t pthread4_id = 0;  // Thread id for the RPC thread

#define LUA_LIB

extern "C" 
{

	static const luaL_Reg lualibs[] = {
  	{"", luaopen_base},
	{LUA_COLIBNAME, luaopen_coroutine},
  	{LUA_LOADLIBNAME, luaopen_package},
  	{LUA_TABLIBNAME, luaopen_table},
  	{LUA_IOLIBNAME, luaopen_io},
  	{LUA_OSLIBNAME, luaopen_os},
  	{LUA_STRLIBNAME, luaopen_string},
  	{LUA_UTF8LIBNAME, luaopen_utf8},
  	{LUA_MATHLIBNAME, luaopen_math},
  	{LUA_DBLIBNAME, luaopen_debug},
  	{LUA_LOADLIBNAME, luaopen_package},
  	{NULL, NULL}
	};

	LUALIB_API void my_openlibs (lua_State *L) {
  		const luaL_Reg *lib = lualibs;
  		for (; lib->func; lib++) {
    			lua_pushcfunction(L, lib->func);
    			lua_pushstring(L, lib->name);
    			lua_call(L, 1, 0);
			fprintf(stderr,"lua_call result (%s):%s\n",lib->name, lua_tostring(L, -1));
  		}
	}
}
extern "C"
{
char	lua_file[128];
lua_State*  openLua() {


        lua_State *L = luaL_newstate();
        if (L) {

                luaL_openlibs(L);                           /* Load Lua libraries */
		//my_openlibs(L);

                if (luaL_loadfile(L, lua_file)) /* Load but don't run the Lua script */
                {
                        bail(L, (char *)"luaL_loadfile() failed");      /* Error out if file can't be read */
                        L=0;
                } else{

                        if (lua_pcall(L, 0, 0, 0))                  /* PRIMING RUN. FORGET THIS AND YOU'RE TOAST */
                        {
                                bail(L, (char *)"lua_pcall1() failed");          /* Error out if Lua file has an error */
                                L=0;
                        }
                }
        }
   return L;
}
}

API_FUNC  customFunc(int app, char *data_str, void *userVars, void *dispPtr){ return EXIT_SUCCESS;}
API_FUNC  processLuaRun(int app, char *data_str, void *tblPtr, void *dispPtr){
			VariableTable *userVars = (VariableTable *)tblPtr;
			scenario *display_scenario = (scenario *)dispPtr;
			char tmp[80];
			char *fname;
			char *name;
			int msize = sizeof(TV_ARRAY);
			TV_ARRAY *shared_memory;
 			fname  = strdup(tmpnam(tmp));
			name = strdup(basename(fname));
			free(fname);

	    		// Allocate some shared memory to pass the variables later after this executes
			TRACE_MSG("Opening shared memory for [%s] - data:(%s)",name,data_str);
	        	int shm_fd = shm_open (name, O_CREAT | O_EXCL | O_RDWR, S_IRWXU | S_IRWXG);
    			if (shm_fd < 0) 
    			{
        			WARNING("Error in shm_open(%s)",name);
				goto fail;
    			}
    			ftruncate(shm_fd, msize);
			
    			TRACE_MSG("Created shared memory object %s\n", name);
			
			
    			// attach the shared memory segment
    			shared_memory = (TV_ARRAY *) mmap(NULL, msize, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    			if (shared_memory == MAP_FAILED) 
    			{
        			WARNING("Error 1 in mmap()");
				goto fail;
    			}
		
    			TRACE_MSG("Shared memory segment allocated correctly (%d bytes).\n", msize);
			// Save off the shared memory segment name for now so we can get it later - pass this back to the sipp script
			shared_memory->count = 0;
			shared_memory->dataIsReady = 0;
			strcpy(shared_memory->element[shared_memory->count].tag,"retkey"); // This is a magic variable name which is used by the script to get our values back with a luaread@retkey
			strcpy(shared_memory->element[shared_memory->count].value,name);
			free(name);
			shared_memory->useThread = false;
			shared_memory->count++;

           		pid_t l_pid;
            		switch(l_pid = fork()) {
            		case -1:
                		// error when forking !
                		ERROR_NO("Forking error main");
                		break;
	
           		case 0:
                		// first child process - execute the command
                		if((l_pid = fork()) < 0) {
                    			ERROR_NO("Forking error child");
                		} else {
                    			if( l_pid == 0) {
						THREAD_DATA *thread_data = (THREAD_DATA *)calloc(1,sizeof(THREAD_DATA));
						strcpy(thread_data->data_str,data_str);
						strcpy(thread_data->name,name);
						do_lua_thread(thread_data);
					}
                    	
                    			exit(EXIT_OTHER);
                		}// end else
                		break;
            		default:
                		// parent process continue
                		// reap first child immediately
                		pid_t ret;
                		while ((ret=waitpid(l_pid, NULL, 0)) != l_pid) {
                    			if (ret != -1) {
                        			ERROR("waitpid returns %1d for child %1d",ret,l_pid);
                    			}
                		}
                		int index;
				for (int i=0;i<shared_memory->count;i++)
				{
                			// Set the internal variable value based on the returned table
                			index = display_scenario->allocVars->find(shared_memory->element[i].tag,false);
                       			if (index>0)
                       				userVars->getVar(index)->setString(strdup(shared_memory->element[i].value));
					TRACE_MSG("Setting TV pair 1 (%s/%s)\n",shared_memory->element[i].tag, shared_memory->element[i].value);
					//printf("Setting TV pair (%s/%s)\n",shared_memory->element[i].tag, shared_memory->element[i].value);
				}
				munmap(shared_memory,sizeof(TV_ARRAY));
				// Don't unlink here, we will do this later when we retrieve the value
				//shm_unlink(name);
                		break;
            		}
			fail:
			TRACE_MSG("End luarun\n");
			return EXIT_SUCCESS;
}
API_FUNC  processLuaRead(int app, char *data_str, void *tblPtr, void *dispPtr){
		VariableTable *userVars = (VariableTable *)tblPtr;
		scenario *display_scenario = (scenario *)dispPtr;

		// Retrieve previously read variables

		int msize = sizeof(TV_ARRAY);
		TV_ARRAY *shared_memory;
		char *tmptr;
		// char *name = data_str;
		//
       		char *name = strtok_r(data_str," ",&tmptr);
       		char *deleteMem = strtok_r(NULL," ",&tmptr);
       		/*char *timeout = strtok_r(NULL," ",&tmptr);
		uintmax_t  millisecondsToWait = 0; 
		// Get the timeout
		if (timeout!=0)
		{
			millisecondsToWait = strtoumax(timeout, NULL, 10);
			if (millisecondsToWait == UINTMAX_MAX && errno == ERANGE){
				WARNING("Failed to convert timeout");
				millisecondsToWait = 0;
			} 

			
		}
		*/

		// Reattach to the named segment and read the valuse from it
		int  shm_fd = shm_open(name, O_RDONLY, 0666);
    		// allocating the shared memory
    		shared_memory = (TV_ARRAY *) mmap(NULL, msize, PROT_READ, MAP_SHARED, shm_fd, 0);
    		if (shared_memory == MAP_FAILED) 
    		{
        		WARNING("Error 3 in mmap()");
    		
		} else {

			/*
			// Pause for the required time and then retrieve the data
			//for (int t=0;t<millisecondsToWait/10 && !shared_memory->dataIsReady;t++) {
			for (int t=0;t<millisecondsToWait/10;t++) {
				usleep(10000);
			}
			*/
			// This ensures the thread is done or else we hangup here - so make sure and add an expected delay in the script or end up waiting on the main thread making SIPP unresponsive
			// Switched to detached threads as this doesn't work anyway as we land here possibly from a different thread and the passed values don't seem to work
			//if (shared_memory->useThread && shared_memory->myThread.joinable())
				//shared_memory->myThread.join();

			// Read the data 
                	int index;
			for (int i=0;i<shared_memory->count;i++)
			{
                       		// Set the internal variable value based on the returned table
                		index = display_scenario->allocVars->find(shared_memory->element[i].tag,false);
                       		if (index>0)
                       			userVars->getVar(index)->setString(strdup(shared_memory->element[i].value));
				TRACE_MSG("Setting TV pair 3(%s/%s)\n",shared_memory->element[i].tag, shared_memory->element[i].value);
				//printf("Setting TV pair (%s/%s)\n",shared_memory->element[i].tag, shared_memory->element[i].value);
			}
			munmap(shared_memory,sizeof(TV_ARRAY));
			close(shm_fd);
			if (strcmp(deleteMem,"1")==0) {
				shm_unlink(name);
				TRACE_MSG("Deleting shared memory(%s)\n",name);
			}


		}
		return EXIT_SUCCESS;

}
//_ApiProcessLuaThread
API_FUNC  processLuaThread(int app, char *data_str, void *tblPtr, void *dispPtr){
		VariableTable *userVars = (VariableTable *)tblPtr;
		scenario *display_scenario = (scenario *)dispPtr;
		char tmp[128];
		char *fname;
		char tmpfname[128];
		char *name;
		int msize = sizeof(TV_ARRAY);
		TV_ARRAY *shared_memory;
 		fname  = tmpnam(tmp);
		strcpy(tmpfname,fname);
		name = basename(tmpfname);

		//if (true) {
    		// Allocate some shared memory to pass the variables later after this executes
		TRACE_MSG("Opening shared memory for [%s] - data:(%s)",name,data_str);
        	int shm_fd = shm_open (name, O_CREAT | O_EXCL | O_RDWR, S_IRWXU | S_IRWXG);
   		if (shm_fd < 0) 
   		{
       			WARNING("Error in shm_open(%s)",name);
    		} else {

    			ftruncate(shm_fd, msize);
    			TRACE_MSG("Created shared memory object %s\n", name);
    			// attach the shared memory segment
    			shared_memory = (TV_ARRAY *) mmap(NULL, msize, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    			if (shared_memory == MAP_FAILED) 
    			{
        			WARNING("Error 2 in mmap()");
    			} else {
		
    				TRACE_MSG("Shared memory segment allocated correctly (%d bytes).\n", msize);
				// Save off the shared memory segment name for now so we can get it later - pass this back to the sipp script
				shared_memory->count = 0;
				shared_memory->dataIsReady = 0;
				strcpy(shared_memory->element[shared_memory->count].tag,"retkey"); // This is a magic variable name which is used by the script to get our values back with a luaread@retkey
				strcpy(shared_memory->element[shared_memory->count].value,name);
				shared_memory->useThread = true;
				shared_memory->count++;

				THREAD_DATA *thread_data = (THREAD_DATA *)calloc(1,sizeof(THREAD_DATA));
				strcpy(thread_data->data_str,data_str);
				strcpy(thread_data->name,name);
				// Create a detached thread so we don't need to join it later
				TRACE_MSG("Create pthread shared memory\n");
				if (pthread_create(&shared_memory->myThread, NULL, (void *(*)(void *))do_lua_thread_detached, thread_data) == -1) {
            				ERROR_NO("Unable to create lua thread");
        			}


                		int index;
				for (int i=0;i<shared_memory->count;i++)
				{
                			// Set the internal variable value based on the returned table
                			index = display_scenario->allocVars->find(shared_memory->element[i].tag,false);
                       			if (index>0)
                       				userVars->getVar(index)->setString(strdup(shared_memory->element[i].value));
					TRACE_MSG("Setting TV pair 2(%s/%s)\n",shared_memory->element[i].tag, shared_memory->element[i].value);
				}
				munmap(shared_memory,sizeof(TV_ARRAY));
			}
		close(shm_fd);
		}
		//}
		//shm_unlink(name);
		TRACE_MSG("Ending lua thread\n");
		return EXIT_SUCCESS;

}

// This is a thread for executing our lua command
void do_lua_thread_detached(THREAD_DATA *thread_data) {
	mysql_thread_init();
        pthread_detach(pthread_self());
	do_lua_thread(thread_data);
	mysql_thread_end();
	pthread_exit(NULL);

}

void do_lua_thread(THREAD_DATA *thread_data) {

		char data_str[4096];
		TV_ARRAY *shared_memory;
		strcpy(data_str,thread_data->data_str);
        	int shm_fd = shm_open (thread_data->name, O_RDWR, S_IRWXU | S_IRWXG);
		char *tmptr;
   		if (shm_fd < 0) 
   		{
       			ERROR("Error in shm_open(%s)",thread_data->name);
    		} else {

    			// attach the shared memory segment
    			shared_memory = (TV_ARRAY *) mmap(NULL, sizeof(TV_ARRAY), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    			if (shared_memory == MAP_FAILED) 
    			{
        			ERROR("Error 4 in mmap()");
    			} else {
			//strcpy(data_str,data.c_str());

			//int shm_fd = thread_data->fd;
       			char *prog = strtok_r(data_str," ",&tmptr);
        		char *name[80];
        		char *val[2048];
			int i=0;
			
       			if (prog!=NULL)
			{
			thread_data->L = openLua();
			if (!thread_data->L)  {
				WARNING("Unable to create a new LUA state!\n");	
			}
			else {
   				//printf("In C, calling Lua->%s()\n",x);
   				lua_getglobal(thread_data->L, prog);                                  /* Tell it to run sipp.lua->xxx() */
   				lua_newtable(thread_data->L);                            /* Push empty table onto stack table now at -1 */
	
   				for (int i=0;i<MAXARGS;i++) {
           				name[i] = strtok_r(NULL," ",&tmptr);
           				if (name[i]==NULL)
                   				break;

					// If we get a rawdata tag - then we will copy to the end
					if (strcmp(name[i],"rawdata")==0) 
           					val[i] = strtok_r(NULL,"",&tmptr);
					else
           					val[i] = strtok_r(NULL," ",&tmptr);
					if (val[i]== NULL)
                   				break;

           				lua_pushstring(thread_data->L, name[i]);                /* Push a key onto the stack, table now at -2 */
           				lua_pushstring(thread_data->L, val[i]);               /* Push a value onto the stack, table now at -3 */
           				lua_settable(thread_data->L, -3);                        /* Take key and value, put into table at -3, */
	
   				}
				
   				int totalargs = i;
				
   				if (lua_pcall(thread_data->L, 1, 1, 0))                  // Run function, !!! NRETURN=1 !!! 
	
           				bail(thread_data->L, (char *)"lua_pcall2() failed");
   				else {
	
                                		//printf("============ Back in C again, Iterating thru returned table ============\n");
				
   						// table is in the stack at index 't' 
           					lua_pushnil(thread_data->L);  // Make sure lua_next starts at beginning 
           					const char *k, *v;
           					int index;
           					while (lua_next(thread_data->L, -2)) {                    // TABLE LOCATED AT -2 IN STACK 
	
            						v = lua_tostring(thread_data->L, -1);                 // Value at stacktop 
            						lua_pop(thread_data->L,1);                            // Remove value 
            						k = lua_tostring(thread_data->L, -1);                 // Read key at stacktop, 
							if (k != 0)
							{
								strcpy(shared_memory->element[shared_memory->count].tag,k);
								if (v != 0) {
									strcpy(shared_memory->element[shared_memory->count].value,v);
									shared_memory->count++;
               								TRACE_MSG("Fromc k=>%s<, v=>%s<\n", k, v);
								}
							}
							else {
								TRACE_MSG("Nothing on return stack\n");
							}
       						}
						shared_memory->dataIsReady = 1; // Mark the data as being available.
				}
			  	lua_gc(thread_data->L, LUA_GCCOLLECT, 0);
			  	lua_close(thread_data->L);

				// 02/15/2022 - NVF Added trim capability based on the environment variable TRIM_MEMORY
				char* trim_mem = getenv("TRIM_MEMORY");
                                if (trim_mem) {
                                        malloc_trim(M_TOP_PAD);
					TRACE_MSG("Trim memory\n");
                                }

				}
       			}
		munmap(shared_memory,sizeof(TV_ARRAY));
		close(shm_fd);
       		}
	}
	free(thread_data);
}

bool_t getcallcounter_1_svc(callcounter_t *argp, callcounter_t *result, struct svc_req *rqstp)
{
        bool_t retval;

        /*
         * insert server code here
         */

        unsigned long long incomingcalls = main_scenario->stats->GetStat(CStat::CPT_C_IncomingCallCreated);
        unsigned long long outgoingcalls = main_scenario->stats->GetStat(CStat::CPT_C_OutgoingCallCreated);
        unsigned long long successcalls = main_scenario->stats->GetStat(CStat::CPT_C_SuccessfulCall);
        unsigned long long failurecalls = main_scenario->stats->GetStat(CStat::CPT_C_FailedCall);

        result->incomingcalls=incomingcalls;
        result->outgoingcalls=outgoingcalls;
        result->successcalls=successcalls;
        result->failurecalls=failurecalls;

        retval = true;
        return retval;
}

bool_t enablelog4autoanswer_1_svc(void *argp, bool_t *result, struct svc_req *rqstp)
{
        bool_t retval;
	extern bool log4auto_answer;
        /*
         * insert server code here
         */

        log4auto_answer=true;
        retval = true;
        return retval;
}

bool_t disablelog4autoanswer_1_svc(void *argp, bool_t *result, struct svc_req *rqstp)
{
        bool_t retval;
	extern bool log4auto_answer;

        /*
         * insert server code here
         */

        log4auto_answer=false;
        retval = true;
        return retval;
}

int sipprpcprog_1_freeresult (SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
        xdr_free (xdr_result, result);

        /*
         * Insert additional freeing code here, if needed
         */

        return 1;
}
void sipprpcprog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
        union {
                callcounter_t getcallcounter_1_arg;
        } argument;
        union {
                callcounter_t getcallcounter_1_res;
                bool_t enablelog4autoanswer_1_res;
                bool_t disablelog4autoanswer_1_res;
        } result;
        bool_t retval;
        xdrproc_t _xdr_argument, _xdr_result;
        bool_t (*local)(char *, void *, struct svc_req *);

        switch (rqstp->rq_proc) {
        case NULLPROC:
                (void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
                return;

        case GETCALLCOUNTER:
                _xdr_argument = (xdrproc_t) xdr_callcounter_t;
                _xdr_result = (xdrproc_t) xdr_callcounter_t;
                local = (bool_t (*) (char *, void *,  struct svc_req *))getcallcounter_1_svc;
                break;

        case ENABLELOG4AUTOANSWER:
                _xdr_argument = (xdrproc_t) xdr_void;
                _xdr_result = (xdrproc_t) xdr_bool;
                local = (bool_t (*) (char *, void *,  struct svc_req *))enablelog4autoanswer_1_svc;
                break;

        case DISABLELOG4AUTOANSWER:
                _xdr_argument = (xdrproc_t) xdr_void;
                _xdr_result = (xdrproc_t) xdr_bool;
                local = (bool_t (*) (char *, void *,  struct svc_req *))disablelog4autoanswer_1_svc;
                break;

        default:
                svcerr_noproc (transp);
                return;
        }
        memset ((char *)&argument, 0, sizeof (argument));
        if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
                svcerr_decode (transp);
                return;
        }
        retval = (bool_t) (*local)((char *)&argument, (void *)&result, rqstp);
        if (retval > 0 && !svc_sendreply(transp, (xdrproc_t) _xdr_result, (char *)&result)) {
                svcerr_systemerr (transp);
        }
        if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
                fprintf (stderr, "%s", "unable to free arguments");
                exit (1);
        }
        if (!sipprpcprog_1_freeresult (transp, _xdr_result, (caddr_t) &result))
                fprintf (stderr, "%s", "unable to free results");

        return;
}

// Remote procedure calls thread
void rpc_thread(void* param)
{
        register SVCXPRT *transp;
        sigset_t              mask;
        sigfillset(&mask); /* Mask all allowed signals */
        int rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);
        if (rc) {
            WARNING("pthread_sigmask returned %d", rc);
            return;
        }

        pmap_unset (SIPPRPCPROG, SIPPRPCVERS);

        transp = svcudp_create(RPC_ANYSOCK);
        if (transp == NULL) {
                fprintf (stderr, "%s", "cannot create udp service.");
                exit(1);
        }
        if (!svc_register(transp, SIPPRPCPROG, SIPPRPCVERS, sipprpcprog_1, IPPROTO_UDP)) {
                ERROR( "%s", "unable to register (SIPPRPCPROG, SIPPRPCVERS, udp).");
                exit(1);
        }

        transp = svctcp_create(RPC_ANYSOCK, 0, 0);
        if (transp == NULL) {
               ERROR( "%s", "cannot create tcp service.");
                exit(1);
        }
        if (!svc_register(transp, SIPPRPCPROG, SIPPRPCVERS, sipprpcprog_1, IPPROTO_TCP)) {
                ERROR( "%s", "unable to register (SIPPRPCPROG, SIPPRPCVERS, tcp).");
                exit(1);
        }

        svc_run ();
        ERROR( "rpc_thread svc_run returned\n");
        pthread_exit(NULL); // 2/8/2022 - NVF Added
        //exit (1);
        /* NOTREACHED */
}


//
// Replace various custom functions with our own
//
extern "C" void appDllLoad(INT index)
{

    TRACE_MSG( "Custom App loaded!.\n");


    /* and/or by overriding default app event handler here */
    setApiFunc(API_CUSTOM_FUNC_1, (API_FUNC)processLuaRun,(char *)"luarun",index);
    setApiFunc(API_CUSTOM_FUNC_2, (API_FUNC)processLuaThread,(char *)"luathread",index);
    setApiFunc(API_CUSTOM_FUNC_3, (API_FUNC)processLuaRead,(char *)"luaread",index);

}

// This hooks into the built-in plugin capability of sipp and allows you to add EXEC commands

extern "C" int init(void *handle,int argc, char *argv[]) {

    	extern bool log4auto_answer;

	   // 2/9/2022 NVF This has to be above the SIGPIPE handler (added to support mysqlclient multithreaded): https://dev.mysql.com/doc/c-api/8.0/en/c-api-threaded-clients.html
        if (mysql_library_init(0, NULL, NULL)) {
                fprintf(stderr, "Warning: Could not initialize MySQL client library.  MySQL should not be used in a threaded call as a result\n");
                exit(1);
        }

	log4auto_answer = false;

	curl_global_init(CURL_GLOBAL_DEFAULT);  // This is so we can use CURL inside our lua scripts in multi-threaded environments

	// Enable the rpc thread
    	if (pthread_create(&pthread4_id, NULL,
            (void *(*)(void *)) rpc_thread, NULL) == -1) {
                ERROR_NO("Unable to create rpc thread");
        }
	// Get the name of the lua file
	for (int i=0;i<argc;i++) {
		if (strcmp(argv[i],"-lua_file")==0){
			strcpy(lua_file,argv[i+1]);
			break;
		}
	}


	// Hook up the API's to run the lua scripts
	//  
	strcpy((char *)CustomApi[0].filename, "myapp.so");
	CustomApi[0].instanceId = 1;
	CustomApi[0].subsystem = 0;
	CustomApi[0].appFlag = 0;
	CustomApi[0].index = 0;
	initSaveApi();
	saveDLLSetting(0,handle);
	appDllLoad(0);
	return  EXIT_SUCCESS;
}

extern "C" int handle_args(char *cmd, char *arg) {
	fprintf(stderr,"Handling commands %s, arg = %s\n",cmd,arg);
	if (strcmp(cmd,"-pid_file")==0) {
		// Write a pid file

        	FILE *f;
		char pid_file[256];
        	strcpy(pid_file, arg);
		fprintf(stderr,"Storing pid at %s\n",pid_file);
        	f = fopen(pid_file, "w");
        	fprintf(f, "%d\n",getpid());
        	fflush(f);
        	fclose(f);
	}

	return  EXIT_SUCCESS;
}

extern "C" int app_shutdown(void *handle) {
	fprintf(stderr,"App Shutdown\n");
  	curl_global_cleanup();
    	mysql_library_end(); // Required for mysql threaded support
	// Cancel the rpc thread
   	if (pthread4_id) {
        	pthread_cancel(pthread4_id);
        	pthread_join(pthread4_id, NULL);
    	}

	return  EXIT_SUCCESS;
}

// Use this to override default SIPP handling of auto responses
extern "C" bool handle_auto_response(T_AutoMode P_case, const char *P_recv,int *handled, call *call_ptr) {

    int res ;
    char * old_last_recv_msg = NULL;
    bool last_recv_msg_saved = false;
    char * last_recv_msg = call_ptr->getLastReceived();
    int msg_index = call_ptr->get_msg_index();
    char * id = call_ptr->get_id();
    extern bool log4auto_answer;

    *handled = 1; // Mark it as handled


    WARNING("Processing auto_response for unexpected message\n");

    switch (P_case) {
    case E_AM_UNEXP_BYE: // response for an unexpected BYE
        // usage of last_ keywords
    	WARNING("Processing auto_response for unexpected BYE\n");
        call_ptr->set_realloc_ptr ( (char *) realloc(last_recv_msg, strlen(P_recv) + 1));
        if (call_ptr->get_realloc_ptr()) {
            call_ptr->setLastReceived(call_ptr->get_realloc_ptr());
        } else {
            free(last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(call_ptr->getLastReceived(), P_recv);

        // The BYE is unexpected, count it
	call_ptr->increment_call_scenario_unexpected_count();
        if (default_behaviors & DEFAULT_BEHAVIOR_ABORTUNEXP) {
            WARNING("Aborting call on an unexpected BYE for call: %s", (id==NULL)?"none":id);
            if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                call_ptr->public_sendBuffer(call_ptr->public_createSendingMessage(get_default_message("200"), -1));
            }

            // if twin socket call => reset the other part here
            if (twinSippSocket && (msg_index > 0)) {
                res = call_ptr->public_sendCmdBuffer(call_ptr->public_createSendingMessage(get_default_message("3pcc_abort"), -1));
                if (res) {
                    WARNING("sendCmdBuffer returned %d", res);
                    return false;
                }
            }
            call_ptr->public_computeStat(CStat::E_CALL_FAILED);
            call_ptr->public_computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
            delete call_ptr;
        } else {
            WARNING("Continuing call on an unexpected BYE for call: %s", (id==NULL)?"none":id);
        }
        break ;

    case E_AM_UNEXP_CANCEL: // response for an unexpected cancel
    	WARNING("Processing auto_response for unexpected CANCEL\n");
        // usage of last_ keywords
	call_ptr->set_realloc_ptr ( (char *) realloc(last_recv_msg, strlen(P_recv) + 1));
        if (call_ptr->get_realloc_ptr()) {
            call_ptr->setLastReceived(call_ptr->get_realloc_ptr());
        } else {
            free(last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(call_ptr->getLastReceived(), P_recv);

        // The CANCEL is unexpected, count it
	call_ptr->increment_call_scenario_unexpected_count();
        if (default_behaviors & DEFAULT_BEHAVIOR_ABORTUNEXP) {
            WARNING("Aborting call on an unexpected CANCEL for call: %s", (id==NULL)?"none":id);
            if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                call_ptr->public_sendBuffer(call_ptr->public_createSendingMessage(get_default_message("200"), -1));
            }

            // if twin socket call => reset the other part here
            if (twinSippSocket && (msg_index > 0)) {
                res = call_ptr->public_sendCmdBuffer(call_ptr->public_createSendingMessage(get_default_message("3pcc_abort"), -1));
                if (res) {
                    WARNING("sendCmdBuffer returned %d", res);
                    return false;
                }
            }

            call_ptr->public_computeStat(CStat::E_CALL_FAILED);
            call_ptr->public_computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
            delete call_ptr;
        } else {
            WARNING("Continuing call on unexpected CANCEL for call: %s", (id==NULL)?"none":id);
        }
        break ;

    case E_AM_PING: // response for a random ping
        // usage of last_ keywords
    	WARNING("Processing auto_response for unexpected PING\n");
	call_ptr->set_realloc_ptr ( (char *) realloc(last_recv_msg, strlen(P_recv) + 1));
        if (call_ptr->get_realloc_ptr()) {
            call_ptr->setLastReceived(call_ptr->get_realloc_ptr());
        } else {
            free(last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(call_ptr->getLastReceived(), P_recv);

        if (default_behaviors & DEFAULT_BEHAVIOR_PINGREPLY) {
            WARNING("Automatic response mode for an unexpected PING for call: %s", (id==NULL)?"none":id);
            call_ptr->public_sendBuffer(call_ptr->public_createSendingMessage(get_default_message("200"), -1));
            // Note: the call ends here but it is not marked as bad. PING is a
            //       normal message.
            // if twin socket call => reset the other part here
            if (twinSippSocket && (msg_index > 0)) {
                res = call_ptr->public_sendCmdBuffer(call_ptr->public_createSendingMessage(get_default_message("3pcc_abort"), -1));
                if (res) {
                    WARNING("sendCmdBuffer returned %d", res);
                    return false;
                }
            }

            CStat::globalStat(CStat::E_AUTO_ANSWERED);
            delete call_ptr;
        } else {
            WARNING("Do not answer on an unexpected PING for call: %s", (id==NULL)?"none":id);
        }
        break ;

    case E_AM_AA: // response for a random INFO, NOTIFY, OPTIONS or UPDATE
        // store previous last msg if msg is INFO, NOTIFY, OPTIONS or UPDATE
        // restore last_recv_msg to previous one
        // after sending ok
    	WARNING("Processing auto_response for unexpected INFO, NOTIFY, OPTIONS or UPDATE\n");
        old_last_recv_msg = NULL;
        if (last_recv_msg != NULL) {
            last_recv_msg_saved = true;
            old_last_recv_msg = (char *) malloc(strlen(last_recv_msg)+1);
            strcpy(old_last_recv_msg, last_recv_msg);
        }
        // usage of last_ keywords
        call_ptr->set_realloc_ptr ( (char *) realloc(last_recv_msg, strlen(P_recv) + 1));
        if (call_ptr->get_realloc_ptr()) {
            call_ptr->setLastReceived(call_ptr->get_realloc_ptr());
        } else {
            free(last_recv_msg);
            free(old_last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(call_ptr->getLastReceived(), P_recv);
	if (log4auto_answer) {
        	WARNING("Automatic response mode for an unexpected INFO, NOTIFY, OPTIONS or UPDATE for call: %s",
                	(id == NULL) ? "none" : id);
	}
        call_ptr->public_sendBuffer(call_ptr->public_createSendingMessage(get_default_message("200"), -1));

        // restore previous last msg
        if (last_recv_msg_saved == true) {
            call_ptr->set_realloc_ptr((char *) realloc(call_ptr->getLastReceived(), strlen(old_last_recv_msg) + 1));
            if (call_ptr->get_realloc_ptr()) {
		 call_ptr->setLastReceived(call_ptr->get_realloc_ptr());
            } else {
                free(call_ptr->getLastReceived());
                ERROR("Out of memory!");
                return false;
            }


            strcpy(call_ptr->getLastReceived(), old_last_recv_msg);

            if (old_last_recv_msg != NULL) {
                free(old_last_recv_msg);
                old_last_recv_msg = NULL;
            }
        }
        CStat::globalStat(CStat::E_AUTO_ANSWERED);
        delete call_ptr;  // 2/16/2022 - NVF Added this for auto response messages as it looked like it wasn't being done otherwise - resulting in a memory leak
        return true;
        break;

    default:
        ERROR("Internal error for automaticResponseMode - mode %d is not implemented!", P_case);
        break ;
    }

    return false;
}
