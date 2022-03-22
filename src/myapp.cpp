/* 
 * Description: Custom modifications to support running LUA inside of a sipp test script, sending values to lua from sipp
 * and returning values to local sipp variables
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

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

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

// 02/9/2022 - NVF Added when trying to fix mysql thread support
#include "mysql.h"

#define callDebug(...) do { if (useCallDebugf) { _callDebug( __VA_ARGS__ ); } } while (0)

using namespace std;

#define USE_PTHREADS 1
// Added for thread support
#if USE_PTHREADS == 0
	#include <thread>
#endif
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
#if USE_PTHREADS == 1
	pthread_t  myThread;
#else
	std::thread myThread;
#endif
	TAG_VAL	element[MAXARGS];

} TV_ARRAY;


void bail(lua_State *L, char *msg){
        WARNING( "\nLUA ERROR:\n  %s: %s\n\n",
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

lua_State*  openLua() {


#ifndef USE_GLOBAL_LUA
        lua_State *L = luaL_newstate();
#else
        if (L) return L;

        L = luaL_newstate();                        // Create Global Lua state variable
#endif
        if (L) {

                luaL_openlibs(L);                           /* Load Lua libraries */

                if (luaL_loadfile(L, "sipp.lua")) /* Load but don't run the Lua script */
                //if (luaL_loadfile(L, lua_file)) /* Load but don't run the Lua script */
                {
                        bail(L, "luaL_loadfile() failed");      /* Error out if file can't be read */
                        L=0;
                } else{

                        if (lua_pcall(L, 0, 0, 0))                  /* PRIMING RUN. FORGET THIS AND YOU'RE TOAST */
                        {
                                bail(L, "lua_pcall1() failed");          /* Error out if Lua file has an error */
                                L=0;
                        }
                }
        }
   return L;
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
#if USE_PTHREADS == 1
				TRACE_MSG("Create pthread shared memory\n");
				if (pthread_create(&shared_memory->myThread, NULL, (void *(*)(void *))do_lua_thread_detached, thread_data) == -1) {
            				ERROR_NO("Unable to create lua thread");
        			}

#else
				TRACE_MSG("Create std shared memory\n");
				shared_memory->myThread = std::thread(do_lua_thread, thread_data);
				shared_memory->myThread.detach();
#endif

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
	
           				bail(thread_data->L, "lua_pcall2() failed");
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
#ifndef USE_GLOBAL_LUA
			  	lua_close(thread_data->L);
#endif
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

//
// Replace various custom functions with our own
//
extern "C" void appDllLoad(INT index)
{

    TRACE_MSG( "Custom App loaded!.\n");


    /* and/or by overriding default app event handler here */
    setApiFunc(API_CUSTOM_FUNC_1, (API_FUNC)processLuaRun,"luarun",index);
    setApiFunc(API_CUSTOM_FUNC_2, (API_FUNC)processLuaThread,"luathread",index);
    setApiFunc(API_CUSTOM_FUNC_3, (API_FUNC)processLuaRead,"luaread",index);

}

// This hooks into the built-in plugin capability of sipp

extern "C" int init(void *handle) {
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

