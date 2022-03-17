/* Functions to handle loading/unloading .so files to replace certain functions in an API table
 * Author: Nathan Franzmeier
 * March 15, 2022
 *  This provides a framework for adding a plugin which overrides the exec_command function in SIPP with new user defined functions 
 *  that are implemented via the sipp plugin mechanism
 *  The format of these new functions in the xml script is
 *  <exec command="command@function  arg1 arg2 arg3 "  - up to 10 args
 */

#include "apifunc.h"
#include "pthread.h"
#include "defines.h"
#include <cstring>
#include <dlfcn.h>

static pthread_mutex_t ApiFuncMutex = PTHREAD_MUTEX_INITIALIZER;


API_FUNC_TABLE ApiHandler[MAXFUNCS][MAXAPPLICATIONS] = {
    {(API_FUNC)customFunc,(char *)"custom1"},
    {(API_FUNC)customFunc,(char *)"custom2"},
    {(API_FUNC)customFunc,(char *)"custom3"},
    {(API_FUNC)customFunc,(char *)"custom4"},
    {(API_FUNC)customFunc,(char *)"custom5"},
    {(API_FUNC)customFunc,(char *)"custom6"},
    {(API_FUNC)customFunc,(char *)"custom7"},
    {(API_FUNC)customFunc,(char *)"custom8"},
    {(API_FUNC)customFunc,(char *)"custom9"},
    {(API_FUNC)customFunc,(char *)"custom10"},
    {(API_FUNC)NULL,(char *)NULL}
};


struct SAVEAPPDLL
{
    INT         index;
    INT         appId;
    BYTE        filename[80];
    API_FUNC    currentApiFunc[MAXFUNCS];
    API_FUNC    oldApiFunc[MAXFUNCS];
    char *	oldApiCmd[MAXFUNCS];
    char * 	currentCmd[MAXFUNCS];
    void        (*unLoadFunc)(void);
    void     *handle;
};

CUSTOMAPI      CustomApi[MAXCUSTOMAPPLICATIONS];  // Use this table to define any override functions

static SAVEAPPDLL  *SaveApiDll;
static INT CurrentApiIndex=0;
static INT MyID = 1;
INT MaxCustomApiTable=MAXCUSTOMAPPLICATIONS;

// Call the generic handler at this index

API_FUNC _ApiCustomFunc(int funcIndex, int app, char *data_str, void  *userVars, void *dispPtr) {

    API_FUNC handler=NULL;

    if(app < MAXAPPLICATIONS && app >=0)
    {
        pthread_mutex_lock(&ApiFuncMutex);
        if(ApiHandler[funcIndex][app].funcPtr)
            handler = ApiHandler[funcIndex][app].funcPtr;
        else
            handler = ApiHandler[funcIndex][0].funcPtr;
        pthread_mutex_unlock(&ApiFuncMutex);
        if (handler != NULL)
           handler(app,data_str,userVars,dispPtr);
    }
    return EXIT_SUCCESS;
}

void setApiFunc(APIFUNCID funcId, API_FUNC handle, char *cmd, INT index)
{
    INT appId;

    if(index < 0 || index >= MaxCustomApiTable)
        index = CurrentApiIndex;

    appId = SaveApiDll[index].appId;

    if(appId >= 0 && appId < MAXAPPLICATIONS && funcId < API_MAX_FUNC_ID)
    {
        SaveApiDll[index].oldApiFunc[funcId] = ApiHandler[funcId][appId].funcPtr;
        SaveApiDll[index].oldApiCmd[funcId] = ApiHandler[funcId][appId].cmdPtr;
        pthread_mutex_lock(&ApiFuncMutex);
        ApiHandler[funcId][appId].funcPtr = handle;
        ApiHandler[funcId][appId].cmdPtr = cmd;
        pthread_mutex_unlock(&ApiFuncMutex);
        SaveApiDll[index].currentApiFunc[funcId] = handle;
    }
}

API_FUNC getApiFunc (APIFUNCID funcId, char *cmd, INT appId)
{
    API_FUNC handler = NULL;
    if(appId >= 0 && appId < MAXAPPLICATIONS && funcId < API_MAX_FUNC_ID)
    {
        pthread_mutex_lock(&ApiFuncMutex);
        if (ApiHandler[funcId][appId].funcPtr !=  handler)
           handler = ApiHandler[funcId][appId].funcPtr;
        pthread_mutex_unlock(&ApiFuncMutex);
    }
    return handler;
}

void resetApiFunc(INT index)
{
    APIFUNCID funcId;
    INT appId;

    if(index < 0 || index >= MaxCustomApiTable)
        index = CurrentApiIndex;

    appId = SaveApiDll[index].appId;

    if(appId >= 0 && appId < MAXAPPLICATIONS )
    {
        for(funcId = API_CUSTOM_FUNC_1; funcId < API_MAX_FUNC_ID;
                funcId = APIFUNCID(funcId+1))
        {
            if(SaveApiDll[index].currentApiFunc[funcId])
            {
                pthread_mutex_lock(&ApiFuncMutex);
                ApiHandler[funcId][appId].funcPtr = SaveApiDll[index].oldApiFunc[funcId];
                ApiHandler[funcId][appId].cmdPtr = SaveApiDll[index].oldApiCmd[funcId];
                pthread_mutex_unlock(&ApiFuncMutex);
                SaveApiDll[index].currentApiFunc[funcId] = NULL;
            }
        }
    }
}
INT saveDLLSetting(INT index,void *handle) {

	SaveApiDll[index].index = index;
	SaveApiDll[index].appId = CustomApi[index].appFlag;
	SaveApiDll[index].handle = handle;
        SaveApiDll[index].unLoadFunc = (VOID (*)(VOID))dlsym(SaveApiDll[index].handle, "appDllUnload");

	return EXIT_SUCCESS;
}

INT loadApiDLL(INT index)
{

    VOID (*appDllInit)(INT index);

    if(index >=0 && index < MaxCustomApiTable &&
       (CustomApi[index].instanceId == MyID || CustomApi[index].instanceId == 0) )
    {
        if(strlen((const char *)CustomApi[index].filename) > 0)
        {
            if(SaveApiDll[index].handle)
            {
                ERROR( "Error: Custom APP %d (%s) already loaded.\n", index, SaveApiDll[index].filename);
            }
            else
            {
                SaveApiDll[index].index = index;
                SaveApiDll[index].appId = CustomApi[index].appFlag;
                strcpy((char *)SaveApiDll[index].filename, (const char *)CustomApi[index].filename);
                CurrentApiIndex = index;
                SaveApiDll[index].handle = dlopen(((const char *)SaveApiDll[index].filename), RTLD_NOW);
                if(SaveApiDll[index].handle == NULL)
                {
                    ERROR( "Error: Failed to create handle - Custom APP %d (%s).\n", index, SaveApiDll[index].filename);
                    return EXIT_FAILURE;
                }
                else
                {
                    appDllInit = (VOID (*)(const INT))dlsym(SaveApiDll[index].handle, "appDllLoad");
		    const char* err = dlerror();
                    if(err)
                    {
                        ERROR( "Error: Unable to find 'appDllLoad' function for Custom APP %d (%s).\n", index, SaveApiDll[index].filename);
                        return EXIT_FAILURE;
                    }

                    SaveApiDll[index].unLoadFunc = (VOID (*)(VOID))dlsym(SaveApiDll[index].handle, "appDllUnload");

                    (*appDllInit)(index);
                }
            }
        }
        else
        {
            ERROR( "Error: Custom APP %d name empty(%s).\n", index, CustomApi[index].filename);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

INT reloadApiDll(INT index)
{
    INT ret = EXIT_SUCCESS;
    SAVEAPPDLL tempSaveDLL;
    APIFUNCID funcId;
    INT         appId;

    /// save the dll ptrs first, then load new ones, then delete
    if(SaveApiDll[index].handle)
    {
        ERROR( "save DLL index %d name %s\n", index, SaveApiDll[index].filename);
        memcpy(&tempSaveDLL, &SaveApiDll[index], sizeof(SAVEAPPDLL));
        SaveApiDll[index].handle = NULL;
        SaveApiDll[index].filename[0] = 0;
        SaveApiDll[index].appId = 0;

        ret = loadApiDLL(index);
        if(ret != EXIT_SUCCESS)
        {
            ERROR( "reload DLL Failed: index %d name %s, rollback to previous one\n", index, SaveApiDll[index].filename);
            memcpy(&SaveApiDll[index], &tempSaveDLL, sizeof(SAVEAPPDLL));
        }
        else /// load new one succeeded, delete old ones
        {
            ERROR( "delete old DLL index %d name %s\n", index, SaveApiDll[index].filename);

            appId = tempSaveDLL.appId;

            if(appId >= 0 && appId < MAXAPPLICATIONS )
            {
                for(funcId = API_CUSTOM_FUNC_1; funcId < API_MAX_FUNC_ID;
                        funcId = APIFUNCID(funcId+1))
                {
                    if(tempSaveDLL.currentApiFunc[funcId] && SaveApiDll[index].currentApiFunc[funcId] == NULL) /// no more needed
                    {
                        pthread_mutex_lock(&ApiFuncMutex);
                        ApiHandler[funcId][appId].funcPtr = tempSaveDLL.oldApiFunc[funcId];
                        ApiHandler[funcId][appId].cmdPtr = tempSaveDLL.oldApiCmd[funcId];
                        pthread_mutex_unlock(&ApiFuncMutex);
                    }
                }

            }
        }
    }
    else /// last time failed to load
    {
        /// just load it
        ret = loadApiDLL(index);
    }

    ERROR( "reload DLL index %d name %s finished %d\n", index, SaveApiDll[index].filename, ret);
    return ret;
}

INT unloadApiDll(INT index)
{
    INT ret = EXIT_SUCCESS;

    if(SaveApiDll[index].handle)
    {
        CurrentApiIndex = index;
        resetApiFunc(index);

        if(SaveApiDll[index].unLoadFunc)
        {
           (*SaveApiDll[index].unLoadFunc)();
        }

       dlclose(SaveApiDll[index].handle);
       SaveApiDll[index].handle = NULL;
       ERROR( "Unloaded index %d name %s\n", index, SaveApiDll[index].filename);
       SaveApiDll[index].filename[0] = 0;
       SaveApiDll[index].appId = 0;
    }
    else
    {
       ERROR( "Error: appId or name mismatch for Custom APP %d(%s).\n", index, SaveApiDll[index].filename);
       ret = EXIT_FAILURE;
    }
    return ret;
}


INT loadCustomApis(VOID)
{
    initSaveApi();
    for(INT i=0; i<MaxCustomApiTable; i++)
    {
       if( (CustomApi[i].instanceId == MyID || CustomApi[i].instanceId == 0))
           loadApiDLL(i);
    }

    return EXIT_SUCCESS;
}

INT initSaveApi() {

    SaveApiDll = new SAVEAPPDLL [MaxCustomApiTable];

    if(SaveApiDll == NULL)
        return EXIT_FAILURE;

    memset(SaveApiDll, 0, sizeof(SAVEAPPDLL)*MaxCustomApiTable);

    return EXIT_SUCCESS;

}
