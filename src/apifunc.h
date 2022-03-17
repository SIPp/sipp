/*
 *  Definitions for setting up an API table to override functionality of the exec command with our own commands so we can add to sipp functionality 
 *  for things like adding lua scripts which can both read and write sipp variables, execute C calls etc.  and in general influence the script execution
 */
extern "C" {
#define MAXAPPLICATIONS 2
#define MAXCUSTOMAPPLICATIONS 1
enum APIFUNCID
{
        API_CUSTOM_FUNC_1,
        API_CUSTOM_FUNC_2,
        API_CUSTOM_FUNC_3,
        API_CUSTOM_FUNC_4,
        API_CUSTOM_FUNC_5,
        API_CUSTOM_FUNC_6,
        API_CUSTOM_FUNC_7,
        API_CUSTOM_FUNC_8,
        API_CUSTOM_FUNC_9,
        API_CUSTOM_FUNC_10,
        API_MAX_FUNC_ID
};

#define INT int
#define VOID void
#define BYTE unsigned char
#define WORD short
#define MAXFUNCS (API_MAX_FUNC_ID+1)
#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS            0
#endif
#ifndef EXIT_FAILURE
#define EXIT_FAILURE            1
#endif

typedef INT (*API_FUNC)(...);


typedef struct S_API_FUNC_TABLE {
	API_FUNC	funcPtr;
	char    *cmdPtr;
	
} API_FUNC_TABLE;

typedef struct S_CUSTOMAPI
{
    INT index;
    BYTE appFlag;      
    BYTE subsystem;   
    WORD instanceId; 
    BYTE filename[80];
} CUSTOMAPI;

extern CUSTOMAPI        CustomApi[MAXCUSTOMAPPLICATIONS];
extern INT              MaxCustomApiTable;

extern API_FUNC_TABLE ApiHandler[MAXFUNCS][MAXAPPLICATIONS];

// Functions to get/set the functions in the API table
API_FUNC _ApiCustomFunc(int func, int app, char *data_str, void *userVars, void *dispPtr);
API_FUNC  customFunc(int app, char *data_str, void *userVars, void *dispPtr);
INT initSaveApi();
INT saveDLLSetting(INT index,void *handle);
void setApiFunc(APIFUNCID funcId, API_FUNC handle, char *cmd, INT index);
API_FUNC getAppFunc(APIFUNCID funcId, INT appId);
void resetAppFunc(INT appId);
}


