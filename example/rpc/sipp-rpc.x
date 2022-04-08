struct callcounter
{
    int      incomingcalls;
    int      outgoingcalls;
    int      successcalls;
    int      failurecalls;
};

typedef struct callcounter callcounter_t;

program SIPPRPCPROG
{
    version SIPPRPCVERS
        {
            callcounter_t GETCALLCOUNTER(callcounter_t)    = 1;
            bool ENABLELOG4AUTOANSWER()    = 2;
            bool DISABLELOG4AUTOANSWER()    = 3;
        } = 1;
} = 0x20000002;
