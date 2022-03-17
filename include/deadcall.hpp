#include "call.hpp"

class deadcall : public virtual task, public virtual listener
{
public:
    deadcall(const char *id, const char * reason);
    ~deadcall();

    virtual bool process_incoming(const char* msg, const struct sockaddr_storage *);
    virtual bool process_twinSippCom(char* msg);

    virtual bool run();

    /* When should this call wake up? */
    virtual unsigned int wake();

    /* Dump call info to error log. */
    virtual void dump();

protected:
    unsigned long expiration;
    char *reason;
};
