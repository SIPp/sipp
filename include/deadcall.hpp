#include "call.hpp"

class deadcall : public virtual task, public virtual listener
{
public:
    /* sent_bye, sent_cancel: the call ended with a BYE or a CANCEL,
     * whose answers are no surprise. */
    deadcall(const char *id, const char *reason, bool sent_bye = false, bool sent_cancel = false);
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
    bool sent_bye;
    bool sent_cancel;
};
