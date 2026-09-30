#include "call.hpp"

class deadcall : public virtual task, public virtual listener
{
public:
    /* reason: a format of the message index the call ended at.
     * sent_bye, sent_cancel: the call ended with a BYE or a CANCEL,
     * whose answers are no surprise. */
    deadcall(const char *id, const char *reason, int index, bool sent_bye = false, bool sent_cancel = false);

    /* Made from blocks of their own: see node_pool */
    static void *operator new(size_t size);
    static void operator delete(void *p, size_t size);

    virtual bool process_incoming(const char* msg, const struct sockaddr_storage *, SIPpSocket *);
    virtual bool process_twinSippCom(char* msg);

    virtual bool run();

    /* When should this call wake up? */
    virtual unsigned int wake();

    /* Dump call info to error log. */
    virtual void dump();

protected:
    unsigned long expiration;
    const char *reason;
    int reason_index;
    bool sent_bye;
    bool sent_cancel;
    /* the Call-ID, if it fits */
    char id_storage[64];

    const char *getReason(char *buf, size_t size);
};
