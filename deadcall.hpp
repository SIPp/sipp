#include "call.hpp"

class deadcall : public virtual task, public virtual listener {
public:
  deadcall(char *id, char * reason);
  ~deadcall();

  virtual bool process_incoming(char * msg, struct sockaddr_storage *);
  virtual bool  process_twinSippCom(char * msg);

  virtual bool run();

  /* When should this call wake up? */
  virtual unsigned int wake();

  /* Dump call info to error log. */
  virtual void dump();

protected:
  unsigned long expiration;
  char *reason;
};
