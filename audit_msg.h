#ifndef _AUDIT_MSG_
#define _AUDIT_MSG_
void audit_msg_init(irc_t *irc);

void audit_msg_dispatch(const char *buf, const int len);
#endif
