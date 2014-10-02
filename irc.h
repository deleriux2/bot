#ifndef _IRC_H_
#define _IRC_H_

#include "tls.h"
#include <sys/queue.h>

#define IRC_FLAG_ZNC 1

struct channel {
  LIST_ENTRY(channel) entries;
  char channelname[64];
};

typedef struct _irc {
  char hostname[256];
  char port[32];
  char user[64];
  char pass[64];
  char nick[64];
  int connected;
  int logged_in;
  int flags;
  int mode;
  char error[512];
  gnutls_session_t session;
  LIST_HEAD(_channels, channel) channels;
} irc_t;

irc_t * irc_connect(const char *hostname, const char *port, const char *nick, int flags);
int irc_reconnect(irc_t *irc);

int irc_set_nick(irc_t *irc, const char *nick);
int irc_set_pass(irc_t *irc, const char *user, const char *pass);
int irc_login(irc_t *irc, const char *nick, const char *pass);
int irc_join(irc_t *irc, const char *channel);
int irc_part(irc_t *irc, const char *chnl);
int irc_get_fd(irc_t *irc);
void irc_set_flag(irc_t *irc, int flag);

#endif
