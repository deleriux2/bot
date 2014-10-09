#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "irc.h"

#define COOLDOWN 1

#define IRC_MODE_AWAY        0x00000001
#define IRC_MODE_INVISIBLE   0x00000002
#define IRC_MODE_WALLOP      0x00000004
#define IRC_MODE_RESTRICT    0x00000008
#define IRC_MODE_OPERATOR    0x00000010
#define IRC_MODE_LOPERATOR   0x00000020
#define IRC_MODE_NOTICE      0x00000040
#define IRC_MODE_MASKIP      0x00000080

#define IRC_MSGLONGTIME      333333

struct irc_data {
  char prefix[512];
  char command[512];
  char params[512];
};

static int irc_send_pong(irc_t *irc, struct irc_data *id);
static int dispatch(irc_t *irc, struct irc_data *id);
static int irc_get_mode(irc_t *irc, struct irc_data *id);
static int irc_get_join(irc_t *irc, struct irc_data *id);

irc_t * irc_connect(
    const char *hostname,
    const char *port,
    const char *nick,
    int flags)
{
  int fd;
  irc_t *irc = NULL;

  irc = malloc(sizeof(*irc));
  if (!irc)
    return NULL;

//  memset(irc, 0, sizeof(*irc));
  irc->mode = 0;
  irc->flags = 0;

  irc->session = tls_connect(hostname, port);
  if (!irc->session)
    goto fin;

  irc->flags = flags;
  irc->connected = 1;

  if (irc_login(irc, nick, "hanzelpass") < 0)
    goto fin;

  LIST_INIT(&irc->channels);

  strncpy(irc->hostname, hostname, sizeof(irc->hostname));
  strncpy(irc->port, port, sizeof(irc->port));
  return irc;

fin:
  if (irc) {
    if (irc->session)
      tls_disconnect(irc->session);
    free(irc);
  }
  return NULL;  
}


/* TEST THIS TEST THIS TEST THIS */
int irc_reconnect(
    irc_t *irc)
{
  tls_disconnect(irc->session);
  irc->session = tls_connect(irc->hostname, irc->port);
  if (!irc->session)
    goto fin;

  if (irc_login(irc, irc->nick, "") < 0)
    goto fin;
  
  irc->connected = 1;
  return 0;
fin:
  if (irc->session)
    tls_disconnect(irc->session);
  return -1;
}


int irc_set_nick(
    irc_t *irc,
    const char *nick)
{
  int rc;
  char buf[512];

  if (irc->connected) {
    /* can send nick when connected or logged in */
    rc = snprintf(buf, 1024, "NICK %s\r\n", nick);
    rc = tls_write(irc->session, buf, rc);
    if (rc <= 0)
      return -1;
  }
  /* The logged in flag is set once the MODE is sent from the server */

  strncpy(irc->nick, nick, sizeof(irc->nick));

  return 0;
}



void irc_set_flag(
    irc_t *irc,
    int flags)
{
  if (irc->connected)
    return;

  irc->flags = flags;
}



int irc_set_pass(
    irc_t *irc,
    const char *user,
    const char *pass)
{
  int rc;
  char buf[512];

  /* can send nick when connected or logged in */
  rc = snprintf(buf, 1024, "PASS %s:%s\r\n", user, pass);
  rc = tls_write(irc->session, buf, rc);
  if (rc <= 0)
    return -1;

  /* The logged in flag is set once the MODE is sent from the server */

  strncpy(irc->user, user, sizeof(irc->user));
  strncpy(irc->pass, pass, sizeof(irc->pass));
  return 0;
}



int irc_login(
    irc_t *irc,
    const char *nick,
    const char *pass)
{
  int rc;
  char buf[512];

  if ((irc->flags & IRC_FLAG_ZNC) == IRC_FLAG_ZNC)
    if (irc_set_pass(irc, nick, pass) < 0)
      return -1;

  if (irc_set_nick(irc, nick) < 0)
    return -1;

  /* Password not currently used, but this should be updated if necessary */
  rc = snprintf(buf, 1024, "USER %s 0 * :selinux_bot\r\n", nick);
  rc = tls_write(irc->session, buf, rc);
  if (rc <= 0)
    return -1;

  return 0;
}

int irc_part(
    irc_t *irc,
    const char *chnl)
{
  int rc;
  char buf[512];

  struct channel *chan;
  for (chan = irc->channels.lh_first; chan != NULL; chan = chan->entries.le_next) {

    if (strncmp(chan->channelname, chnl, sizeof(chan->channelname)) == 0) {
      rc = snprintf(buf, 512, "PART %s\r\n", chnl);
      rc = tls_write(irc->session, buf, rc);
      if (rc <= 0)
        return -1;
      break;
    }

  }

  return 0;
}

int irc_join(
    irc_t *irc,
    const char *channel)
{
  int rc;
  char buf[512];

  if (irc->logged_in) {
    rc = snprintf(buf, 512, "JOIN %s\r\n", channel);
    rc = tls_write(irc->session, buf, rc);
    if (rc <= 0)
      return -1;
  }

  return 0;
}


int irc_get_fd(
    irc_t *irc)
{
  return tls_fd(irc->session);
}

int irc_send(
    irc_t *irc,
    const char *target,
    char *message)
{
  int rc;
  char msgbuf[512];
  char buf[512];
  int mlen = strlen(message);
  int prelen = 8 + strlen(target) + 3; /* "PRIVMSG +<target> ... +\r\n" */
  int mblen;
  char *p;
  char *mb;

  if (!irc->logged_in)
    return -1;

  /* Since we can never send > 512 bytes, we must chop up the message into 
     smaller chunks and send them instead. Theres a cooldown between sends.
  */
  p = message;
  /* Add some cooldown between message sends */
  while (mlen > (512-prelen) || strstr(p, "\n") != NULL) {
    memset(msgbuf, 0, sizeof(msgbuf));
    memcpy(msgbuf, p, (512-prelen));

    mb = msgbuf;
    if ( ((mb = strstr(mb, "\n"))) || ((mb = rindex(mb, ' '))) ) {
      mblen = (mb+1) - msgbuf;
      *mb = 0;
    }
    else
      mblen = strlen(msgbuf);
    p += mblen;
    mlen -= mblen;

    if (mblen == 1 && msgbuf[0] == '\n')
      continue;

    rc = snprintf(buf, 512, "PRIVMSG %s %s\r\n", target, msgbuf);
    if (tls_write(irc->session, buf, rc) < 0)
      return -1;
    usleep(IRC_MSGLONGTIME);
  }

  memset(msgbuf, 0, sizeof(msgbuf));
  memset(buf, 0, sizeof(buf));
  strncpy(msgbuf, p, 512-prelen);
  if (strlen(msgbuf)== 0 || strlen(msgbuf) == 1 && msgbuf[0] == '\n')
    return 0;

  rc = snprintf(buf, 512, "PRIVMSG %s %s\r\n", target, msgbuf);
  if ((rc = tls_write(irc->session, buf, rc)) < 0)
    return -1;
  sleep(COOLDOWN);
  return rc;
}


int irc_dispatch(
    irc_t *irc)
{
  int rc, rc2;
  char *buf = NULL;
  struct irc_data *id = NULL;
  /* Read a line from the server */

  for (;;) {
    rc = tls_read(irc->session, &buf);
    if (rc <= 0)
      goto end;

    /* Parse the IRC message */
    id = malloc(sizeof(*id));
    memset(id, 0, sizeof(*id));

    if (sscanf(buf, ":%s %s %[^\r\n]\r\n", 
               id->prefix, id->command, id->params) < 3)
    {
      if (sscanf(buf, "%s %[^\r\n]\r\n", id->command, id->params) < 2) {
        fprintf(stderr, "WARNING: Dropping junk..\n");
        goto end;
      }
    }

    dispatch(irc, id);
    free(id);
    id = NULL;
    free(buf);
    buf = NULL;
    rc2 = tls_read_pending();
    if (!rc2)
      break;
  }

end:
  if (id)
    free(id);
  if (buf)
    free(buf);
  return rc;
}



static int irc_send_pong(
    irc_t *irc,
    struct irc_data *id)
{
  char buf[512];
  int rc;

  rc = snprintf(buf, 512, "PONG %s\r\n", id->params);
  return tls_write(irc->session, buf, rc);
}


static int irc_get_mode(
    irc_t *irc,
    struct irc_data *id)
{
  int rc;
  int len;
  int i;

  char nick[64];
  char mode[8];
  char operator;
  int flags = 0;

  memset(nick, 0, sizeof(nick));
  memset(mode, 0, sizeof(mode));
  operator = 0;

  rc = sscanf(id->params, "%s :%c%8s", nick, &operator, mode);
  if (rc < 3)
    return 0;

  if (strncmp(nick, irc->nick, sizeof(irc->nick)))
    return 0;

  len = strlen(mode);

  for (i=0; i < len; i++) {
    switch(mode[i]) {
      case 'a':
        flags |= IRC_MODE_AWAY;
      break;
      case 'i':
        flags |= IRC_MODE_INVISIBLE;
      break;
      case 'w':
        flags |= IRC_MODE_WALLOP;
      break;
      case 'r':
        flags |= IRC_MODE_RESTRICT;
      break;
      case 'o':
        flags |= IRC_MODE_OPERATOR;
      break;
      case 'O':
        flags |= IRC_MODE_LOPERATOR;
      break;
      case 's':
        flags |= IRC_MODE_NOTICE;
      break;
      case 'x':
        flags |= IRC_MODE_MASKIP;
      break;
      default:
        printf("UNKNOWN MODE: %c\n", mode[i]);
      break;
    }
  }

  if (operator == '+')
    irc->mode |= flags;
  else if (operator == '-')
    irc->mode ^= flags;
  else
    return 0;

  irc->logged_in = 1;

  return 1;
}


static int irc_get_join(
    irc_t *irc,
    struct irc_data *id)
{
  int rc;
  char channel[512];
  struct channel *c = NULL;

  memset(channel, 0, sizeof(channel));

  if (sscanf(id->params, ":%s", channel) < 0)
    return 0;

  c = malloc(sizeof(*c));
  if (!c)
    return -1;

  strncpy(c->channelname, channel, sizeof(c->channelname));
  LIST_INSERT_HEAD(&irc->channels, c, entries);
}

static int irc_get_part(
    irc_t *irc,
    struct irc_data *id)
{
  int rc;
  char channel[512];
  struct channel *c = NULL;

  memset(channel, 0, sizeof(channel));

  if (sscanf(id->params, "%s", channel) < 0)
    return 0;

  for (c = irc->channels.lh_first; c != NULL; c = c->entries.le_next) {
    if (strncmp(channel, c->channelname, 64) == 0) {
      LIST_REMOVE(c, entries);
      free(c);
      break;
    }
  }

  return 0;
}


static int dispatch(
    irc_t *irc,
    struct irc_data *id)
{
  int rc=0;

  if (strcmp(id->command, "PING") == 0)
    rc = irc_send_pong(irc, id);

  else if (strcmp(id->command, "MODE") == 0)
    rc = irc_get_mode(irc, id);

  else if (strcmp(id->command, "JOIN") == 0)
    rc = irc_get_join(irc, id);

  else if (strcmp(id->command, "PART") == 0)
    rc = irc_get_part(irc, id);

  else {
    ;//printf("%s %s %s\n", id->prefix, id->command, id->params);
  }

  return rc;
}

