#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <sys/epoll.h>

#include "irc.h"

#define CAFILE "/etc/pki/tls/cert.pem"
#define NICK "hanzel"

/* TODO: 
 * A way better configuration matrix
 * Part channels nicely on exit.
 * Handle the situation where you get disconnected.
 * Rate limiting.
 * A configuration database.
 */

struct config {
  char hostname[256];
  char port[64];
  char nickname[64];
  char channel[64];
} config;

struct irc_msg {
  char prefix[256];
  char command[256];
  char params[2048];
};




/* Needs some work, totally temporary */
void parse_config(
    const int argc,
    const char **argv)
{
  strncpy(config.hostname, "irc.hashbang.sh", strlen("irc.hashbang.sh"));
  strncpy(config.port, "4446", 4);
  strncpy(config.nickname, "hanzel", 6);
  strncpy(config.channel, "#selinux", 8);
}

static int handle_message(
    gnutls_session_t session,
    struct irc_msg *msg)
{
  char buf[4096];
  int len, rc=0;

  if (strncmp(msg->command, "PING", sizeof(msg->command)) == 0) {
    printf("Sending PONG message\n");
    rc = snprintf(buf, len, "PONG %s", msg->params);
  }
  else if (strncmp(msg->command, "MODE", sizeof(msg->command)) == 0) {
    printf("Received mode\n");
    if ((rc = join_channel(session, config.channel)) < 0)
      rc = -1;
  }

  /* Ignore all else */
  else {
    printf(":%s %s %s", msg->prefix, msg->command, msg->params);
  }

  if (rc)
    rc = gnutls_record_send(session, buf, rc);
  return rc;
}

int join_channel(
    gnutls_session_t session,
    const char *channel)
{
  char buf[1024];
  int rc;
  rc = snprintf(buf, 1024, "JOIN %s\r\n", channel);
  rc = gnutls_record_send(session, buf, rc);
  if (rc <= 0)
    return -1;

  return 0;
}


int main(
  const int argc,
  const char **argv)
{
  int rc, fd, rc2, i;
  char *data;
  int poll;
  struct epoll_event ev[1];

  irc_t *irc;

  parse_config(argc, argv);

  tls_setup(CAFILE);
  irc = irc_connect(config.hostname, config.port, config.nickname, IRC_FLAG_ZNC);
  fd = irc_get_fd(irc);

  /* Setup the polling object */
  ev[0].events = EPOLLIN;
  ev[0].data.fd = fd;
  poll = epoll_create1(EPOLL_CLOEXEC);
  if (poll < 0)
    err(EXIT_FAILURE, "Cannot create polling object");

  if (epoll_ctl(poll, EPOLL_CTL_ADD, fd, &ev[0]) < 0)
    err(EXIT_FAILURE, "Cannot add fd to polling object");

  /* Go into polling loop */
  do {
    rc = epoll_wait(poll, ev, 1, -1);
    if (rc < 0)
      err(EXIT_FAILURE, "Polling failed");

    for (i = 0; i < rc; i++) {
      if (ev[i].data.fd == fd)
        rc = irc_dispatch(irc);

      if (rc < 0)
        break;
    }

  } while (rc >= 0);
}

