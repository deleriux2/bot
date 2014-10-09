#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <mqueue.h>

#include <sys/epoll.h>

#include "irc.h"
#include "timed_action.h"
#include "audit_msg.h"

#define CAFILE "/etc/ca-bundle.pem"
#define NICK "hanzel1"

/* TODO: 
 * A way better configuration matrix
 * Part channels nicely on exit.
 * Handle the situation where you get disconnected!!!!
 * A configuration database.
 */

struct config {
  char hostname[256];
  char port[64];
  char nickname[64];
  char channel[64];
  char qname[256];
} config;

struct msgq {
  mqd_t q;
  irc_t *irc;
  char channel[64];
};

/* Super private structures */
struct join_chan {
  irc_t *irc;
  char channel[64];
};

static int join_channel(void *data);


/* Needs some work, totally temporary */
void parse_config(
    const int argc,
    const char **argv)
{
  strncpy(config.hostname, "irc.hashbang.sh", strlen("irc.hashbang.sh"));
//  strncpy(config.port, "4446", 4);
  strncpy(config.port, "6697", 4);
  strncpy(config.nickname, "hanzel1", 7);
  strncpy(config.channel, "#selinux", 8);
  strncpy(config.qname, "/gretel", 7);
}

static int join_channel(
    void *data)
{
  struct join_chan *chan = (struct join_chan *)data;
  return irc_join(chan->irc, chan->channel);
}

static struct msgq * messageq_setup(
    const char *qname,
    const char *channel,
    irc_t *irc)
{
  struct msgq *q = malloc(sizeof(*q));
  if (!q)
    err(EXIT_FAILURE, "Cannot allocate for message queue");

  q->q = mq_open(qname, O_RDONLY|O_CREAT, 0660, NULL);
  if (q->q < 0)
    err(EXIT_FAILURE, "Cannot open message queue");

  q->irc = irc;
  strncpy(q->channel, channel, sizeof(q->channel));

  return q;
}


int messageq_dispatch(
    struct msgq *q)
{
  int rc;
  int len;
  char buf[8192];

  memset(buf, 0, sizeof(buf));
  if (!q->irc->logged_in) {
    usleep(100000);
    return 0;
  }

  len = mq_receive(q->q, buf, sizeof(buf), NULL);
  if (len < 0)
    return -1;

  /* Pass this to the audit library */
  audit_msg_dispatch(buf, len);

  return 0;
}



int main(
  const int argc,
  const char **argv)
{
  int rc, fd, rc2, i;
  char *data;
  int events;
  int poll;
  struct msgq *mq;
  struct timespec when;
  struct epoll_event ev[3];
  struct join_chan d;

  timed_action_t *ta;
  irc_t *irc;

  parse_config(argc, argv);

  tls_setup(CAFILE);
  /* Setup the IRC connection */
  //irc = irc_connect(config.hostname, config.port, config.nickname, IRC_FLAG_ZNC);
  irc = irc_connect(config.hostname, config.port, config.nickname, 0);

  /* Enable the audit parser */
  audit_msg_init(irc);

  /* Setup the timed action */
  ta = timed_action_init();
  if (!ta)
    err(EXIT_FAILURE, "Could not setup timed action");

  /* Attach to the message queue. */
  mq = messageq_setup(config.qname, config.channel, irc);

  /* Join a room after a period of timeout */
  when.tv_nsec = 0;
  when.tv_sec = 4;
  d.irc = irc;
  strncpy(d.channel, config.channel, 64);

  if (timed_action_add(ta, &when, join_channel, &d) < 0)
    err(EXIT_FAILURE, "Cannot initiate timed action add");

  /* Setup the polling object */
  ev[0].events = EPOLLIN;
  ev[0].data.fd = irc_get_fd(irc);
  ev[1].events = EPOLLIN;
  ev[1].data.fd = timed_action_get_fd(ta);
  ev[2].events = EPOLLIN;
  ev[2].data.fd = mq->q;
  poll = epoll_create1(EPOLL_CLOEXEC);
  if (poll < 0)
    err(EXIT_FAILURE, "Cannot create polling object");

  if (epoll_ctl(poll, EPOLL_CTL_ADD, irc_get_fd(irc), &ev[0]) < 0)
    err(EXIT_FAILURE, "Cannot add fd to polling object");
  if (epoll_ctl(poll, EPOLL_CTL_ADD, timed_action_get_fd(ta), &ev[1]) < 0)
    err(EXIT_FAILURE, "Cannot add fd to polling object");
  if (epoll_ctl(poll, EPOLL_CTL_ADD, mq->q, &ev[2]) < 0)
    err(EXIT_FAILURE, "Cannot add fd to polling object");

  /* Go into polling loop */
  do {
    events = epoll_wait(poll, ev, 2, -1);
    if (events < 0)
      err(EXIT_FAILURE, "Polling failed");

    for (i = 0; i < events; i++) {
      if (ev[i].data.fd == irc_get_fd(irc)) {
        rc = irc_dispatch(irc);
        if (rc == 0)
          goto end;
      }
      else if (ev[i].data.fd == timed_action_get_fd(ta))
        rc = timed_action_dispatch(ta);
      else if (ev[i].data.fd == mq->q)
        rc = messageq_dispatch(mq);

      if (rc < 0)
        break;
    }

  } while (rc >= 0);

end:
  exit(1);
}



