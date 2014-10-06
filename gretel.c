#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <mqueue.h>
#include <grp.h>

#include <libaudit.h>

#define QNAME "/gretel"
#define QGRP "wheel"
#define EVENT_HANDLES 2

static int copy_audit_data(int infd, mqd_t out);
static int handle_signal(int sigfd);
static int config_sighandlers(void);
static mqd_t config_messagequeue(void);

/* audisp expects us to handle HUP and TERM. So lets handle it */
int main(
    const int argc,
    const char **argv)
{
  int rc, i;
  int poll = -1;
  int sigfd = -1;
  mqd_t mq = -1;
  struct epoll_event ev[EVENT_HANDLES];

  /* Setup the epoll */
  poll = epoll_create1(EPOLL_CLOEXEC);
  if (poll < 0)
    err(EXIT_FAILURE, "Cannot setup poll");

  /* Configure signal handlers */
  sigfd = config_sighandlers();

  ev[0].events = EPOLLIN;
  ev[0].data.fd = 0;
  ev[1].events = EPOLLIN;
  ev[1].data.fd = sigfd;

  /* Poll on the relevent file descriptors */
  if (epoll_ctl(poll, EPOLL_CTL_ADD, 0, &ev[0]) < 0)
    err(EXIT_FAILURE, "Unable to add to polling set");
  if (epoll_ctl(poll, EPOLL_CTL_ADD, sigfd, &ev[1]) < 0)
    err(EXIT_FAILURE, "Unable to add to polling set");

  /* Setup the message queue */
  mq = config_messagequeue();

  /* Go into the event loop */
  do {
    rc = epoll_wait(poll, ev, EVENT_HANDLES, -1);
    if (rc < 0 && errno == EINTR)
      continue;
    else if (rc < 0)
      err(EXIT_FAILURE, "Cannot poll file descriptors");

    for (i=0; i < rc; i++) {
      
      if (ev[i].data.fd == 0) {
        rc = copy_audit_data(0, mq);
        if (rc < 0)
          err(EXIT_FAILURE, "Error copying audit data");
      }
      else if (ev[i].data.fd == sigfd) {
        rc = handle_signal(sigfd);
        if (rc < 0) 
          break;
      }
    }
  } while (rc >= 0);
}


/* Copy from audit data and pass to queue.
   If it blocks, leave it blocked */
static int copy_audit_data(
    int infd,
    mqd_t out)
{
  char buf[MAX_AUDIT_MESSAGE_LENGTH];
  int rc;
  memset(buf, 0, sizeof(buf));

  rc = read(infd, buf, MAX_AUDIT_MESSAGE_LENGTH);
  /* Error or end of data */
  if (rc <= 0)
    return -1;

  if (mq_send(out, buf, rc, 0) < 0)
    return -1;

  return 0;
}


/* Recieves and deals with signals */
static int handle_signal(
    int sigfd)
{
  int rc;
  struct signalfd_siginfo siginfo;
  rc = read(sigfd, &siginfo, sizeof(siginfo));
  if (rc != sizeof(siginfo)) {
    warn("Bad read on signal info");
    return -1;
  }

  switch (siginfo.ssi_signo) {
    case SIGTERM:
      warn("Received notice to quit. Terminating");
      return -1;
    break;

    case SIGHUP:
      warn("Reloading dispatcher");
      return 0;
    break;

    default:
      warn("Received unknown signal in sigfd");
      return -1;
    break;
  }

  return -1;
}

static int config_sighandlers(
    void)
{
  sigset_t sigs;
  int fd = -1;

  if (sigemptyset(&sigs) < 0)
    err(EXIT_FAILURE, "Error initializing sigset");

  if (sigaddset(&sigs, SIGINT) < 0)
    err(EXIT_FAILURE, "Error initializing sigset");
  if (sigaddset(&sigs, SIGTERM) < 0)
    err(EXIT_FAILURE, "Error initializing sigset");

  /* Block these signals from their normal handling routines */
  if (sigprocmask(SIG_BLOCK, &sigs, NULL) < 0)
    err(EXIT_FAILURE, "Unable to mask signals");

  fd = signalfd(-1, &sigs, SFD_CLOEXEC);
  if (fd < 0)
    err(EXIT_FAILURE, "Cannot setup signalfd");
 
  return fd;
}

/* Configures the message queue */
static int config_messagequeue(
    void)
{
  struct group *grp;
  mqd_t m = -1;

  grp = getgrnam(QGRP);
  if (!grp)
    errx(EXIT_FAILURE, "Cannot get gid for %s", QGRP);

  m = mq_open(QNAME, O_WRONLY|O_CREAT, 0660, NULL);
  if (m < 0)
    err(EXIT_FAILURE, "Cannot setup message queue");

  if (fchown(m, getuid(), grp->gr_gid) < 0)
    warn("Had difficulty setting ownerships on the message queue");

  return m;
}

