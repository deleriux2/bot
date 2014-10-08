#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <limits.h>

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

struct config {
  char configfile[NAME_MAX];
  char queue_name[NAME_MAX];
  char qgrp[128];
  int poll;
  mqd_t mq;
};

static int is_whitespace(const char *str);
static int parse_config(const char *filename);
static int copy_audit_data(int infd, mqd_t out);
static int handle_signal(int sigfd);
static int config_sighandlers(void);
static mqd_t config_messagequeue(struct config *conf);

struct config *conf;

/* audisp expects us to handle HUP and TERM. So lets handle it */
int main(
    const int argc,
    const char **argv)
{
  int rc, i;
  int poll = -1;
  int sigfd = -1;
  int events;
  struct epoll_event ev[EVENT_HANDLES];
  if (argc < 2)
    errx(EXIT_FAILURE, "Expect path to configuration file");

  /* Parse the config */
  if (parse_config(argv[1]) < 0)
    errx(EXIT_FAILURE, "Cannot parse configuration file. Aborting");

  /* Setup the epoll */
  conf->poll = epoll_create1(EPOLL_CLOEXEC);
  if (conf->poll < 0)
    err(EXIT_FAILURE, "Cannot setup poll");

  /* Configure signal handlers */
  sigfd = config_sighandlers();

  ev[0].events = EPOLLIN;
  ev[0].data.fd = 0;
  ev[1].events = EPOLLIN;
  ev[1].data.fd = sigfd;

  /* Poll on the relevent file descriptors */
  if (epoll_ctl(conf->poll, EPOLL_CTL_ADD, 0, &ev[0]) < 0)
    err(EXIT_FAILURE, "Unable to add to polling set");
  if (epoll_ctl(conf->poll, EPOLL_CTL_ADD, sigfd, &ev[1]) < 0)
    err(EXIT_FAILURE, "Unable to add to polling set");

  /* Go into the event loop */
  do {
    events = epoll_wait(conf->poll, ev, EVENT_HANDLES, -1);
    if (events < 0 && errno == EINTR)
      continue;
    else if (events < 0)
      err(EXIT_FAILURE, "Cannot poll file descriptors");

    for (i=0; i < events; i++) {
      
      if (ev[i].data.fd == 0) {
        rc = copy_audit_data(0, conf->mq);
        if (rc < 0)
          err(EXIT_FAILURE, "Error copying audit data");
        else if (rc == 0) {
          break;
        }
      }
      else if (ev[i].data.fd == sigfd) {
        rc = handle_signal(sigfd);
        if (rc < 0) 
          break;
      }
    }
  } while (events >= 0 && rc > 0);

  exit(EXIT_FAILURE);
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
    return rc;

  if (mq_send(out, buf, rc, 0) < 0)
    return -1;

  return strlen(buf);
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
      parse_config(conf->configfile);
      return 0;
    break;

    case SIGINT:
      warn("Received notice to quit .Terminating");
      return -1;
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
  if (sigaddset(&sigs, SIGHUP) < 0)
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
    struct config *conf)
{
  struct group *grp;
  mqd_t m = -1;

  grp = getgrnam(conf->qgrp);
  if (!grp)
    errx(EXIT_FAILURE, "Cannot get gid for %s", conf->qgrp);

  m = mq_open(QNAME, O_WRONLY|O_CREAT, 0660, NULL);
  if (m < 0)
    err(EXIT_FAILURE, "Cannot setup message queue");

  if (fchown(m, getuid(), grp->gr_gid) < 0)
    warn("Had difficulty setting ownerships on the message queue");

  return m;
}

static int is_whitespace(
    const char *str)
{
  int len = strlen(str);
  int i;
  if (len == 0)
    return 1;

  for (i=0; i < len; i++) {
    if (!isspace(str[i]))
      return 0;
  }
  return 1;
}


/* Sets up the configuration of this program */
static int parse_config(
    const char *filename)
{
  FILE *c = NULL;
  char buf[4096];
  char name[256];
  char value[256];
  struct epoll_event ev;

  struct config *new = malloc(sizeof(struct config));
  if (!new)
    goto fail;

  memset(new, 0, sizeof(new));
  memset(buf, 0, sizeof(buf));

  strncpy(new->configfile, filename, NAME_MAX);
  if (conf) {
    new->poll = conf->poll;
  }
  else {
    new->poll = -1;
  }

  c = fopen(filename, "r");
  if (!c)
    goto fail;

  while (!feof(c)) {
    memset(name, 0, sizeof(name));
    memset(value, 0, sizeof(value));
    if (fgets(buf, sizeof(buf), c) == NULL)
      break;

    /* Skip over comments of whitespace */
    if (buf[0] == '#' || is_whitespace(buf))
      continue;

    if (sscanf(buf, "%[a-zA-Z0-9_] = %[a-zA-Z0-9_];\n", name, value) != 2) {
      warnx("Parse configuration failure. Expected \"name = value;\", but got \"%s\"", buf);
      goto fail;
    }

    if (strcmp(name, "queue_name") == 0 && new->queue_name[0] == 0)
      strncpy(new->queue_name, value, NAME_MAX);
    else if (strcmp(name, "queue_group") == 0 && new->qgrp[0] == 0)
      strncpy(new->qgrp, value, 128);
    else {
      warnx("Spurious entry in config file: %s\n", buf);
      goto fail;
    }
  }

  if (new->queue_name[0] == 0 || new->qgrp[0] == 0) {
    warnx("Required entries in config file were not present");
    goto fail;
  }

  /* Fill in the other entries and recreate the mq file */
  new->mq = config_messagequeue(new);
  /* Close the old queue */
  if (conf && conf->mq > -1) {
    close(conf->mq);
    free(conf);
  }
  conf = new;
  return 0;

fail:
  if (c)
    fclose(c);
  if (new)
   free(new);
  return -1;
}	
