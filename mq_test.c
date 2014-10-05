#include <stdlib.h>
#include <stdio.h>
#include <mqueue.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

int main(
    const int argc,
    const char **argv)
{
  int rc;
  mqd_t mq;
  char qname[256];
  struct mq_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.mq_flags = 0;
  attr.mq_maxmsg = 64;
  attr.mq_msgsize = 128*1024;


  if (argc < 3)
    err(EXIT_FAILURE, "Must provide a queue name and message");

  memset(qname, 0, sizeof(qname));
  snprintf(qname, 256, "/%s", argv[1]);
  mq = mq_open(qname, O_WRONLY|O_CREAT, 0660, NULL);
  if (mq < 0)
    err(EXIT_FAILURE, "Cannot open message queue");

  rc = mq_setattr(mq, &attr, NULL);
  if (rc < 0)
    err(EXIT_FAILURE, "Could not set attr");

  rc = strlen(argv[2]);
  rc = mq_send(mq, argv[2], rc, 0);
  if (rc < 0)
    err(EXIT_FAILURE, "Error sending to queue");

  printf("OK\n");
  exit(0);  
}
