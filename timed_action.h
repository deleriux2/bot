#ifndef _TIMED_ACTION_H
#define _TIMED_ACTION_H
#include <sys/queue.h>
#include <sys/timerfd.h>

struct action {
  struct timespec when;
  void *data;
  int (*callback)(void *data);
  LIST_ENTRY(action) entries;
};


typedef struct timed_action {
  int actionid;
  int timerfd;
  LIST_HEAD(actions, action) actions_head;
} timed_action_t;


timed_action_t * timed_action_init(void);
int timed_action_get_fd(timed_action_t *ta);
void timed_action_destroy(timed_action_t *ta);
int timed_action_add(timed_action_t *ta, struct timespec *when, int (*callback)(void *), void *data);
int timed_action_dispatch(timed_action_t *ta);
#endif
