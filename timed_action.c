#include "timed_action.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/time.h>

timed_action_t * timed_action_init(
    void)
{
  int rc;
  timed_action_t *ta = NULL;

  ta = malloc(sizeof(timed_action_t));
  if (!ta)
    return NULL;

  ta->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  LIST_INIT(&ta->actions_head);
  if (ta->timerfd < 0)
    goto fin;

  return ta;

fin:
  rc = errno;
  if (ta && ta->timerfd > -1)
    close(ta->timerfd);
  if (ta)
    free(ta);
  errno = rc;
  return NULL;
}

int timed_action_get_fd(
    timed_action_t *ta)
{
  if (ta)
    return ta->timerfd;
  return -1;
}

void timed_action_destroy(
    timed_action_t *ta)
{
  struct action *a;
  if (ta && ta->timerfd)
    close(ta->timerfd);
  if (ta) {
    while (ta->actions_head.lh_first) {
      a = ta->actions_head.lh_first;
      LIST_REMOVE(a, entries);
      free(a);
    }
    free(ta);
  }
}


int timed_action_add(
    timed_action_t *ta,
    struct timespec *when,
    int (*callback)(void *),
    void *data)
{
  int rc;
  struct itimerspec next;
  struct itimerspec set;
  struct itimerspec arm;

  struct action *action = NULL;
  struct action *inspect = NULL;
  struct action *inspect_nxt = NULL;

  memset(&set, 0, sizeof(set));
  memset(&arm, 0, sizeof(arm));
  arm.it_value.tv_sec = when->tv_sec;
  arm.it_value.tv_nsec = when->tv_nsec;

  /* Get the next timed event */
  rc = timerfd_gettime(ta->timerfd, &next);
  if (rc < 0)
    goto fail;

  /* If the timer is all zeroes the timer isn't armed */
  if (next.it_interval.tv_sec == 0 && 
      next.it_interval.tv_nsec == 0 &&
      next.it_value.tv_sec == 0 &&
      next.it_value.tv_nsec == 0)
    goto set;

  /* Use this value to determine the next time */
  set.it_value.tv_sec = when->tv_sec;
  set.it_value.tv_nsec = when->tv_nsec;

  set.it_value.tv_sec -= next.it_value.tv_sec;
  set.it_value.tv_nsec -= next.it_value.tv_nsec;

  /* If the values are equal, which is unlikely. Schedule this one to go after the last */
  if (set.it_value.tv_sec == 0 && set.it_value.tv_nsec == 0) {
    goto assign;
  }

  /* If this time occurs before next, we must rearm the timer */
  if (set.it_value.tv_sec == 0 && set.it_value.tv_nsec < 0 ||
      set.it_value.tv_sec < 0)
    goto set;

  /* Arms or rearms the timer */
set:
  if (timerfd_settime(ta->timerfd, 0, &arm, NULL) < 0)
    goto fail;


  /* Assign the callback to the list. This list must be ordered
     by nearest callback time */
assign:
  action = malloc(sizeof(*action));
  if (!action)
    goto fail;
  memset(action, 0, sizeof(*action));

  action->when.tv_sec = when->tv_sec;
  action->when.tv_nsec = when->tv_nsec;
  action->data = data;
  action->callback = callback;

  inspect = ta->actions_head.lh_first;
  while (inspect) {
    inspect_nxt = inspect->entries.le_next;

    /* If the value is just smaller than the first entry,
       we insert it as a head value */
    if (when->tv_sec == inspect->when.tv_sec &&
        when->tv_nsec < inspect->when.tv_nsec ||
        when->tv_sec < inspect->when.tv_sec) {
      inspect = NULL;
      break;
    }

    /* If no next entry exists, we are at the end of the queue,
       and the entry belongs on the tail */
    if (inspect_nxt == NULL)
      break;

    /* If the value lies between this one and the next,
       insert it there */
    if (when->tv_sec >= inspect->when.tv_sec &&
        when->tv_sec <= inspect_nxt->when.tv_sec &&
        when->tv_nsec >= inspect->when.tv_nsec &&
        when->tv_nsec <= inspect_nxt->when.tv_nsec) {
      break;
    }

    inspect = inspect_nxt;
  }

  if (inspect == NULL)
    LIST_INSERT_HEAD(&ta->actions_head, action, entries);
  else
    LIST_INSERT_AFTER(inspect, action, entries);

  return 0;

fail:
  rc = errno;
  if (action)
    free(action);
  errno = rc;
  return -1;
  
}

int timed_action_dispatch(
    timed_action_t *ta)
{
  int rc, i;
  struct timespec when;
  struct itimerspec arm;
  struct action *act, *tmp;
  unsigned long long events;
  /* Read from the timerfd */
  if (read(ta->timerfd, &events, sizeof(events)) < 0)
    goto fail;

  /* Process events number of events from the queue. If any fail abort. */
  for (i=0; i < events; i++) {
    /* Pull in the action */
    act = ta->actions_head.lh_first;

    /* There are more events than actions?? */
    if (!act)
      return -1;

    while (act) {
      when.tv_sec = act->when.tv_sec;
      when.tv_nsec = act->when.tv_nsec;
      tmp = act;

      /* Execute this action */
      if (!act->callback || act->callback(act->data) < 0)
        goto fail;
      /* If the when of this is the same as the when of next
         then switch to next action and process that too */
      if (act->entries.le_next &&
          act->when.tv_sec == act->entries.le_next->when.tv_sec &&
          act->when.tv_nsec == act->entries.le_next->when.tv_nsec)
        act = act->entries.le_next;
      else
        act = NULL;
      LIST_REMOVE(tmp, entries);
      free(tmp);
    }
  }

  /* All events are done. If we have more events in the queue,
     then we must re-arm the timer */
  if (ta->actions_head.lh_first) {
    when.tv_sec = ta->actions_head.lh_first->when.tv_sec - when.tv_sec;
    when.tv_nsec = ta->actions_head.lh_first->when.tv_nsec - when.tv_nsec;
    if (when.tv_nsec < 0) {
      when.tv_sec--;
      when.tv_nsec = -when.tv_nsec;
    }

    memset(&arm, 0, sizeof(arm));
    arm.it_value.tv_sec = when.tv_sec;
    arm.it_value.tv_nsec = when.tv_nsec;
    if (timerfd_settime(ta->timerfd, 0, &arm, NULL) < 0)
      goto fail;
  }

  return 0;

fail:
  return -1;
}
