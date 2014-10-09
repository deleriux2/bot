#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <linux/audit.h>
#include <libaudit.h>
#include <auparse.h>

#include "irc.h"
#include "audit_msg.h"

const static int accepted_types[] = {
  AUDIT_PATH,
};

static auparse_state_t *au = NULL;

/* Returns raw field data */
static int aumsg_find_int(
    const char *name)
{
  int type;
  if (auparse_find_field(au, name))
    return auparse_get_field_int(au);
  return -1;
}

static char * aumsg_find_str(
    const char *name)
{
  int type;
  const char *val;
  auparse_first_record(au);
  auparse_first_field(au);
  if (auparse_find_field(au, name)) {
    val = auparse_interpret_field(au);
    if (!val)
      return NULL;
    else
      return strdup(val);
  }
  return NULL;
}

static void audit_handle_event(
    auparse_state_t *au,
    auparse_cb_event_t cb_event_type,
    void *data)
{
  int i, fields;
  int type;
  irc_t *irc = (irc_t *)data;
  char record_buf[4096];

  /* Some useful audit records */
  const char *record;
  char *user = NULL, *euser = NULL, *exe = NULL;
  char *result = NULL, *addr = NULL, *pid = NULL;
  char *sig = NULL, *proctitle = NULL;
  char *syscall = NULL,  *class = NULL;

  memset(record_buf, 0, sizeof(record_buf));

  if (cb_event_type != AUPARSE_CB_EVENT_READY)
    return;

  if (auparse_first_record(au) <= 0)
    return;

  type = auparse_get_type(au);

  switch (type) {
    case AUDIT_USER_START:
    case AUDIT_USER_END:
      break;
      /* This is too chatty */
      /* Filter this specifically to avoid crond records */
      euser = aumsg_find_str("uid");
      user = aumsg_find_str("auid");
      exe = aumsg_find_str("exe");
      printf(" USER: %s\n", euser);
      printf("AUSER: %s\n", user);

      if (strcmp(user, euser) == 0)
        goto fin;

      if (type == AUDIT_USER_START)
        snprintf(record_buf, 4096, "Session started with privileges switched for user %s to %s using %s\n",
               user, euser, exe);
      else 
        snprintf(record_buf, 4096, "Session finished with privileges switched back to user %s from %s using %s\n",
               user, euser, exe);
    break;

    case AUDIT_LOGIN:
    case AUDIT_USER_LOGIN:
    case AUDIT_USER_LOGOUT:
      user = aumsg_find_str("auid");
      result = aumsg_find_str("res");
      addr = aumsg_find_str("addr");
      exe = aumsg_find_str("exe");
      if ((strncmp(result, "success", 7) != 0) && (strncmp(result, "yes", 3) != 0))
        goto fin;
      if (type == AUDIT_USER_LOGIN)
        snprintf(record_buf, 4096, "User %s has logged from %s in via %s\n", user, addr, exe);
      else if (type == AUDIT_LOGIN)
        snprintf(record_buf, 4096, "User %s has logged in\n", user);
      else
        snprintf(record_buf, 4096, "User %s has logged out\n", user);
    break;

    case AUDIT_ADD_USER:
    case AUDIT_DEL_USER:
      result = aumsg_find_str("res");
      record = auparse_get_record_text(au);
      if (strcmp(result, "success") != 0)
        goto fin;

      if (type == AUDIT_ADD_USER) {
        /* No other way to do this..*/
        if (strstr(record, "adding home directory")) {
          sleep(1);
          user = aumsg_find_str("id");
          snprintf(record_buf, 4096, "A new user was created: %s\n", user);
        }
      }
      else {
        if (strstr(record, "deleting user entries")) {
          user = aumsg_find_str("id");
          snprintf(record_buf, 4096, "A user was deleted: %s\n", user);
        }
      }

    case AUDIT_ADD_GROUP:
    case AUDIT_DEL_GROUP:
      result = aumsg_find_str("res");
      record = auparse_get_record_text(au);
      if (strcmp(result, "success") != 0)
        goto fin;

      if (type == AUDIT_ADD_GROUP) {
        /* No other way to do this..*/
        if (strstr(record, "adding group to")) {
          sleep(1);
          user = aumsg_find_str("id");
          snprintf(record_buf, 4096, "A new group was created: %s\n", user);
        }
      }
      else {
        if (strstr(record, "removing group from")) {
          user = aumsg_find_str("id");
          snprintf(record_buf, 4096, "A group was deleted: %s\n", user);
        }
      }
    break;

    case AUDIT_ANOM_ABEND:
      pid = aumsg_find_str("pid");
      user = aumsg_find_str("uid");
      exe = aumsg_find_str("exe");
      sig = aumsg_find_str("sig");

      snprintf(record_buf, 4096, "Application pid %s path %s running as user %s has crashed with signal %s\n",
               pid, exe, user, sig);
    break;

    case AUDIT_AVC:
      proctitle = aumsg_find_str("proctitle");
      user = aumsg_find_str("uid");
      class = aumsg_find_str("tclass");
      syscall = aumsg_find_str("seperms");
      result = aumsg_find_str("success");
      pid = aumsg_find_str("pid");
      snprintf(record_buf, 4096, "SELinux alert: Process %s with command %s owned by %s attempted to perform a %s on a %s. Success=%s.\n",
               pid, proctitle, user, syscall, class, result);
    break;
  }

  if (strlen(record_buf))
    irc_send(irc, "#selinux", record_buf);

fin:
  if (proctitle)
    free(proctitle);
  if (sig)
    free(sig);
  if (pid)
    free(pid);
  if (addr)
    free(addr);
  if (result)
    free(result);
  if (exe)
    free(exe);
  if (user)
    free(user);
  if (euser)
    free(euser);
  return;
}


void audit_msg_init(
    irc_t *irc)
{
  au = auparse_init(AUSOURCE_FEED, 0);
  if (!au)
    err(EXIT_FAILURE, "Could not initiate audit parser");

  auparse_add_callback(au, audit_handle_event, irc, NULL);
  return;
}


void audit_msg_dispatch(
    const char *buf,
    const int len)
{
  if (auparse_feed(au, buf, len) < 0)
    warn("auparse_feed");
}
