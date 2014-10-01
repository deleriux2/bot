#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define CAFILE "/etc/pki/tls/cert.pem"
#define NICK "hanzel"

// WARNING: EXPECT THIS TO BE TOTALLY REWRITTEN
/* TODO: Keep track of channels bot is a member of.
 * A way better configuration matrix
 * Part channels nicely on exit.
 * Do proper event handling with epoll
 * Handle the situation where you get disconnected.
 * Rate limiting.
 * A configuration database.
 */

struct irc_bot_state {
  char buffer[16384];
} state;

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

gnutls_certificate_credentials_t xcred;


/* Needs some work, totally temporary */
void parse_config(
    const int argc,
    const char **argv)
{
  strncpy(config.hostname, "irc.hashbang.sh", strlen("irc.hashbang.sh"));
  strncpy(config.port, "6697", 4);
  strncpy(config.nickname, "hanzel", 6);
  strncpy(config.channel, "#selinux", 8);
}

static void tls_setup(
    void)
{
  int rc;

  if (gnutls_check_version("3.1.4") == NULL)
    err(EXIT_FAILURE, "GnuTLS 3.1.4 or later is required.\n");

  gnutls_global_init();

  /* Load root certifictes */
  rc = gnutls_certificate_allocate_credentials(&xcred);
  if (rc != GNUTLS_E_SUCCESS) 
    errx(EXIT_FAILURE, "Cannot allocate credential structure: %s", 
                                               gnutls_strerror(rc));

  rc = gnutls_certificate_set_x509_trust_file(xcred, CAFILE,
                                               GNUTLS_X509_FMT_PEM);
  if (rc < 0)
    errx(EXIT_FAILURE, "Unable to load root certificates: %s",
                                               gnutls_strerror(rc));


}


static int tcp_connect(
    const char *host,
    const char *port)
{
  int fd, rc;
  struct addrinfo *ai;

  rc = getaddrinfo(host, port, NULL, &ai);
  if (rc)
    errx(EXIT_FAILURE, "DNS resolultion error: %s", gai_strerror(rc));

  fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0)
    err(EXIT_FAILURE, "Cannot create socket");

  if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0)
    err(EXIT_FAILURE, "Cannot connect to host");

  freeaddrinfo(ai);

  return fd;
}

static gnutls_session_t tls_connect(
    const char *host,
    const char *port)
{
  int rc;
  int fd;
  gnutls_session_t session;

  memset(&state, 0, sizeof(state));

  /* Initiate TLS session */
  rc = gnutls_init(&session, GNUTLS_CLIENT);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Unable to start TLS session: %s",
                                                     gnutls_strerror(rc));

  /* Do some server name indication */
  rc = gnutls_server_name_set(session, GNUTLS_NAME_DNS, host,
                                                            strlen(host));
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Cannot set server name: %s",
                                                     gnutls_strerror(rc));

  /* Ciphers we accept */
  rc = gnutls_set_default_priority(session);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Cannot set cipher selection: %s",
                                                     gnutls_strerror(rc));

  /* Load the certificate chain into this session */
  rc = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
                                                          xcred);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Cannot load CA certificate file into session: %s",
                                                     gnutls_strerror(rc));

  fd = tcp_connect(host, port);

  gnutls_transport_set_int(session, fd);
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  do {
    rc = gnutls_handshake(session);
  } while (rc < 0 && !gnutls_error_is_fatal(rc));

  if (rc < 0)
    errx(EXIT_FAILURE, "Error performing TLS handshake: %s", 
                                                    gnutls_strerror(rc));
  return session;
}

static void tls_disconnect(
    gnutls_session_t session)
{
  int fd;

  gnutls_transport_get_int(session);
  if (fd < 0)
    return;

  gnutls_bye(session, GNUTLS_SHUT_RDWR);
  shutdown(fd, SHUT_RDWR);
  close(fd);
  gnutls_deinit(session);
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


int irc_parse(
    gnutls_session_t session,
    const char *buf,
    int len)
{
  int rc;
  int slen;
  char temp[4096];
  char *p, *p2;
  struct irc_msg msg;

  memset(temp, 0, sizeof(temp));
  memset(&msg, 0, sizeof(msg));

  if (len <= 0)
  return -1;

  /* Append to end of big buf */
  strncat(state.buffer, buf, sizeof(state.buffer));
  p = state.buffer;

  while (1) {
    p2 = strstr(p, "\r\n");
    if (!p2)
      break;

    slen = (p2-p)+2;
    memcpy(temp, p, slen);
    p+=slen;
    

    rc = sscanf(temp, ":%s %s %4096c", msg.prefix, msg.command, msg.params);
    if (rc == 0) {
      rc = sscanf(temp, "%s %4096c", msg.command, msg.params);
      if (rc < 2)
        return -1;
    }
    memset(temp, 0, sizeof(temp));

    handle_message(session, &msg);
  };
  if (p-state.buffer < slen) {
    /* Move the remaining bytes to the front of the buffer */
    memcpy(temp, p, p-state.buffer);
    memset(state.buffer, 0, sizeof(state.buffer));
    strncat(state.buffer, temp, sizeof(temp));
  }
  else {
    /* Nothing in the buffer to process. Clear it. */
    memset(state.buffer, 0, sizeof(state.buffer));
  }

  return 0;    
}

int irc_login(
    gnutls_session_t session)
{
  int rc;
  char buf[1024];

  rc = snprintf(buf, 1024, "NICK %s\r\n", config.nickname);
  rc = gnutls_record_send(session, buf, rc);
  if (rc <= 0)
    return -1;

  rc = snprintf(buf, 1024, "USER %s 0 * :selinux_bot\r\n", config.nickname);
  rc = gnutls_record_send(session, buf, rc);
  if (rc <= 0)
    return -1;

  return 0;
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
  int rc, fd, rc2;
  char buf[4096];
  struct irc_msg msg;
  gnutls_session_t session;

  parse_config(argc, argv);
  tls_setup();

  /* gnutls_certificate_set_verify_function(xcred,
                                               _verify_certificate_callback);
  */

  session = tls_connect(config.hostname, config.port);

  /* Login with nick/user */
  if (irc_login(session) < 0) {
    tls_disconnect(session);
    err(EXIT_FAILURE, "Failure in logging in");
  }

  do {
    memset(buf, 0, sizeof(buf));
    rc = gnutls_record_recv(session, buf, sizeof(buf));

    if ((rc = irc_parse(session, buf, rc)) < 0) {
      warnx("Error parsing message: %s\n", buf);
      continue;
    }

  } while (rc >= 0);
  tls_disconnect(session);
}

