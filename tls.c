#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "tls.h"

char buffer[65536];

gnutls_certificate_credentials_t xcred;

static int tcp_connect(const char *host, const char *port);

void tls_setup(
    const char *cafile)
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

  rc = gnutls_certificate_set_x509_trust_file(xcred, cafile,
                                               GNUTLS_X509_FMT_PEM);
  if (rc < 0)
    errx(EXIT_FAILURE, "Unable to load root certificates: %s",
                                               gnutls_strerror(rc));
}



static int tcp_connect(
    const char *host,
    const char *port)
{
  int fd = -1;
  int rc;
  struct addrinfo *ai;

  rc = getaddrinfo(host, port, NULL, &ai);
  if (rc) {
    warnx("DNS resolution error: %s", gai_strerror(rc));
    goto end;
  }

  fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0) {
    warn("Cannot create socket");
    goto end;
  }

  if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
    warn("Cannot connect to host");
  }

end:
  freeaddrinfo(ai);

  return fd;
}

int tls_fd(
    gnutls_session_t session)
{
  return gnutls_transport_get_int(session);
}

gnutls_session_t tls_connect(
    const char *host,
    const char *port)
{
  int rc;
  int fd;
  gnutls_session_t session = NULL;
  memset(buffer, 0, sizeof(buffer));

  /* Initiate TLS session */
  rc = gnutls_init(&session, GNUTLS_CLIENT);
  if (rc != GNUTLS_E_SUCCESS) {
    warnx("Unable to start TLS session: %s", gnutls_strerror(rc));
    goto end;
  }

  /* Do some server name indication */
  rc = gnutls_server_name_set(session, GNUTLS_NAME_DNS, host, strlen(host));
  if (rc != GNUTLS_E_SUCCESS) {
    warnx("Cannot set server name: %s", gnutls_strerror(rc));
    goto end;
  }

  /* Ciphers we accept */
  rc = gnutls_set_default_priority(session);
  if (rc != GNUTLS_E_SUCCESS) {
    warnx("Cannot set cipher selection: %s", gnutls_strerror(rc));
    goto end;
  }

  /* Load the certificate chain into this session */
  rc = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
  if (rc != GNUTLS_E_SUCCESS) {
    warnx("Cannot load CA certificate file into session: %s", gnutls_strerror(rc));
    goto end;
  }

  fd = tcp_connect(host, port);
  if (fd < 0)
    goto end;

  gnutls_transport_set_int(session, fd);
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  do {
    rc = gnutls_handshake(session);
  } while (rc < 0 && !gnutls_error_is_fatal(rc));

  if (rc < 0) {
    warnx("Error performing TLS handshake: %s", gnutls_strerror(rc));
    goto end;
  }

  return session;

end:
  tls_disconnect(session);
  return NULL;
  
}

void tls_disconnect(
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


int tls_read(
    gnutls_session_t session,
    char **buf)
{
  char data[512];
  char *p;
  int rc, len=0;
  memset(data, 0, sizeof(data));

  /* If the buffer has no full record.. */
  if (strstr(buffer, "\r\n") == NULL) {
    rc = gnutls_record_recv(session, data, sizeof(data));
    if (rc <= 0)
      return -1;
    /* Tack onto end of our buffer */
    strncat(buffer, data, sizeof(data));
  }

  /* Find a matching string */
  p = strstr(buffer, "\r\n");
  if (p == NULL)
    return 0;
  p += 2;

  /* Get len */
  len = (p - buffer);

  /* Allocate buffer memory */
  *buf = malloc(len+1);
  if (!*buf)
    return -1;
  memset(*buf, 0, len+1);

  memcpy(*buf, buffer, len);
  memset(buffer, 0, len);
  /* Remove entry we just copied from the overall buffer */
  memmove(buffer, p, sizeof(buffer)-len);

  return len;
}

int tls_read_pending(
    void)
{
  if (strstr(buffer, "\r\n") == NULL)
    return 0;
  return 1;
}

int tls_write(
    gnutls_session_t session,
    char *buf, 
    int len)
{
  return gnutls_record_send(session, buf, len);
}
