#ifndef _TLS_H_
#define _TLS_H_

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

gnutls_session_t tls_connect(const char *host, const char *port);
void tls_disconnect(gnutls_session_t session);
void tls_setup(const char *cafile);
int tls_read(gnutls_session_t session, char **buf);
int tls_write(gnutls_session_t session, char *buf, int len);
int tls_fd(gnutls_session_t session);
int tls_read_pending(void);
#endif
