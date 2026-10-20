#ifndef AUDIT_CLIENT_H
#define AUDIT_CLIENT_H

#include "audit_proto.h"

/* Send one log entry. Returns 0 on success, -1 (errno set) on error. */
int audit_client_write(const char *write_sock, int level,
		       const char *source, const char *message);

/*
 * Read up to count entries starting at entry index offset. cb is invoked per
 * entry (return non-zero to stop). *next receives the offset to continue
 * from and *more whether further entries exist (both may be NULL).
 * Returns 0 on success, -1 on error (errno set, or EPROTO for a bad reply).
 */
typedef int (*audit_read_cb)(const struct audit_entry *e, void *priv);
int audit_client_read(const char *read_sock, unsigned int offset,
		      unsigned int count, audit_read_cb cb, void *priv,
		      unsigned int *next, int *more);

#endif
