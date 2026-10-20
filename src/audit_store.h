/*
 * Storage backend. The current implementation is a plain text file and is
 * only a placeholder: port audit_store.c to a secure storage and keep this
 * interface unchanged.
 */
#ifndef AUDIT_STORE_H
#define AUDIT_STORE_H

#include "audit_proto.h"

struct audit_store;

struct audit_store *audit_store_open(const char *path);
void audit_store_close(struct audit_store *s);

/* Append one entry. Returns 0 on success, -1 on error. */
int audit_store_append(struct audit_store *s, const struct audit_entry *e);

/*
 * Read up to max entries, starting at entry index offset, into out.
 * Returns the number read (>= 0) or -1 on error. *more is set when
 * further entries exist after the returned ones.
 */
int audit_store_read(struct audit_store *s, uint32_t offset,
		     struct audit_entry *out, uint32_t max, int *more);

#endif
