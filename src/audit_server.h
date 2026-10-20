#ifndef AUDIT_SERVER_H
#define AUDIT_SERVER_H

#include <sys/types.h>

struct audit_server;

struct audit_server_config {
	const char *write_path;	/* AF_UNIX/SOCK_DGRAM */
	const char *read_path;	/* AF_UNIX/SOCK_SEQPACKET */
	const char *log_path;	/* storage backend file */
	mode_t write_mode;	/* permissions of the write socket */
	mode_t read_mode;	/* permissions of the read socket */
};

/* Must be called after uloop_init(). Returns NULL on failure. */
struct audit_server *audit_server_new(const struct audit_server_config *cfg);
void audit_server_free(struct audit_server *srv);

#endif
