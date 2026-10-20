#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <libubox/uloop.h>
#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "audit_proto.h"
#include "audit_server.h"
#include "audit_store.h"

struct audit_client {
	struct uloop_fd fd;
	struct audit_server *srv;
};

struct audit_server {
	struct audit_server_config cfg;
	char *write_path;
	char *read_path;
	struct audit_store *store;
	struct uloop_fd write_fd;
	struct uloop_fd read_fd;
	struct blob_buf b;
};

enum { W_LEVEL, W_SOURCE, W_MESSAGE, __W_MAX };
static const struct blobmsg_policy write_policy[__W_MAX] = {
	[W_LEVEL]   = { .name = "level",   .type = BLOBMSG_TYPE_INT32 },
	[W_SOURCE]  = { .name = "source",  .type = BLOBMSG_TYPE_STRING },
	[W_MESSAGE] = { .name = "message", .type = BLOBMSG_TYPE_STRING },
};

enum { R_OFFSET, R_COUNT, __R_MAX };
static const struct blobmsg_policy read_policy[__R_MAX] = {
	[R_OFFSET] = { .name = "offset", .type = BLOBMSG_TYPE_INT32 },
	[R_COUNT]  = { .name = "count",  .type = BLOBMSG_TYPE_INT32 },
};

/* Validate that buf holds one well formed blob_attr. */
static struct blob_attr *packet_attr(void *buf, ssize_t len)
{
	struct blob_attr *attr = buf;

	if (len < (ssize_t)sizeof(*attr))
		return NULL;
	if (blob_raw_len(attr) < sizeof(*attr) || blob_pad_len(attr) > (size_t)len)
		return NULL;
	return attr;
}

static int bind_unix(int type, const char *path, mode_t mode)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	int fd;

	if (strlen(path) >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(sa.sun_path, path);

	fd = socket(AF_UNIX, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	unlink(path);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
	    chmod(path, mode) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* ---- write path: SOCK_DGRAM ---- */

static void handle_write(struct audit_server *srv, struct blob_attr *attr)
{
	struct blob_attr *tb[__W_MAX];
	struct audit_entry e;

	if (blobmsg_parse(write_policy, __W_MAX, tb, blob_data(attr), blob_len(attr)) < 0 ||
	    !tb[W_LEVEL] || !tb[W_SOURCE] || !tb[W_MESSAGE])
		return;

	memset(&e, 0, sizeof(e));
	e.time = time(NULL);
	e.level = (int32_t)blobmsg_get_u32(tb[W_LEVEL]);
	snprintf(e.source, sizeof(e.source), "%s", blobmsg_get_string(tb[W_SOURCE]));
	snprintf(e.message, sizeof(e.message), "%s", blobmsg_get_string(tb[W_MESSAGE]));

	if (audit_store_append(srv->store, &e) < 0)
		fprintf(stderr, "auditd: failed to store entry: %s\n", strerror(errno));
}

static void write_cb(struct uloop_fd *u, unsigned int events)
{
	struct audit_server *srv = container_of(u, struct audit_server, write_fd);
	uint32_t buf[AUDIT_MAX_PACKET / sizeof(uint32_t)];
	(void)events;

	for (;;) {
		struct blob_attr *attr;
		ssize_t n = recv(u->fd, buf, sizeof(buf), MSG_DONTWAIT);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return;
		}
		attr = packet_attr(buf, n);
		if (attr)
			handle_write(srv, attr);
	}
}

/* ---- read path: SOCK_SEQPACKET ---- */

static void build_read_reply(struct audit_server *srv, int status,
			     uint32_t offset, const struct audit_entry *ents,
			     int n, int more)
{
	void *arr, *tbl;
	int i;

	blob_buf_init(&srv->b, 0);
	blobmsg_add_u32(&srv->b, "status", status);
	blobmsg_add_u32(&srv->b, "next", offset + (n > 0 ? n : 0));
	blobmsg_add_u8(&srv->b, "more", more);
	arr = blobmsg_open_array(&srv->b, "entries");
	for (i = 0; i < n; i++) {
		tbl = blobmsg_open_table(&srv->b, NULL);
		blobmsg_add_u64(&srv->b, "time", (uint64_t)ents[i].time);
		blobmsg_add_u32(&srv->b, "level", ents[i].level);
		blobmsg_add_string(&srv->b, "source", ents[i].source);
		blobmsg_add_string(&srv->b, "message", ents[i].message);
		blobmsg_close_table(&srv->b, tbl);
	}
	blobmsg_close_array(&srv->b, arr);
}

static void handle_read(struct audit_client *c, struct blob_attr *attr)
{
	struct audit_server *srv = c->srv;
	struct blob_attr *tb[__R_MAX];
	struct audit_entry *ents = NULL;
	uint32_t offset = 0, count = 0;
	int n = 0, more = 0, status = AUDIT_OK;

	if (blobmsg_parse(read_policy, __R_MAX, tb, blob_data(attr), blob_len(attr)) < 0 ||
	    !tb[R_OFFSET] || !tb[R_COUNT]) {
		status = AUDIT_ERR_INVALID;
	} else {
		int32_t o = (int32_t)blobmsg_get_u32(tb[R_OFFSET]);
		int32_t cnt = (int32_t)blobmsg_get_u32(tb[R_COUNT]);

		if (o < 0 || cnt < 0) {
			status = AUDIT_ERR_INVALID;
		} else {
			offset = o;
			count = cnt > AUDIT_MAX_READ_COUNT ? AUDIT_MAX_READ_COUNT : cnt;
		}
	}

	if (status == AUDIT_OK && count) {
		ents = calloc(count, sizeof(*ents));
		n = ents ? audit_store_read(srv->store, offset, ents, count, &more) : -1;
		if (n < 0) {
			n = 0;
			status = AUDIT_ERR_IO;
		}
	}

	build_read_reply(srv, status, offset, ents, n, more);
	free(ents);
	send(c->fd.fd, srv->b.head, blob_pad_len(srv->b.head),
	     MSG_NOSIGNAL | MSG_DONTWAIT);
	blob_buf_free(&srv->b);
}

static void client_close(struct audit_client *c)
{
	uloop_fd_delete(&c->fd);
	close(c->fd.fd);
	free(c);
}

static void client_cb(struct uloop_fd *u, unsigned int events)
{
	struct audit_client *c = container_of(u, struct audit_client, fd);
	uint32_t buf[AUDIT_MAX_PACKET / sizeof(uint32_t)];
	struct blob_attr *attr;
	ssize_t n;

	(void)events;
	n = recv(u->fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	if (n <= 0) {
		client_close(c);
		return;
	}

	attr = packet_attr(buf, n);
	if (!attr) {
		client_close(c);
		return;
	}
	handle_read(c, attr);
}

static void accept_cb(struct uloop_fd *u, unsigned int events)
{
	struct audit_server *srv = container_of(u, struct audit_server, read_fd);
	(void)events;

	for (;;) {
		struct audit_client *c;
		int fd = accept4(u->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

		if (fd < 0)
			return;
		c = calloc(1, sizeof(*c));
		if (!c) {
			close(fd);
			return;
		}
		c->srv = srv;
		c->fd.fd = fd;
		c->fd.cb = client_cb;
		uloop_fd_add(&c->fd, ULOOP_READ);
	}
}

/* ---- lifecycle ---- */

struct audit_server *audit_server_new(const struct audit_server_config *cfg)
{
	struct audit_server *srv = calloc(1, sizeof(*srv));

	if (!srv)
		return NULL;
	srv->cfg = *cfg;
	srv->write_path = strdup(cfg->write_path);
	srv->read_path = strdup(cfg->read_path);
	srv->write_fd.fd = -1;
	srv->read_fd.fd = -1;
	if (!srv->write_path || !srv->read_path)
		goto err;

	srv->store = audit_store_open(cfg->log_path);
	if (!srv->store) {
		fprintf(stderr, "auditd: cannot open %s: %s\n", cfg->log_path, strerror(errno));
		goto err;
	}

	srv->write_fd.fd = bind_unix(SOCK_DGRAM, cfg->write_path, cfg->write_mode);
	if (srv->write_fd.fd < 0) {
		fprintf(stderr, "auditd: write socket %s: %s\n", cfg->write_path, strerror(errno));
		goto err;
	}
	srv->write_fd.cb = write_cb;

	srv->read_fd.fd = bind_unix(SOCK_SEQPACKET, cfg->read_path, cfg->read_mode);
	if (srv->read_fd.fd < 0 || listen(srv->read_fd.fd, 16) < 0) {
		fprintf(stderr, "auditd: read socket %s: %s\n", cfg->read_path, strerror(errno));
		goto err;
	}
	srv->read_fd.cb = accept_cb;

	uloop_fd_add(&srv->write_fd, ULOOP_READ);
	uloop_fd_add(&srv->read_fd, ULOOP_READ);
	return srv;

err:
	audit_server_free(srv);
	return NULL;
}

void audit_server_free(struct audit_server *srv)
{
	if (!srv)
		return;
	if (srv->write_fd.fd >= 0) {
		if (srv->write_fd.registered)
			uloop_fd_delete(&srv->write_fd);
		close(srv->write_fd.fd);
		unlink(srv->write_path);
	}
	if (srv->read_fd.fd >= 0) {
		if (srv->read_fd.registered)
			uloop_fd_delete(&srv->read_fd);
		close(srv->read_fd.fd);
		unlink(srv->read_path);
	}
	audit_store_close(srv->store);
	free(srv->write_path);
	free(srv->read_path);
	free(srv);
}
