#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "audit_client.h"

static int connect_unix(int type, const char *path, int do_connect)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	int fd;

	if (strlen(path) >= sizeof(sa.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(sa.sun_path, path);

	fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (do_connect && connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int err = errno;
		close(fd);
		errno = err;
		return -1;
	}
	return fd;
}

int audit_client_write(const char *write_sock, int level,
		       const char *source, const char *message)
{
	struct blob_buf b = { 0 };
	int fd, ret = -1, err;

	fd = connect_unix(SOCK_DGRAM, write_sock, 1);
	if (fd < 0)
		return -1;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "level", level);
	blobmsg_add_string(&b, "source", source);
	blobmsg_add_string(&b, "message", message);

	if (blob_pad_len(b.head) <= AUDIT_MAX_PACKET &&
	    send(fd, b.head, blob_pad_len(b.head), MSG_NOSIGNAL) >= 0)
		ret = 0;

	err = errno;
	blob_buf_free(&b);
	close(fd);
	errno = err;
	return ret;
}

enum { P_STATUS, P_NEXT, P_MORE, P_ENTRIES, __P_MAX };
static const struct blobmsg_policy reply_policy[__P_MAX] = {
	[P_STATUS]  = { .name = "status",  .type = BLOBMSG_TYPE_INT32 },
	[P_NEXT]    = { .name = "next",    .type = BLOBMSG_TYPE_INT32 },
	[P_MORE]    = { .name = "more",    .type = BLOBMSG_TYPE_INT8 },
	[P_ENTRIES] = { .name = "entries", .type = BLOBMSG_TYPE_ARRAY },
};

enum { E_TIME, E_LEVEL, E_SOURCE, E_MESSAGE, __E_MAX };
static const struct blobmsg_policy entry_policy[__E_MAX] = {
	[E_TIME]    = { .name = "time",    .type = BLOBMSG_TYPE_INT64 },
	[E_LEVEL]   = { .name = "level",   .type = BLOBMSG_TYPE_INT32 },
	[E_SOURCE]  = { .name = "source",  .type = BLOBMSG_TYPE_STRING },
	[E_MESSAGE] = { .name = "message", .type = BLOBMSG_TYPE_STRING },
};

int audit_client_read(const char *read_sock, unsigned int offset,
		      unsigned int count, audit_read_cb cb, void *priv,
		      unsigned int *next, int *more)
{
	struct blob_buf b = { 0 };
	uint32_t *buf;
	struct blob_attr *attr, *tb[__P_MAX], *pos;
	ssize_t n;
	size_t rem;
	unsigned int consumed = 0;
	int fd, ret = -1;

	buf = malloc(AUDIT_MAX_PACKET);
	if (!buf)
		return -1;

	fd = connect_unix(SOCK_SEQPACKET, read_sock, 1);
	if (fd < 0)
		goto out_free;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "offset", offset);
	blobmsg_add_u32(&b, "count", count);
	n = send(fd, b.head, blob_pad_len(b.head), MSG_NOSIGNAL);
	blob_buf_free(&b);
	if (n < 0)
		goto out_close;

	n = recv(fd, buf, AUDIT_MAX_PACKET, 0);
	if (n < 0)
		goto out_close;

	attr = (struct blob_attr *)buf;
	if (n < (ssize_t)sizeof(*attr) || blob_raw_len(attr) < sizeof(*attr) ||
	    blob_pad_len(attr) > (size_t)n ||
	    blobmsg_parse(reply_policy, __P_MAX, tb, blob_data(attr), blob_len(attr)) < 0 ||
	    !tb[P_STATUS] || !tb[P_NEXT] || !tb[P_MORE] || !tb[P_ENTRIES]) {
		errno = EPROTO;
		goto out_close;
	}
	if (blobmsg_get_u32(tb[P_STATUS]) != AUDIT_OK) {
		errno = EIO;
		goto out_close;
	}

	if (next)
		*next = blobmsg_get_u32(tb[P_NEXT]);
	if (more)
		*more = blobmsg_get_u8(tb[P_MORE]);

	blobmsg_for_each_attr(pos, tb[P_ENTRIES], rem) {
		struct blob_attr *et[__E_MAX];
		struct audit_entry e;

		if (blobmsg_parse(entry_policy, __E_MAX, et, blobmsg_data(pos),
				  blobmsg_data_len(pos)) < 0 ||
		    !et[E_TIME] || !et[E_LEVEL] || !et[E_SOURCE] || !et[E_MESSAGE]) {
			errno = EPROTO;
			goto out_close;
		}
		memset(&e, 0, sizeof(e));
		e.time = (int64_t)blobmsg_get_u64(et[E_TIME]);
		e.level = (int32_t)blobmsg_get_u32(et[E_LEVEL]);
		snprintf(e.source, sizeof(e.source), "%s", blobmsg_get_string(et[E_SOURCE]));
		snprintf(e.message, sizeof(e.message), "%s", blobmsg_get_string(et[E_MESSAGE]));
		consumed++;
		if (cb && cb(&e, priv)) {
			/* The callback consumed this entry, but not the rest of the page. */
			if (next)
				*next = offset + consumed;
			if (more && rem > blob_pad_len(pos))
				*more = 1;
			break;
		}
	}
	ret = 0;

out_close:
	{
		int err = errno;
		close(fd);
		errno = err;
	}
out_free:
	free(buf);
	return ret;
}
