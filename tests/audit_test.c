#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>

#include "audit_client.h"
#include "audit_server.h"
#include "audit_store.h"

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #expr, errno); \
		exit(1); \
	} \
} while (0)

static char test_dir[] = "/tmp/audit-test-XXXXXX";
static char write_path[108], read_path[108], log_path[108];

static int bind_socket(const char *path, int type)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);

	CHECK(fd >= 0);
	CHECK(strlen(path) < sizeof(sa.sun_path));
	strcpy(sa.sun_path, path);
	CHECK(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	return fd;
}

struct callback_state {
	unsigned int seen;
	unsigned int stop_after;
};

static int consume_entry(const struct audit_entry *e, void *priv)
{
	struct callback_state *s = priv;
	CHECK(!strcmp(e->source, "test"));
	CHECK(!strcmp(e->message, "entry"));
	s->seen++;
	return s->seen == s->stop_after;
}

/* Exercise the public client against a real seqpacket peer. */
static void check_reply(const void *packet, size_t len, int malformed,
			unsigned int stop_after, int use_callback,
			unsigned int expected_next, int expected_more)
{
	int fd = bind_socket(read_path, SOCK_SEQPACKET);
	pid_t child;
	int status, ret, err, more = -1;
	unsigned int next = 999;
	struct callback_state state = { .stop_after = stop_after };

	CHECK(listen(fd, 1) == 0);
	child = fork();
	CHECK(child >= 0);
	if (!child) {
		char request[128];
		int peer;
		alarm(5);
		peer = accept(fd, NULL, NULL);
		CHECK(peer >= 0);
		CHECK(recv(peer, request, sizeof(request), 0) > 0);
		CHECK(send(peer, packet, len, MSG_NOSIGNAL) == (ssize_t)len);
		close(peer);
		close(fd);
		_exit(0);
	}
	close(fd);
	errno = 0;
	ret = audit_client_read(read_path, 10, 3,
				use_callback ? consume_entry : NULL, &state, &next, &more);
	err = errno;
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(unlink(read_path) == 0);
	if (malformed) {
		CHECK(ret == -1 && err == EPROTO);
		CHECK(state.seen == 0 && next == 999 && more == -1);
	} else {
		CHECK(ret == 0);
		CHECK(next == expected_next && more == expected_more);
		CHECK(state.seen == (use_callback ? (stop_after ? stop_after : 3) : 0));
	}
}

static void test_malformed(void)
{
	uint32_t *packet = malloc(AUDIT_MAX_PACKET);
	unsigned int i;
	CHECK(packet != NULL);
	/* A short declared root length must not underflow blob_len(). Fill the
	 * remaining packet with attributes to expose scanning past its end. */
	for (i = 0; i < AUDIT_MAX_PACKET / sizeof(*packet); i++)
		packet[i] = htonl(sizeof(*packet));
	for (i = 0; i < sizeof(*packet); i++) {
		packet[0] = htonl(i);
		check_reply(packet, AUDIT_MAX_PACKET, 1, 0, 1, 0, 0);
	}
	check_reply(packet, 3, 1, 0, 1, 0, 0);
	packet[0] = htonl(AUDIT_MAX_PACKET);
	check_reply(packet, 4, 1, 0, 1, 0, 0);
	free(packet);
}

static void test_pagination(void)
{
	struct blob_buf b = { 0 };
	int page_more, i;
	void *arr, *entry;

	for (page_more = 0; page_more <= 1; page_more++) {
		blob_buf_init(&b, 0);
		blobmsg_add_u32(&b, "status", AUDIT_OK);
		blobmsg_add_u32(&b, "next", 13);
		blobmsg_add_u8(&b, "more", page_more);
		arr = blobmsg_open_array(&b, "entries");
		for (i = 0; i < 3; i++) {
			entry = blobmsg_open_table(&b, NULL);
			blobmsg_add_u64(&b, "time", 123);
			blobmsg_add_u32(&b, "level", 1);
			blobmsg_add_string(&b, "source", "test");
			blobmsg_add_string(&b, "message", "entry");
			blobmsg_close_table(&b, entry);
		}
		blobmsg_close_array(&b, arr);
		check_reply(b.head, blob_pad_len(b.head), 0, 1, 1, 11, 1);
		check_reply(b.head, blob_pad_len(b.head), 0, 2, 1, 12, 1);
		check_reply(b.head, blob_pad_len(b.head), 0, 3, 1, 13, page_more);
		check_reply(b.head, blob_pad_len(b.head), 0, 0, 1, 13, page_more);
		check_reply(b.head, blob_pad_len(b.head), 0, 0, 0, 13, page_more);
		blob_buf_free(&b);
	}
}

static void test_sockets(void)
{
	struct audit_server_config cfg = {
		.write_path = write_path, .read_path = read_path, .log_path = log_path,
		.write_mode = 0600, .read_mode = 0600,
	};
	struct audit_server *srv;
	struct stat before, after;
	const char *paths[] = { write_path, read_path };
	char spare[108], contents[16];
	unsigned int i;
	int fd;
	FILE *f;

	CHECK(uloop_init() == 0);
	for (i = 0; i < 2; i++) {
		f = fopen(paths[i], "w");
		CHECK(f != NULL);
		CHECK(fputs("keep-me", f) >= 0 && fclose(f) == 0);
		CHECK(lstat(paths[i], &before) == 0);
		CHECK(audit_server_new(&cfg) == NULL);
		CHECK(lstat(paths[i], &after) == 0);
		CHECK(before.st_ino == after.st_ino && S_ISREG(after.st_mode));
		f = fopen(paths[i], "r");
		CHECK(f != NULL && fgets(contents, sizeof(contents), f) != NULL);
		CHECK(!strcmp(contents, "keep-me") && fclose(f) == 0);
		CHECK(unlink(paths[i]) == 0);
	}
	/* Stale sockets are preserved too: cleanup requires an operator decision. */
	fd = bind_socket(write_path, SOCK_DGRAM);
	close(fd);
	CHECK(lstat(write_path, &before) == 0);
	CHECK(audit_server_new(&cfg) == NULL);
	CHECK(lstat(write_path, &after) == 0 && before.st_ino == after.st_ino);
	CHECK(unlink(write_path) == 0);

	srv = audit_server_new(&cfg);
	CHECK(srv != NULL);
	CHECK(lstat(write_path, &before) == 0);
	CHECK(audit_server_new(&cfg) == NULL);
	CHECK(lstat(write_path, &after) == 0 && before.st_ino == after.st_ino);
	CHECK(audit_client_write(write_path, 0, "test", "still reachable") == 0);
	/* Fail at the read socket after creating a new write socket. Only that
	 * new socket may be removed during failed-startup cleanup. */
	snprintf(spare, sizeof(spare), "%s/spare", test_dir);
	cfg.write_path = spare;
	CHECK(lstat(read_path, &before) == 0);
	CHECK(audit_server_new(&cfg) == NULL);
	CHECK(lstat(read_path, &after) == 0 && before.st_ino == after.st_ino);
	CHECK(access(spare, F_OK) == -1 && errno == ENOENT);
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	CHECK(fd >= 0);
	{
		struct sockaddr_un sa = { .sun_family = AF_UNIX };
		strcpy(sa.sun_path, read_path);
		CHECK(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	}
	close(fd);
	audit_server_free(srv);
	CHECK(access(write_path, F_OK) == -1 && errno == ENOENT);
	CHECK(access(read_path, F_OK) == -1 && errno == ENOENT);
	uloop_done();
	CHECK(unlink(log_path) == 0);
}

static void test_store(void)
{
	struct audit_store *store = audit_store_open(log_path);
	struct audit_entry in = { .time = 123, .level = 2,
		.source = "test", .message = "tabs\tand\nnewlines" }, out[2];
	int more, i;
	CHECK(store != NULL);
	for (i = 0; i < 3; i++)
		CHECK(audit_store_append(store, &in) == 0);
	CHECK(audit_store_read(store, 0, out, 2, &more) == 2 && more == 1);
	CHECK(out[0].time == in.time && out[0].level == in.level);
	CHECK(!strcmp(out[0].source, "test"));
	CHECK(!strcmp(out[0].message, "tabs and newlines"));
	CHECK(audit_store_read(store, 2, out, 2, &more) == 1 && more == 0);
	CHECK(audit_store_read(store, 3, out, 2, &more) == 0 && more == 0);
	CHECK(unlink(log_path) == 0);
	/* fopen(directory) succeeds on Linux; the subsequent fgets fails. */
	CHECK(mkdir(log_path, 0700) == 0);
	errno = 0;
	CHECK(audit_store_read(store, 0, out, 2, &more) == -1 && errno == EISDIR);
	audit_store_close(store);
	CHECK(rmdir(log_path) == 0);
}

int main(int argc, char **argv)
{
	CHECK(argc == 2 && mkdtemp(test_dir) != NULL);
	snprintf(write_path, sizeof(write_path), "%s/write", test_dir);
	snprintf(read_path, sizeof(read_path), "%s/read", test_dir);
	snprintf(log_path, sizeof(log_path), "%s/log", test_dir);
	if (!strcmp(argv[1], "malformed"))
		test_malformed();
	else if (!strcmp(argv[1], "pagination"))
		test_pagination();
	else if (!strcmp(argv[1], "sockets"))
		test_sockets();
	else if (!strcmp(argv[1], "store"))
		test_store();
	else
		CHECK(0);
	CHECK(rmdir(test_dir) == 0);
	return 0;
}
