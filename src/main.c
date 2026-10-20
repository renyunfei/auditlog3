#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libubox/uloop.h>

#include "audit_proto.h"
#include "audit_server.h"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-w write_sock] [-r read_sock] [-f log_file]\n"
		"  -w  datagram socket for writing logs (default %s)\n"
		"  -r  seqpacket socket for reading logs (default %s)\n"
		"  -f  log file backing the store (default %s)\n",
		prog, AUDIT_DEFAULT_WRITE_SOCK, AUDIT_DEFAULT_READ_SOCK,
		AUDIT_DEFAULT_LOG_FILE);
}

int main(int argc, char **argv)
{
	struct audit_server_config cfg = {
		.write_path = AUDIT_DEFAULT_WRITE_SOCK,
		.read_path = AUDIT_DEFAULT_READ_SOCK,
		.log_path = AUDIT_DEFAULT_LOG_FILE,
		.write_mode = 0666,
		.read_mode = 0600,
	};
	struct audit_server *srv;
	int ch;

	while ((ch = getopt(argc, argv, "w:r:f:h")) != -1) {
		switch (ch) {
		case 'w': cfg.write_path = optarg; break;
		case 'r': cfg.read_path = optarg; break;
		case 'f': cfg.log_path = optarg; break;
		default:
			usage(argv[0]);
			return ch == 'h' ? 0 : 1;
		}
	}

	uloop_init();
	srv = audit_server_new(&cfg);
	if (!srv) {
		uloop_done();
		return 1;
	}

	uloop_run();

	audit_server_free(srv);
	uloop_done();
	return 0;
}
