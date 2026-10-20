#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "audit_client.h"

int main(int argc, char **argv)
{
	const char *sock = AUDIT_DEFAULT_WRITE_SOCK;

	if (argc == 5 && !strcmp(argv[1], "-s")) {
		sock = argv[2];
		argv += 2;
		argc -= 2;
	}
	if (argc != 3) {
		fprintf(stderr, "Usage: %s [-s write_sock] <source> <message>\n", argv[0]);
		return 1;
	}
	if (audit_client_write(sock, 0, argv[1], argv[2]) < 0) {
		perror("audit write");
		return 1;
	}
	return 0;
}
