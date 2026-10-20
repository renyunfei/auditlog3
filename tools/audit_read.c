#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "audit_client.h"

static int print_entry(const struct audit_entry *e, void *priv)
{
	time_t t = (time_t)e->time;
	char ts[32];

	(void)priv;
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
	printf("%s [%d] %s: %s\n", ts, e->level, e->source, e->message);
	return 0;
}

int main(int argc, char **argv)
{
	const char *sock = AUDIT_DEFAULT_READ_SOCK;
	unsigned int offset = 0, next = 0;
	int more = 1;

	if (argc == 3 && !strcmp(argv[1], "-s"))
		sock = argv[2];
	else if (argc != 1) {
		fprintf(stderr, "Usage: %s [-s read_sock]\n", argv[0]);
		return 1;
	}

	while (more) {
		if (audit_client_read(sock, offset, AUDIT_MAX_READ_COUNT,
				      print_entry, NULL, &next, &more) < 0) {
			perror("audit read");
			return 1;
		}
		offset = next;
	}
	return 0;
}
