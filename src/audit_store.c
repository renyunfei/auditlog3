#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "audit_store.h"

/* Line format: <time>\t<level>\t<source>\t<message>\n */

struct audit_store {
	char *path;
};

static void sanitize_copy(char *dst, size_t dstlen, const char *src)
{
	size_t i;

	for (i = 0; i + 1 < dstlen && src[i]; i++)
		dst[i] = (src[i] == '\t' || src[i] == '\n' || src[i] == '\r') ? ' ' : src[i];
	dst[i] = '\0';
}

struct audit_store *audit_store_open(const char *path)
{
	struct audit_store *s;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		return NULL;
	close(fd);

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;
	s->path = strdup(path);
	if (!s->path) {
		free(s);
		return NULL;
	}
	return s;
}

void audit_store_close(struct audit_store *s)
{
	if (!s)
		return;
	free(s->path);
	free(s);
}

int audit_store_append(struct audit_store *s, const struct audit_entry *e)
{
	char src[AUDIT_SOURCE_MAX], msg[AUDIT_MESSAGE_MAX];
	FILE *f;
	int ret = 0;

	sanitize_copy(src, sizeof(src), e->source);
	sanitize_copy(msg, sizeof(msg), e->message);

	f = fopen(s->path, "ae");
	if (!f)
		return -1;
	if (fprintf(f, "%lld\t%d\t%s\t%s\n", (long long)e->time, (int)e->level,
		    src, msg) < 0)
		ret = -1;
	if (fclose(f) != 0)
		ret = -1;
	return ret;
}

static int parse_line(char *line, struct audit_entry *e)
{
	char *p = line, *t, *end;

	t = strchr(p, '\t');
	if (!t)
		return -1;
	*t = '\0';
	e->time = strtoll(p, &end, 10);
	if (*end)
		return -1;

	p = t + 1;
	t = strchr(p, '\t');
	if (!t)
		return -1;
	*t = '\0';
	e->level = (int32_t)strtol(p, &end, 10);
	if (*end)
		return -1;

	p = t + 1;
	t = strchr(p, '\t');
	if (!t)
		return -1;
	*t = '\0';
	snprintf(e->source, sizeof(e->source), "%s", p);

	p = t + 1;
	p[strcspn(p, "\r\n")] = '\0';
	snprintf(e->message, sizeof(e->message), "%s", p);
	return 0;
}

int audit_store_read(struct audit_store *s, uint32_t offset,
		     struct audit_entry *out, uint32_t max, int *more)
{
	char line[AUDIT_SOURCE_MAX + AUDIT_MESSAGE_MAX + 64];
	uint32_t idx = 0, n = 0;
	FILE *f;

	*more = 0;
	f = fopen(s->path, "re");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		size_t len = strlen(line);

		/* skip the remainder of an over-long line */
		if (len && line[len - 1] != '\n' && !feof(f)) {
			int c;
			while ((c = fgetc(f)) != EOF && c != '\n')
				;
		}

		if (idx++ < offset)
			continue;
		if (n == max) {
			*more = 1;
			break;
		}
		/* keep indexes stable: a corrupt line yields a placeholder entry */
		if (parse_line(line, &out[n]) != 0) {
			memset(&out[n], 0, sizeof(out[n]));
			snprintf(out[n].message, sizeof(out[n].message), "<corrupt record>");
		}
		n++;
	}

	fclose(f);
	return (int)n;
}
