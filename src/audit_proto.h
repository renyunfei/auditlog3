/*
 * Wire protocol shared by the audit daemon and clients.
 *
 * Every message (datagram or seqpacket) is one complete blob_attr holding a
 * blobmsg table.
 *
 *  Write  (AF_UNIX/SOCK_DGRAM, fire and forget):
 *      { "level": int32, "source": string, "message": string }
 *
 *  Read   (AF_UNIX/SOCK_SEQPACKET, request/response):
 *      request : { "offset": int32, "count": int32 }
 *      response: { "status": int32, "next": int32, "more": bool,
 *                  "entries": [ { "time": int64, "level": int32,
 *                                 "source": string, "message": string } ] }
 */
#ifndef AUDIT_PROTO_H
#define AUDIT_PROTO_H

#include <stdint.h>
#include <stddef.h>

#define AUDIT_DEFAULT_WRITE_SOCK "/var/run/auditlog-w.sock"
#define AUDIT_DEFAULT_READ_SOCK  "/var/run/auditlog-r.sock"
#define AUDIT_DEFAULT_LOG_FILE   "/var/log/audit.log"

#define AUDIT_SOURCE_MAX   64
#define AUDIT_MESSAGE_MAX  1024
#define AUDIT_MAX_PACKET   (128 * 1024)
#define AUDIT_MAX_READ_COUNT 32

enum audit_status {
	AUDIT_OK = 0,
	AUDIT_ERR_INVALID = 1,
	AUDIT_ERR_IO = 2,
};

struct audit_entry {
	int64_t  time;
	int32_t  level;
	char     source[AUDIT_SOURCE_MAX];
	char     message[AUDIT_MESSAGE_MAX];
};

#endif
