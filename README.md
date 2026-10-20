# auditlog3
重构auditlog

基于 libubox（uloop + blobmsg）的审计日志框架，C 语言实现。

- `auditd`：守护进程，监听两个 AF_UNIX socket
  - 写日志：`SOCK_DGRAM`（默认 `/var/run/auditlog-w.sock`），消息 `{level, source, message}`
  - 读日志：`SOCK_SEQPACKET`（默认 `/var/run/auditlog-r.sock`），请求 `{offset, count}`，应答 `{status, next, more, entries[]}`
- `src/audit_store.[ch]`：存储后端，目前用文本文件占位，移植时只需替换该模块
- `src/audit_client.[ch]`：客户端封装 `audit_client_write()` / `audit_client_read()`
- `tools/`：命令行 `audit-write`、`audit-read`

```
mkdir build && cd build && cmake .. && make
./auditd -w /tmp/w.sock -r /tmp/r.sock -f /tmp/audit.log
./audit-write -s /tmp/w.sock sshd "login ok"
./audit-read -s /tmp/r.sock
```

协议定义见 `src/audit_proto.h`。
