# Event vocabulary - ECS alignment

221B's `Event` uses ECS-style vocabulary so analysts see familiar terms. Internal names are flat; this table maps them.

| 221B field | ECS field | Notes |
|---|---|---|
| `ts_utc` | `@timestamp` | always aware UTC |
| `category` | `event.category` | authentication, network, file, process, web, iam |
| `action` | `event.action` | login, logout, sudo, su, useradd, group_add, http, conn, file_read, file_write, proc_exec, cron_add, key_add, log_clear, other |
| `outcome` | `event.outcome` | success / failure / unknown |
| `host` | `host.name` | from syslog host, file-name hint, or `host` column |
| `user` | `user.name` | |
| `src_ip` / `dst_ip` | `source.ip` / `destination.ip` | |
| `dst_port` | `destination.port` | |
| `bytes_out` / `bytes_in` | `source.bytes` / `destination.bytes` | |
| `object` | `process.command_line` / `url.path` / `file.path` | by action |
| `user_agent` | `user_agent.original` | |
| `session_id` | `session.id` (non-ECS convention) | `host:pid` for sshd |
| `attrs` | (extra) | unmapped source fields are kept, never dropped |
| `parse_flags` | (extra) | `tz_assumed`, `inferred_year`, `invalid_user`, ... |

Vocabulary credit: Elastic Common Schema (Apache-2.0), OCSF (Apache-2.0). No schema code is vendored.
