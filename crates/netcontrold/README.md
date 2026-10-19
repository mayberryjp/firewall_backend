# Rust management daemon

`netcontrold` runs the networking engine and native Rust protocol services in the
same process. There is no Go wrapper or external service supervision.

## Launch contract

```
netcontrold --backend simulator --listen 0.0.0.0:8080 --state state.json
```

`--backend linux` requires a pre-created exclusive `--namespace`. Other current
options are `--keys`, comma-separated `--adopt-parents`,
`--allow-host-tunables`, `--allow-host-services`, `--gateway-monitoring`,
`--services-state-dir`, `--credential-db`, `--auth-file`, and the paired
`--tls-cert`/`--tls-key`. Optional `--ssh-listen` enables the in-process
configuration CLI; `--ssh-host-key` selects its persistent private Ed25519 host
key, default `<state>.ssh-key`, and requires `--ssh-listen`.
All options use conventional double-hyphen syntax.
Daemon executable paths, child UID/GID, child runtime directories, and obsolete
external-service binary flags do not exist.
Specifically removed: `--softflowd-binary`, `--softflowd-runtime-dir`,
`--softflowd-uid`, `--softflowd-gid`, `--dhcp-relay-binary`,
`--dhcp-relay-runtime-dir`, `--dhcp-relay-uid`, `--dhcp-relay-gid`,
`--ntp-binary`, `--syslog-binary`, `--vnstatd-binary`, `--vnstat-binary`,
and `--services-runtime-dir`. `--backend-log-file` is replaced by the fixed
`<services-state-dir>/backend.log` source; `--syslog-ca-file` is replaced by
the native service's system-trust TLS policy. The WireGuard key-directory
default is now `/etc/netcontrol/keys`.

HTTP defaults to `0.0.0.0:8080`; a trusted management network is mandatory for
unencrypted onboarding. Optional TLS uses rustls with ring, in process, not
OpenSSL. Building ring requires a supported native C compiler. TLS proxy
forwarded headers are deliberately not trusted: secure cookies and origin checks
follow the actual listener. On Unix SIGTERM and Ctrl-C initiate graceful
HTTP/SSH shutdown and durable engine shutdown. Pending transactions retain their
confirmation deadline for restart recovery; expired deadlines roll back.
Engine deadline ticks run every 250 ms; a tick failure stops both listeners.

With host services enabled on Linux, structured daemon events are appended to
`<services-state-dir>/backend.log` and stderr. The file is private and feeds the
native syslog backend source. Request bodies, raw URLs, cookies, passwords,
Authorization headers, and API-key tokens are never logged.

## Configuration SSH

The custom Rust SSH server accepts the literal username `apikey` and an existing
API key via SSH password authentication, not a device-account password. HTTP and
SSH share the same API-key resolver and engine; every command rechecks revocation.
`enable` never grants permissions. Sessions have private candidates; full-package
apply, confirmation, rollback, recovery, revision conflicts and permissions are
identical to API transactions. Neither disconnect nor normal session exit
confirms an applied transaction. No system shell, SFTP or forwarding is exposed.
The [CLI guide](../../docs/CLI.md) defines commands and operator setup.

## Device identity schema

The default identity path is `<state>.credentials.json`. `--credential-db` may
select another file. The new explicit JSON schema is:

```
{
  "schema": 1,
  "account": null,
  "sessions": {},
  "keys": {}
}
```

An account contains `username`, Argon2id PHC `password_hash`, and `complete`.
Sessions map SHA-256 token digests to Unix expiry seconds. Keys map random
64-character hexadecimal IDs to
`{"key":{"id":"...","name":"...","masked":"nc_...abcd","created_at":"<RFC3339>"},"token_sha256":"<SHA-256 hex>"}`.
Only the final four token characters are retained for display. Actual API keys
contain 256 random bits and are returned exactly once, on creation. No plaintext
password, API key, or session token is persisted.

A stable adjacent `.lock` file provides a process-wide exclusive lock; atomic
replacement commits and syncs each complete identity update. Both files are
owner-only on Unix. Symlinks, hard-linked files, invalid/empty existing data, and
unknown schemas are rejected, never reset or migrated. Keep the database and its
lock in a local private daemon-owned directory, protected against other users.
Unix credential directories must be daemon-owned and not group/world-writable.
Updates use a private same-directory pending file, file fsync, atomic replacement,
and directory fsync on Unix; Windows replacement uses `MoveFileExW` with
replace-existing/write-through flags. The prior database is never unlinked
before replacement. Transient Windows access/sharing/lock denials receive eight
bounded atomic attempts (254 ms total backoff), never a delete-and-rename fallback.
On Windows deployment must provision an owner-only directory ACL; Unix mode bits
cannot enforce Windows ACLs. Existing Go databases are not read or overwritten.

Account names are 1..64 UTF-8 bytes; passwords are 12..72 UTF-8 bytes; key names
are unique 1..80 UTF-8 bytes. Names must be trimmed and contain no controls.
There are at most 32 active, 30-minute sessions and 100 API keys. Setup/login is
limited globally to 10 attempts/minute. The single device account cannot invoke
networking APIs: it only creates/revokes user-facing API keys. A key is accepted
for networking only after `/auth/complete` confirms `{"saved":true}` and at least
one key exists.

## Scoped provisioning alternative

`--auth-file` is mutually exclusive with `--credential-db` and disables `/auth/`
onboarding. It accepts only the following **new**, explicit file schema, not the
former bare credential-array format:

```
{
  "schema": 1,
  "credentials": [{
    "name": "read-only-dashboard",
    "token_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "permissions": ["state.read"]
  }]
}
```

The hash above is synthetic, not a working credential. Provision a random
256-bit key out of band and store only its SHA-256 hash. Files must be private,
regular, daemon-owned, at most 1 MiB, with 1..100 unique names/hashes and only
permissions exported by `netcontrol_core::PERMISSIONS`. Configuration is read
once at startup; restart to apply scoped-key revocation. Unknown/duplicate
permissions, unknown JSON fields, and duplicate names/hashes are rejected.

## HTTP contract

The embedded account/key website remains at `/`, `/app.js`, `/style.css`.
`GET /auth/status`, `POST /auth/setup`, `POST /auth/login`,
`POST /auth/logout`, `GET|POST /auth/keys`,
`DELETE /auth/keys/{id}`, and `POST /auth/complete` retain the onboarding
workflow. Mutating `/auth/` requests require exact same-origin `Origin` and
`application/json`. Unknown JSON fields and trailing JSON are rejected.

Session cookies are `HttpOnly; SameSite=Strict; Path=/auth/; Max-Age=1800`, with
`Secure` only on the TLS listener. Authentication responses have
`{"error":"..."}` failures; networking failures have
`{"error":"...","transaction":null}` where no transaction exists.
Invalid JSON and oversized bodies return 400. Setup/login bodies are limited
to 4096 bytes; other request bodies are limited to 1 MiB and reads to 10 seconds.
Unknown session/key/login credentials return 401/404/401; duplicate account and
completion without keys return 409; invalid names, duplicate keys, and the
100-key limit return 400. The 32-active-session limit explicitly returns 409
(rather than an opaque credential-store 500). Unexpected identity persistence
errors return 500 with only `credential service unavailable`.
After a credential write failure, identity operations fail closed until restart;
networking key lookup returns 503 `credential store unavailable`. This avoids
overwriting a possibly committed file from stale in-memory account state.

Networking requests use only `Authorization: Bearer <API key>`. Scoped
permissions are passed unchanged to the core engine; device-generated keys
receive the complete permission set. `/api/v1/` alone sends allow-all-origin
CORS and exposes `Location, WWW-Authenticate, Retry-After`. Unauthenticated
preflight accepts only GET/POST and Authorization/Content-Type, returning 204;
unsupported requested methods/headers return 405/400. Neither credentials mode
grants cookie authorization to networking routes. `/auth/` never emits CORS.

This is an unreleased breaking persisted-schema/CLI change; recommended bump:
major once an initial release baseline is approved. No software release version
is implied by workspace development metadata `0.0.0`.
