# telnet: a Telnet client and server in C

A small, dependency-free Telnet implementation (RFC 854/855/857/858/1073/1091/1143)
for Linux/Unix. One shared protocol library, a single-threaded `poll()` server that
runs real shells on PTYs, and a raw-mode terminal client.

> **Security:** Telnet is plaintext, including passwords and everything you type.
> The server binds to **127.0.0.1** by default, refuses to run as **root** without
> `-R`, and has **no authentication of its own**: anyone who can connect gets a shell
> as the user running the server. Use it on loopback or a trusted lab network only.

## Build

    make            # bin/telnet-server, bin/telnet-client
    make test       # unit tests (codec parser/encoder, RFC 1143 state machine)
    make DEBUG=1    # -O0 -Werror + AddressSanitizer + UBSan
    make clean

Needs a C11 compiler, GNU make, and `forkpty` (glibc/macOS; links `-lutil`).

## Quick start

    ./bin/telnet-server -p 2323 &
    ./bin/telnet-client localhost 2323

Press `Ctrl-]` for the `telnet>` prompt (`status`, `send ayt`, `quit`, `help`).

## Server flags

| Flag | Default | Meaning |
|---|---|---|
| `-p, --port PORT` | 2323 | TCP port |
| `-b, --bind ADDR` | 127.0.0.1 | Bind address (`0.0.0.0` / `::` exposes it; a warning is logged) |
| `-s, --shell PROG` | /bin/sh | Program run inside each PTY |
| `-m, --max-clients N` | 32 | Extra clients are told "Server busy" and dropped |
| `-w, --idle-timeout SEC` | 0 (off) | Disconnect idle sessions |
| `-B, --banner FILE` | none | Text sent on connect |
| `-l, --log-file FILE` | stderr | Log destination |
| `-L, --log-level LVL` | info | error, warn, info, debug, trace |
| `-R, --allow-root` | off | Permit running as root (not recommended) |
| `-v`, `-h` | | Version, help |

## Client flags

    telnet-client [options] host [port]

| Flag | Default | Meaning |
|---|---|---|
| `-4`, `-6` | any | Force IPv4 / IPv6 |
| `-e CHAR` | `^]` | Escape character (`'^]'`, `'^A'`, or a literal char) |
| `-E` | | Disable escape character |
| `-t TYPE` | `$TERM` | Terminal type sent via TERMINAL-TYPE |
| `-p PORT` | 2323 | Port (alternative to positional) |
| `-c SEC` | 10 | Connect timeout |
| `-d` | | Print negotiation (`RCVD DO NAWS`, `SENT WILL SGA`...) to stderr |
| `-v`, `-h` | | Version, help |

## Design

    +----------------+      TCP       +-------------------------------+
    | telnet-client  | <------------> | telnet-server (poll loop)     |
    | raw tty <-> codec <-> socket    | socket <-> codec <-> PTY/shell|
    +----------------+                +-------------------------------+
              both link  src/common/  (codec, RFC 1143 options, ring buffer, net, log)

* **`telnet_codec`**: a byte-at-a-time parser state machine that is safe across
  arbitrary TCP segmentation (verified by feeding every input in every chunk size).
  Emits DATA / NEGOTIATE / SUBNEG / CMD events in order. Handles `IAC IAC`, `CR NUL`,
  `CR LF`, caps subnegotiation at 256 bytes and recovers from malformed sequences.
  The encoder escapes `IAC` and turns bare CR into `CR NUL`.
* **`telnet_opts`**: RFC 1143 "Q method" (six states per side) so option
  negotiation can never loop. Per-option allow/deny policy per side.
* **Server**: one thread, one `poll()` loop. Each session has two non-blocking
  fds (socket + PTY master) and two ring buffers. Backpressure: the PTY is only read
  while the client's output buffer has room, and the socket only while the PTY's input
  buffer has room, so a slow client cannot grow memory. The shell is spawned only
  after TERMINAL-TYPE and NAWS are resolved (or after a 2 s timeout, so plain `nc`
  clients still work), so `TERM` and the window size are correct from the first prompt.
  `TERM` is sanitized before use. `IP` sends ^C, `AYT` answers `[Yes]`.
  SIGCHLD reaps children, SIGPIPE is ignored, SIGINT/SIGTERM shut down cleanly.
* **Client**: `poll()` on stdin and the socket, terminal in raw mode (restored on
  every exit path), `SIGWINCH` triggers a NAWS update, local echo is on until the
  server sends `WILL ECHO`. Works with piped stdin too (`cmds | telnet-client ...`).

### Negotiation at connect

| Server sends | Client answers |
|---|---|
| `WILL ECHO`, `WILL SGA`, `DO SGA` | `DO ECHO`, `DO SGA`, `WILL SGA` |
| `DO NAWS` | `WILL NAWS` + window size, and again on resize |
| `DO TTYPE` | `WILL TTYPE`; then `SB TTYPE SEND` -> `SB TTYPE IS <term>` |

## Layout

    include/            public headers (one per module)
    src/common/         codec, options, ring buffer, logging, socket helpers
    src/server/         config, listener/loop (server.c), per-client session
    src/client/         config, main loop (client.c), terminal (raw mode), ui (telnet> prompt)
    tests/              test_codec.c, test_opts.c

## Known limits

No authentication or encryption (put it behind SSH/VPN/stunnel, or add TLS and a login
step), no LINEMODE/ENVIRON/BINARY, no Windows support, Linux/macOS only.
