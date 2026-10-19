# FtpServer in .NET
FTP(S) server implementation in C# / .NET

> **Note:** This project is still experimental. It is no longer unsafe by default, but it has not
> been through a security audit or a production deployment. Review the configuration before
> exposing it to an untrusted network.

## Features

**Server**
- NativeAOT support (a ~6 MB self-contained executable)
- Linux and Windows support
- Custom path for the FTP root directory, confined with a sub-filesystem jail that also refuses
  junctions and symbolic links leading out of it (set `FollowLinks` to treat the root as a mapping
  and follow them; hard links are outside what either setting can control)
- Username/password authentication, optional anonymous access, per-user home directories
- Virtual folders: any directory on the host, mounted anywhere in the tree, optionally read-only —
  server-wide or per user
- A management CLI (`FtpServer user add`) that writes hashed accounts into the settings file, which
  the running server picks up without a restart
- PBKDF2 password hashes (`PasswordHash`); the plain and SHA-256 forms still work and warn at startup
- Read-only mode, connection limits, idle timeouts and failed-login throttling
- Two hosting front-ends: raw sockets (default) and Kestrel

**FTP**
- FTPS, explicit (`AUTH TLS`) and implicit (TLS from the first byte on a second port,
  conventionally 990), with optional TLS on the data connection and session resumption across the
  two (so clients that require it, such as FileZilla, are satisfied)
- `MODE Z` deflate compression of the data connection
- Active and passive mode, including IPv6 (`EPRT`/`EPSV`) and the long forms (`LPRT`/`LPSV`)
- UTF-8 pathnames (RFC 2640)

### Supported commands

| Area | Commands |
|---|---|
| Access control | `USER` `PASS` `ACCT` `REIN` `QUIT` `HOST` |
| Security | `AUTH` `PBSZ` `PROT` |
| Navigation | `CWD` `CDUP` `PWD` `MKD` `RMD` `RMDA` `DELE` `RNFR` `RNTO` `XCUP` `XMKD` `XPWD` `XRMD` |
| Transfer setup | `TYPE` `MODE` (`S`, `Z`) `STRU` `ALLO` `REST` `PORT` `EPRT` `LPRT` `PASV` `EPSV` `LPSV` |
| Transfers | `RETR` `STOR` `STOU` `APPE` `ABOR` |
| Listings | `LIST` (incl. `-R` unless `Features.LISTR` is off, and a pathname) `NLST` `MLSD` `MLST` `STAT` |
| Metadata | `SIZE` `MDTM` `MFMT` `MFCT` (Windows, macOS) `MFF` `AVBL` `DSIZ` |
| Checksums | `HASH` `RANG` `XCRC` `XMD5` `XSHA1` `XSHA256` `XSHA512` |
| Informational | `FEAT` `OPTS` `HELP` `SYST` `NOOP` `SITE` (`CHMOD`/`HELP`/`SYMLINK`/`UTIME`) `LANG` `CLNT` `CSID` |

Deliberately answered `502`: `SMNT`, `SPSV`, `THMB`, `XRCP`, `XRSQ`, `XSEM`, `XSEN`, `MFCT` on Linux
(which has no way to set a creation time),
and the RFC 2228 mechanisms that TLS does not use (`ADAT`, `MIC`, `CONF`, `ENC`). `CCC` answers
`534` rather than dropping the control connection back to cleartext.

Exercised by an integration suite that drives the protocol at the byte level, and by two
independent client implementations in CI: `curl` (plain and explicit FTPS, including `REST`
resume and `NLST`) and `System.Net.FtpWebRequest`. FileZilla and WinSCP have **not** been tested;
the commands they rely on are covered individually, but nobody has driven a real session with them.
Beyond Compare 4 (Indy's `TIdFTP`) has been checked against the command sequence it sends and the
replies it accepts, again without a live session.

### Client compatibility notes

Where the RFCs leave room, the server answers the way common clients expect:

- **`XCRC`/`XMD5`/`XSHA*` answer `250 <HEX>`**, the bare upper-case digest and nothing after it.
  That is the de-facto form, and the only one Indy-based clients such as Beyond Compare accept.
  `HASH` keeps its `213 <algorithm> <range> <digest> <path>` reply. When the whole argument names an
  existing file it is used as the pathname as-is, so names like `a,b.txt` or `report 2023` are not
  mistaken for a path plus a byte range.
- **`REST` is accepted in either `TYPE`.** The marker applies to the next `RETR`/`STOR`/`APPE`; if
  that transfer is still in `TYPE A` with a nonzero marker it is refused with `554` before any
  `150`, because an offset into the translated stream does not map onto the file. Clients that
  probe for resume support with `REST 1` while still in the default `TYPE A` see `350`.
- **A resumed `STOR` truncates the file at the end of the new data**, so nothing stale is left
  behind it. A marker past the end of the file (or for a file that does not exist) is refused with
  `554` before the `150`.
- **MLSx facts default to `type;size;modify;perm;UNIX.mode`.** `UNIX.owner` and `UNIX.group` are
  supported but off until a client asks for them with `OPTS MLST`: they cost an account lookup, and
  clients that never send `OPTS MLST` would pay for facts they do not parse. On Windows `perm` is
  derived from the session's access and the read-only attribute, not from the file's ACL.
- **`SITE CHMOD` on Windows answers `200` and changes nothing**, saying so in the reply text.
  Clients that copy permissions on upload (Beyond Compare does by default) would otherwise report
  every upload as failed. Set `Features.IgnoreUnsupportedChmod` to `false` for a `504` instead.
- **`SITE UTIME` accepts all three forms clients send**: ProFTPD's time-first
  `SITE UTIME <YYYYMMDDhhmm[ss]> <path>`, the multi-timestamp
  `SITE UTIME <path> <atime> <mtime> <ctime> UTC` (Pure-FTPd, WinSCP), and `<path> <time>`.
  Pathnames may contain spaces in every form.
- **`MDTM <time> <path>` sets the modification time**, the form servers used before `MFMT`, with
  Serv-U's optional `+/-minutes` zone suffix. A file whose name really begins with a timestamp is
  still read, never written.
- **`MFF` is all or nothing**: it sets `modify`, `create` (Windows, macOS) and `UNIX.mode` (Unix),
  and a fact it cannot change refuses the whole command with `504`.
- **`MODE Z`** compresses transfers and listings with zlib; `OPTS MODE Z LEVEL <0-9>` picks the
  level (default 6). Clients only use it when `FEAT` lists it and their user enables compression.
  `Features.ModeZ` turns it off.
- **`SITE SYMLINK <target> <link>` is off by default** (`Features.SiteSymlink`). When on, the target
  is resolved like any pathname, must exist inside the same folder tree as the link, and the link
  stores a relative path, so it can never reach anything the session could not reach already. On
  Windows it needs Developer Mode or the symbolic-link privilege.
- **Implicit FTPS** (`ImplicitTlsPort`) protects the data connection by default, accepts `PROT`
  without `PBSZ`, answers `AUTH` with `503`, and keeps TLS through `REIN`. It is independent of
  `Ftps`, which governs explicit `AUTH TLS` on `Port`.

## Configuration

Settings come from `appsettings.json`, then `FTP_`-prefixed environment variables, then the
command line — later sources win.

```jsonc
{
  "Port": 21,
  "Path": "ftproot",          // never "/" — the server refuses to start
  "Passive": true,
  "Ftps": false,
  "RequireTls": false,        // reject USER/PASS until AUTH TLS has run
  "ImplicitTlsPort": null,    // e.g. 990: also serve implicit FTPS on this port
  "ReadOnly": false,

  "FollowLinks": false,       // follow junctions/symlinks that lead outside Path

  "VirtualFolders": [         // mounted for every session; users can add or override their own
    { "Path": "/public", "PhysicalPath": "D:/data/public", "ReadOnly": true }
  ],

  "Authentication": {
    "AllowAnonymous": false,
    "AnonymousCanWrite": false,
    "MaxFailedAttempts": 5,
    "Users": [
      {
        "Name": "alice",
        "PasswordHash": "pbkdf2-sha256$210000$<salt>$<hash>",
        "HomeDirectory": "alice",
        "VirtualFolders": [
          { "Path": "/shared",  "PhysicalPath": "D:/data/shared" },
          { "Path": "/archive", "PhysicalPath": "D:/data/archive", "ReadOnly": true }
        ]
      }
    ]
  },

  "Connection": {
    "MaxConnections": 100,
    "MaxConnectionsPerAddress": 10,
    "MaxCommandLength": 4096,
    "IdleTimeout": "00:05:00"
  },

  "DataConnection": {
    "AllowForeignHost": false,   // leave off: this is what blocks the FTP bounce attack
    "MinimumPort": 1024,
    "VerifyPeerAddress": true,
    "PublicAddress": null,       // public IP advertised in PASV replies when behind NAT
    "Timeout": "00:00:30"
  },

  "Certificate": {
    "Path": "server.pfx",        // omit to generate a self-signed certificate
    "Password": null,
    "AllowTlsResume": true       // leave on: clients may require the data connection
                                 // to resume the control connection's TLS session
  },

  "Features": {
    "XCRC": true,                // XCRC/XMD5/XSHA1/XSHA256/XSHA512
    "LISTR": true,               // honour LIST -R; off ignores the flag
    "MLST": true,
    "Hash": true,                // HASH
    "Site": true,                // SITE CHMOD/HELP/UTIME (and SYMLINK, below)
    "IgnoreUnsupportedChmod": true, // Windows: SITE CHMOD answers 200 as a no-op, not 504
    "ModeZ": true,               // MODE Z deflate compression
    "SiteSymlink": false         // SITE SYMLINK, confined to the session's own tree
  }
}
```

### Virtual folders

`VirtualFolders` grafts directories onto a tree. `Path` is where the folder appears; `PhysicalPath`
is the directory it maps to, absolute or relative to the server root.

It can be set in two places. At the top level it applies to **every** session, anonymous ones
included; on a user it applies to that user alone, on top of the server-wide list. A user entry
that mounts the same `Path` as a server-wide one replaces it rather than colliding with it — which
is how one user is given their own `/data`, or a stricter one.

```jsonc
{
  "VirtualFolders": [
    { "Path": "/public", "PhysicalPath": "D:/data/public", "ReadOnly": true }
  ],
  "Authentication": {
    "Users": [
      { "Name": "alice", "PasswordHash": "...", "VirtualFolders": [
        { "Path": "/public", "PhysicalPath": "D:/data/public" }   // alice may write to it
      ] }
    ]
  }
}
```

Unlike `HomeDirectory`, a virtual folder is **not** confined to the server root — mapping a
directory from elsewhere on the host is the point of it. Only the mapped subtree is reachable
through the mount, and links leading out of it are still refused unless `FollowLinks` is on (which
each folder can override for itself). A `ReadOnly` folder refuses every modifying command with 550,
whatever the user's own access is, and rename is refused at both ends.

With no `VirtualFolders` anywhere, a session is served exactly as before: the root, or the user's
home directory, and nothing else.

An authenticator can go further and hand a session a file system of its own — see
`IFtpFileSystemSource` and the `FtpUser` constructor. That is the extension point for a user store
that is not the settings file: the source is asked for a fresh `IFileSystem` per login, so it can
serve an in-memory tree, a composed set of mounts, or a remote store.

### Managing users

The server executable doubles as its own management CLI. Passwords are prompted for, never taken as
an argument, so they stay out of the shell history and the process list.

```bash
FtpServer user add alice --home alice
```

| Command | What it does |
|---|---|
| `user add <name> [--home <dir>] [--read-only] [--iterations N]` | Adds an account with a PBKDF2 hash |
| `user list` | Lists the configured accounts and how each password is stored |
| `user passwd <name>` | Replaces the password, dropping any weaker stored form |
| `user remove <name>` | Removes the account |
| `hash` | Prints a hash to paste in by hand |

All of them take `--config <path>` (default: `appsettings.json` beside the executable) and edit only
the `Authentication:Users` array, leaving every other setting — including ones this build does not
know about — untouched. Comments in the file are read, but a save rewrites the document and drops
them. Running with no command starts the server, so `FtpServer --Port 2121` still works.

### What a running server picks up

The settings files are watched. An account added, changed or removed while the server runs takes
effect on the **next login** — no restart:

- **Live:** the user list, per-user homes, virtual folders, read-only flags, anonymous access,
  login throttling, listing limits, and the timeouts a new session reads.
- **Restart only:** `Port`, `PassivePortRange`, `Certificate` and the hosting front-end. These are
  bound to sockets that are already open.
- Sessions that are already logged in keep the tree and access they logged in with.

A saved file that is invalid, or that does not parse at all, is reported in the log and ignored: the
server keeps running on the last configuration that was valid. At startup the same problem stops the
server instead, because there is nothing to fall back on.

### Security notes

- **Set `Path`.** It is always mounted as a jail, and a value of `/` is rejected at startup. Every
  operation is checked against where the path really lands, so a junction or symbolic link inside
  the tree cannot be used to read or write outside it. `FollowLinks: true` turns that off, for a
  root deliberately assembled out of links. Neither setting affects hard links, which have no
  target to refuse to follow — keep the root on a filesystem no untrusted account can write to.
  The root's own location is resolved at startup and re-checked at most once a second, rather than
  on every operation: if a directory at or above the root is swapped for a link, the server
  notices within that second and then refuses everything until the root lands where it did.
- **Store passwords as `PasswordHash`.** `Password` and `PasswordSha256` are kept for existing
  configurations and warn at startup: an unsalted digest can be cracked offline at billions of
  guesses a second if the configuration ever leaks. `FtpServer user add` always writes the hashed
  form.
- **A virtual folder is a hole in the jail, by design.** `PhysicalPath` is not confined to `Path`,
  so mount only what the user should have, and prefer `ReadOnly` where writes are not needed.
- **Authentication is required by default.** Set `Authentication.AllowAnonymous` to open the
  server up, and pair it with `ReadOnly` or `AnonymousCanWrite: false` unless uploads are wanted.
- **`DataConnection.AllowForeignHost` should stay off.** Turning it on re-enables the RFC 2577
  bounce attack, where the server can be used to reach hosts and ports the client cannot.
- **Configure a real certificate** for FTPS. The generated self-signed one changes on every
  restart and no client can verify it.
- **Behind NAT, set `DataConnection.PublicAddress`** to the router's public IP and forward the
  passive port range (plus port 21) to the server. Without it, PASV advertises the private LAN
  address, which internet clients cannot reach. Every peer but a loopback one gets it, LAN peers
  included (in a container the local address is the container's, which they cannot reach either),
  so it must be an address those reach too. EPSV is unaffected because its reply never carries an
  address. The server does not open router
  ports itself (no UPnP/NAT-PMP) — forwarding must be configured on the router.

## Usage

1. Go to the `src/FtpServer` directory
2. Adjust `appsettings.json`
3. Run:
   ```bash
   dotnet run
   ```

Publish a self-contained executable:

```bash
dotnet publish -c Release -r win-x64
```

With a runtime identifier the server is published as a NativeAOT executable. Cross-compiling AOT
is not supported by .NET; add `-p:PublishAot=false` to publish without it.

## Development

```bash
dotnet test
```

The suite covers the parsers and the listing formatter directly, and drives a real server over a
loopback socket for the protocol-level behaviour.

TLS session resumption cannot be observed through `SslStream`, so it has its own check that uses
`openssl s_client`:

```bash
tools/verify-tls-resumption.sh 2500
```
