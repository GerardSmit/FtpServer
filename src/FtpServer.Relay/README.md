# FtpRelay

Plain FTP in, FTPS out. Every client connection gets its own connection to an FTPS server, with
explicit TLS on the control connection and protected data connections. Commands and replies pass
as they are; the client logs in with its own username and password, and the relay keeps no accounts.

Plain FTP only travels between the client and the relay. By default the relay listens on
`127.0.0.1`, so it serves the machine it runs on and nothing else.

## What the relay does itself

- `AUTH`, `PBSZ`, `PROT` and `HOST` are answered by the relay: the client side is plain, and the
  server is the configured one.
- `PASV`, `EPSV`, `PORT` and `EPRT` set up the client's data connection with the relay. For each
  transfer the relay opens a protected data connection to the server and copies the bytes between
  the two. `ABOR` stops both.
- `FEAT` leaves out TLS, and MLSD and MLST unless `OfferMlsd` is set: some clients list one folder
  per command when they can use MLSD, and use a recursive listing (one `LIST -R` for a whole tree)
  only when they cannot.
- `LIST` is sent with `-T`, so every time has seconds and a year, and the times are converted from
  the server's zone (`Upstream:ListTimeZone`) to the one the client expects (`ListTimeZone`).
- `RETR` and `STOR` go directly when the server offers `DIRECT` in FEAT:
  - **Key.** At every start the relay makes a key pair of its own. After the login it tells the server
    its fingerprint with `SITE DIRECT KEY <sha256>`; a server that does not take it gets no direct
    requests.
  - **Grant.** Before each transfer the relay sends `SITE DIRECT RETR <path>` (or `STOR`), and a server
    that grants it answers `200 direct://<address>[,<address>…]:<port>/<token>?sha256=<certificate fingerprint>`,
    naming the machine that holds the file.
  - **TCP.** The relay connects to whichever address answers first, over TLS 1.3 with both sides'
    certificates pinned: the machine's by the fingerprint in the URL, the relay's by the key the server
    passed on to the machine. It sends the token on a line of its own and moves the file between that
    machine and the client. A download is answered `OK <length>` and that many bytes; an upload is
    answered `OK`, sent in frames of a 4-byte big-endian length and that many bytes ended by an empty
    frame, and confirmed `OK <length>`; a refusal is `ERR <message>`. After an upload the relay waits
    for `SITE DIRECT DONE <token>` before it answers `226`.
  - **UDP.** When no address answers, the relay punches through both sides' NAT and firewall instead:
    it asks STUN servers for its public address and sends `SITE DIRECT UDP <token> <candidates>`. The
    server answers `200 <key> <candidates>` with where the machine can be reached, both sides send to
    each other, and the same TLS session and protocol run over a reliable UDP connection
    (`GerardSmit.FtpServer.Direct`, on LiteNetLib).
  - **Fallback.** A refused grant, a way that does not work (TCP and UDP are each skipped for ten
    minutes after that) or a refusal before the transfer starts sends the file through the server as
    usual, with any `REST` given again.

## Build

```
dotnet publish src/FtpServer.Relay -c Release -r win-x64 -o C:\FtpRelay
```

This gives a NativeAOT `C:\FtpRelay\FtpRelay.exe` (about 5 MB, no .NET runtime needed) and
`appsettings.json` next to it. Building it needs the Visual Studio C++ build tools.

## Configure

`appsettings.json`, section `Relay`:

| Setting | Default | |
|---|---|---|
| `ListenAddress` | `127.0.0.1` | Where clients connect. Another address of this machine, or empty for every interface, serves the network, in plain FTP. |
| `Port` | `21` | |
| `PassivePortStart`, `PassivePortEnd` | `50300`–`50349` | Open them in the firewall when serving the network. |
| `OfferMlsd` | `false` | |
| `ListTimeZone` | `Standard` | The zone the client gets LIST times in: `Standard` (this machine's zone without daylight saving time, as clients that convert LIST times with the standard offset all year read them), `Local`, or a time zone id such as `UTC`. |
| `Direct` | `true` | Ask for direct transfers when the server offers them. |
| `DirectConnectTimeout` | `00:00:02` | How long a direct connection may take before the transfer goes through the server. |
| `DirectAnswerTimeout` | `00:00:30` | How long the other machine may take to answer, including writing an upload. |
| `DirectUdp` | `true` | Punch through over UDP when the machine cannot be reached over TCP. |
| `DirectUdpTimeout` | `00:00:05` | How long punching through and the TLS handshake over UDP may take. |
| `StunServers` | `stun.l.google.com:19302`, `stun.cloudflare.com:3478` | Where the relay asks for its public address. |
| `Upstream:Host`, `Upstream:Port` | required, `21` | The FTPS server. |
| `Upstream:CertificateThumbprint` | empty | Accept this certificate although it does not validate (a test server's self-signed one). Empty accepts only certificates valid for the host. |
| `Upstream:ListTimeZone` | `UTC` | The zone the server writes LIST times in. |
| `Upstream:TimeoutSeconds` | `120` | How long to wait for a reply. |

Any setting can also be given on the command line: `FtpRelay.exe --Relay:Port=2121`.

## Run

In a console: `FtpRelay.exe`. As a Windows service, from an elevated prompt:

```
sc.exe create FtpRelay binPath= "C:\FtpRelay\FtpRelay.exe" start= auto
sc.exe start FtpRelay
```

Logins, refusals and failures to reach the server go to the console, and warnings to the Windows
event log.
