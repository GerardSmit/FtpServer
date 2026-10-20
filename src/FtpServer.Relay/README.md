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
- `RETR` and `STOR` go directly when the server offers `DIRECT` in FEAT: the relay first sends
  `SITE DIRECT RETR <path>` (or `STOR`), and a server that grants it answers
  `200 direct://<address>[,<address>…]:<port>/<token>?sha256=<certificate fingerprint>`, naming the
  machine that holds the file. The relay connects to whichever address answers first, over TLS with
  that certificate pinned, sends the token on a line of its own and moves the file between that
  machine and the client. A download is answered `OK <length>` and that many bytes; an upload is
  answered `OK`, sent in frames of a 4-byte big-endian length and that many bytes ended by an empty
  frame, and confirmed `OK <length>`; a refusal is `ERR <message>`. A refused grant, an address that
  does not answer (skipped for ten minutes after that) or a refusal before the transfer starts sends
  the file through the server as usual, with any `REST` given again.

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
