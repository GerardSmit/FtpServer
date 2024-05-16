# FtpServer in .NET
FTP(S) server implementation in C# / .NET

> **Note:** This project is still in experimental stage and not ready for production use.

## Features
The following features are supported by the FTP server:

**Server**
- NativeAOT support
- Connection handler in Kestrel
- Linux and Windows support
- Custom path for FTP root directory
- Auto disconnect client after idle time

**FTP**
- FTPS (FTP over SSL) support
- Only active mode support
- Basic FTP commands support
  - PWD
  - CWD
  - LIST
  - RETR
  - STOR
  - PORT
  - PROT

More features will be added in the future.

Note: the server has only been tested with FileZilla FTP client on Windows.

## Usage
Follow the steps below to run the FTP server:

1. Go to the `src/FtpServer` directory
2. Replace the settings in `appsettings.json` with your own settings
3. Run the following command to start the server:
   ```bash
   dotnet run
   ```

Currently there is no executable file to download to run the server without the source code. You can publish the project yourself to create an executable file with the following command:
```bash
dotnet publish -c Release -r win-x64
```

When given the runtime identifier (`-r`) the server will also be published as AOT (Ahead-Of-Time) compiled executable. When you're trying to cross compile the server, you'll get an error that this isn't supported by .NET. You can publish the server without AOT compilation by adding `-p:PublishAot=false` to the command.