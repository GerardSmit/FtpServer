namespace FtpServer.IO.Results;

public readonly struct PermissionResult(bool read, bool write, bool execute)
{
    public bool Read { get; } = read;
    public bool Write { get; } = write;
    public bool Execute { get; } = execute;
}