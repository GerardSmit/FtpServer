namespace FtpServer.IO.Results;

public readonly struct FilePermissionResult(
    PermissionResult user,
    PermissionResult group,
    PermissionResult other,
    string? ownerName,
    string? groupName)
{
    public PermissionResult User { get; } = user;
    public PermissionResult Group { get; } = group;
    public PermissionResult Other { get; } = other;
    public string? OwnerName { get; } = ownerName;
    public string? GroupName { get; } = groupName;
}