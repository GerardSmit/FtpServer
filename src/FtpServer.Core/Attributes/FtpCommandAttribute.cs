namespace FtpServer;

// Internal: only the source generator that builds FtpServer.Core reads these, and it is not shipped
// in the package, so on a consumer's own enum they would silently do nothing.
[AttributeUsage(AttributeTargets.Field)]
internal sealed class FtpCommandAttribute(string code) : Attribute
{
    public string Code { get; } = code;
}

[AttributeUsage(AttributeTargets.Enum)]
internal sealed class GenerateCommandExtensionsAttribute : Attribute;
