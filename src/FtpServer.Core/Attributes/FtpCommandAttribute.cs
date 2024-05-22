namespace FtpServer;

[AttributeUsage(AttributeTargets.Field)]
public class FtpCommandAttribute(string code) : Attribute
{
    public string Code { get; } = code;
}

[AttributeUsage(AttributeTargets.Enum)]
public class GenerateCommandExtensionsAttribute : Attribute;
