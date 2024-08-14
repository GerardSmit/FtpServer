using System.Collections.Immutable;
using System.Linq;
using FtpServer.SourceGenerator.Helpers;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace FtpServer.SourceGenerator;

[Generator]
public class FtpCommandSourceGenerator : IIncrementalGenerator
{
    private const string GeneratorAttributeName = "FtpServer.GenerateCommandExtensionsAttribute";
    private const string FtpCommandAttributeName = "FtpServer.FtpCommandAttribute";

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        IncrementalValuesProvider<EnumInfo> declarations = context.SyntaxProvider
            .ForAttributeWithMetadataName(
                GeneratorAttributeName,
                predicate: static (s, _) => s is EnumDeclarationSyntax,
                transform: static (ctx, _) => GetEnum(ctx, (EnumDeclarationSyntax)ctx.TargetNode))
            .Where(static e => e is not null)!;

        context.RegisterSourceOutput(declarations, Generate);
    }

    private static void Generate(SourceProductionContext ctx, EnumInfo info)
    {
        var sb = new IndentedStringBuilder();

        sb.AppendLine("using System;");
        sb.AppendLine("using System.Buffers;");
        sb.AppendLine("using FtpServer;");
        sb.AppendLine("using System.Threading.Tasks;");
        sb.AppendLine();

        sb.AppendLine("namespace FtpServer;");
        sb.AppendLine();

        using (sb.CodeBlock("public static class FtpCommandExtensions"))
        {
            // FtpCommandExtensions.ToGatewayId
            using (sb.CodeBlock("public static string ToCommand(this FtpCommand name)"))
            {
                using (sb.CodeBlock("return name switch", close: "};"))
                {
                    foreach (var value in info.Values)
                    {
                        sb.AppendLine($"FtpCommand.{value.Name} => \"{value.Code}\",");
                    }

                    sb.AppendLine("_ => \"UNKNOWN\"");
                }
            }

            sb.AppendLine();

            // FtpCommandExtensions.FromUtf8
            using (sb.CodeBlock("public static FtpCommand FromUtf8(ReadOnlySpan<byte> span)"))
            {
                var lengths = info.Values.GroupBy(static v => v.Code.Length);

                foreach (var lengthGroups in lengths)
                {
                    var groups = lengthGroups
                        .GroupBy(static v => v.Code[0])
                        .ToList();

                    using (sb.CodeBlock($"if (span.Length == {lengthGroups.Key})"))
                    {
                        if (groups.Count == 1)
                        {
                            foreach (var value in groups[0])
                            {
                                sb.AppendLine($"if (span.SequenceEqual(\"{value.Code}\"u8))");
                                sb.AppendLine("{");
                                sb.AppendLine($"    return FtpCommand.{value.Name};");
                                sb.AppendLine("}");
                                sb.AppendLine();
                            }
                        }
                        else
                        {
                            foreach (var charGroups in groups)
                            {
                                using (sb.CodeBlock($"if (span[0] == '{charGroups.Key}')"))
                                {
                                    foreach (var value in charGroups)
                                    {
                                        sb.AppendLine($"if (span.SequenceEqual(\"{value.Code}\"u8))");
                                        sb.AppendLine("{");
                                        sb.AppendLine($"    return FtpCommand.{value.Name};");
                                        sb.AppendLine("}");
                                        sb.AppendLine();
                                    }

                                    sb.AppendLine("return FtpCommand.Unknown;");
                                }

                                sb.AppendLine();
                            }
                        }

                        sb.AppendLine("return FtpCommand.Unknown;");
                    }

                    sb.AppendLine();
                }

                sb.AppendLine("return FtpCommand.Unknown;");
            }
        }

        sb.AppendLine();

        using (sb.CodeBlock("public abstract class FtpCommandHandler"))
        {
            sb.AppendLine("protected virtual ValueTask UnknownAsync(FtpSession session, FtpCommand command, ReadOnlySequence<byte> data, CancellationToken token) => throw new NotImplementedException();");
            sb.AppendLine();

            foreach (var value in info.Values)
            {
                sb.AppendLine($"public virtual ValueTask {value.Name}Async(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token) => UnknownAsync(session, FtpCommand.{value.Name}, data, token);");
                sb.AppendLine();
            }

            using (sb.CodeBlock("public ValueTask HandleAsync(FtpSession session, FtpCommand command, ReadOnlySequence<byte> data, CancellationToken token)"))
            {
                using (sb.CodeBlock("return command switch", close: "};"))
                {
                    foreach (var value in info.Values)
                    {
                        sb.AppendLine($"FtpCommand.{value.Name} => {value.Name}Async(session, data, token),");
                    }

                    sb.AppendLine("_ => UnknownAsync(session, command, data, token)");
                }

                // TODO: Performance check whether the following code is faster than the switch statement
                /*
                var lengths = info.Values.GroupBy(static v => v.Code.Length);

                foreach (var lengthGroups in lengths)
                {
                    var groups = lengthGroups
                        .GroupBy(static v => v.Code[0])
                        .ToList();

                    using (sb.CodeBlock($"if (span.Length == {lengthGroups.Key})"))
                    {
                        if (groups.Count == 1)
                        {
                            foreach (var value in groups[0])
                            {
                                sb.AppendLine($"if (span.SequenceEqual(\"{value.Code}\"u8))");
                                sb.AppendLine("{");
                                sb.AppendLine($"    return {value.Name}Async(session, data, token);");
                                sb.AppendLine("}");
                                sb.AppendLine();
                            }
                        }
                        else
                        {
                            foreach (var charGroups in groups)
                            {
                                using (sb.CodeBlock($"if (span[0] == '{charGroups.Key}')"))
                                {
                                    foreach (var value in charGroups)
                                    {
                                        sb.AppendLine($"if (span.SequenceEqual(\"{value.Code}\"u8))");
                                        sb.AppendLine("{");
                                        sb.AppendLine($"    return {value.Name}Async(session, data, token);");
                                        sb.AppendLine("}");
                                        sb.AppendLine();
                                    }

                                    sb.AppendLine("return UnknownAsync(session, FtpCommand.Unknown, data, token);");
                                }

                                sb.AppendLine();
                            }
                        }

                        sb.AppendLine("return UnknownAsync(session, FtpCommand.Unknown, data, token);");
                    }

                    sb.AppendLine();
                }

                sb.AppendLine("return UnknownAsync(session, FtpCommand.Unknown, data, token);");
                */
            }
        }

        ctx.AddSource($"{info.Name}.FtpCommandExtensions.cs", sb.ToString());
    }

    private static EnumInfo? GetEnum(GeneratorAttributeSyntaxContext ctx, EnumDeclarationSyntax enumDeclarationSyntax)
    {
        var attribute = ctx.SemanticModel.Compilation.GetTypeByMetadataName(FtpCommandAttributeName);
        if (attribute is null)
        {
            return null;
        }

        var symbol = ctx.SemanticModel.GetDeclaredSymbol(enumDeclarationSyntax) as INamedTypeSymbol;

        if (symbol is null)
        {
            return null;
        }

        var builder = ImmutableArray.CreateBuilder<EnumValueInfo>();

        foreach (var member in symbol.GetMembers())
        {
            if (member is not IFieldSymbol fieldSymbol)
            {
                continue;
            }

            var attributeData = fieldSymbol.GetAttribute(attribute);

            if (attributeData is null)
            {
                continue;
            }

            if (attributeData.ConstructorArguments[0].Value is not string code)
            {
                continue;
            }

            builder.Add(new EnumValueInfo(member.Name, code));
        }

        if (builder.Count == 0)
        {
            return null;
        }

        var symbolDisplayFormat = new SymbolDisplayFormat(typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces);
        var enumNamespace = symbol.ContainingNamespace.ToDisplayString(symbolDisplayFormat);

        return new EnumInfo(symbol.Name, enumNamespace, builder.ToImmutable());
    }
}

internal record EnumInfo(string Name, string? Namespace, EquatableArray<EnumValueInfo> Values);

internal record EnumValueInfo(string Name, string Code);