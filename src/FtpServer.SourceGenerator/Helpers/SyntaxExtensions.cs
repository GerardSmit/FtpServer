using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace FtpServer.SourceGenerator.Helpers;

public static class SyntaxExtensions
{
    public static AttributeData? GetAttribute(this ISymbol node, ISymbol attribute)
    {
        foreach (var attributeData in node.GetAttributes())
        {
            if (attribute.Equals(attributeData.AttributeClass, SymbolEqualityComparer.Default))
            {
                return attributeData;
            }
        }

        return null;
    }

    public static ImmutableArray<string> GetNamespaces(this SyntaxNode syntax)
    {
        var namespaces = ImmutableArray.CreateBuilder<string>();

        var node = syntax;

        while (node is not null && node is not CompilationUnitSyntax)
        {
            switch (node)
            {
                case NamespaceDeclarationSyntax nds:
                    namespaces.Insert(0, nds.Name.ToString());
                    break;
                case FileScopedNamespaceDeclarationSyntax file:
                    namespaces.Add(file.Name.ToString());
                    break;
            }

            node = node.Parent;
        }

        return namespaces.ToImmutable();
    }
}
