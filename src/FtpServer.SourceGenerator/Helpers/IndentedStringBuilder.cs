using System;
using System.Collections.Concurrent;
using System.Text;

namespace FtpServer.SourceGenerator.Helpers;

public class IndentedStringBuilder
{
    private readonly ConcurrentDictionary<int, string> indentCache = new();

    private int spaces;
    private string indent = string.Empty;

    private int Spaces
    {
        get => spaces;
        set
        {
            if (spaces == value)
            {
                return;
            }

            spaces = value;
            indent = indentCache.GetOrAdd(value, v => new string(' ', v));
        }
    }

    private StringBuilder Builder { get; }


    public IndentedStringBuilder(int spaces = 0)
    {
        Spaces = spaces;
        Builder = new StringBuilder();
    }

    public IndentedStringBuilder AppendLine()
    {
        return AppendLine("\n");
    }

    public IndentedStringBuilder Append(string text)
    {
        if (text.HasNewLine())
        {
            var lines = text.GetLines();

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];

                if (i == 0)
                {
                    Builder.Append(indent);
                }
                else
                {
                    Builder.AppendLine();
                    Builder.Append(indent);
                }

                Builder.Append(line);
            }
        }
        else
        {
            Builder.Append(indent);
            Builder.Append(text);
        }

        return this;
    }

    /// <summary>
    /// Append the last part of a line. This will add a new line but no indent at the beginning.
    /// </summary>
    public IndentedStringBuilder AppendEnd(string text)
    {
        if (text.GetLines().Length > 1)
        {
            throw new ArgumentException("AppendEnd must not contain multiple lines");
        }

        Builder.AppendLine(text.TrimEnd());
        return this;
    }

    public IndentedStringBuilder AppendLine(string text)
    {
        if (text.HasNewLine())
        {
            Append(text);
            Builder.AppendLine();
        }
        else
        {
            Builder.Append(indent);
            Builder.AppendLine(text);
        }

        return this;
    }

    public IndentedStringBuilder Indent(int addSpaces = 4)
    {
        Spaces = Math.Max(0, Spaces + addSpaces);
        return this;
    }

    public IndentedStringBuilder Dedent(int removeSpaces = 4)
    {
        Spaces = Math.Max(0, Spaces - removeSpaces);
        return this;
    }

    /// <summary>
    /// Write a new scope and take a lambda to write to the builder within it. This way it is easy to ensure the
    /// scope is closed correctly.
    /// </summary>
    public DisposeCodeBlock CodeBlock(string openingLine, int spaces = 4, string open = "{", string close = "}")
    {
        if (!string.IsNullOrEmpty(openingLine))
        {
            AppendLine(openingLine);
            AppendLine(open);
        }
        else
        {
            AppendLine(open);
        }

        Indent(spaces);
        return new DisposeCodeBlock(spaces, close, this);
    }

    public override string ToString()
    {
        return Builder.ToString();
    }

    public readonly struct DisposeCodeBlock(int spaces, string close, IndentedStringBuilder builder) : IDisposable
    {
        public void Dispose()
        {
            builder.Dedent(spaces);
            builder.AppendLine(close);
        }
    }
}