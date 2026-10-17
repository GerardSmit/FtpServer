using System.Buffers;
using System.Text;
using FtpServer;
using FtpServer.Handlers;

namespace FtpServer.Tests;

public class FtpRequestTests
{
    private static (FtpCommand Command, string Data) Parse(string line)
    {
        var bytes = Encoding.ASCII.GetBytes(line);
        var request = FtpRequest.Parse(bytes);
        return (request.Command, Encoding.ASCII.GetString(request.Data.Span));
    }

    [Theory]
    [InlineData("USER", FtpCommand.AuthenticationUsername)]
    [InlineData("user", FtpCommand.AuthenticationUsername)]
    [InlineData("UsEr", FtpCommand.AuthenticationUsername)]
    [InlineData("pwd", FtpCommand.PrintWorkingDirectory)]
    [InlineData("XSHA256", FtpCommand.CalculateSha256Checksum)]
    [InlineData("xsha256", FtpCommand.CalculateSha256Checksum)]
    public void Verbs_are_case_insensitive(string verb, FtpCommand expected)
    {
        // RFC 959 section 5.3.1.
        Assert.Equal(expected, Parse(verb).Command);
    }

    [Theory]
    [InlineData("")]
    [InlineData("X")]
    [InlineData("NOTACOMMAND")]
    [InlineData("USERNAME")]
    public void Unknown_verbs_do_not_throw(string line)
    {
        Assert.Equal(FtpCommand.Unknown, Parse(line).Command);
    }

    [Fact]
    public void Argument_is_everything_after_the_first_space()
    {
        var (command, data) = Parse("RETR my file.txt");

        Assert.Equal(FtpCommand.RetrieveFile, command);
        Assert.Equal("my file.txt", data);
    }

    [Fact]
    public void Trailing_space_yields_an_empty_argument()
    {
        var (command, data) = Parse("USER ");

        Assert.Equal(FtpCommand.AuthenticationUsername, command);
        Assert.Equal(string.Empty, data);
    }

    [Fact]
    public void Command_without_argument_has_empty_data()
    {
        var (command, data) = Parse("PWD");

        Assert.Equal(FtpCommand.PrintWorkingDirectory, command);
        Assert.Equal(string.Empty, data);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4095)]
    [InlineData(65536)]
    public void Long_lines_are_parsed_without_overflowing(int length)
    {
        // Regression: ParseSequence used to size its buffer at line.Length - 2 and then copy the
        // whole line into it, throwing for any argument-less line that spanned two segments.
        var line = new string('A', length);

        Assert.Equal(FtpCommand.Unknown, Parse(line).Command);
    }

    [Fact]
    public void Telnet_escapes_are_stripped()
    {
        // IAC IP, IAC DM, then "ABOR" - how a client signals an urgent abort.
        byte[] line = [255, 244, 255, 242, (byte)'A', (byte)'B', (byte)'O', (byte)'R'];

        var length = FtpRequest.StripTelnet(line);
        var request = FtpRequest.Parse(line.AsMemory(0, length));

        Assert.Equal(FtpCommand.Abort, request.Command);
    }

    [Fact]
    public void Doubled_iac_is_unescaped_to_a_literal_byte()
    {
        byte[] line = [(byte)'C', (byte)'W', (byte)'D', (byte)' ', 255, 255];

        var length = FtpRequest.StripTelnet(line);
        var request = FtpRequest.Parse(line.AsMemory(0, length));

        Assert.Equal(FtpCommand.ChangeWorkingDirectory, request.Command);
        Assert.Equal(new byte[] { 255 }, request.Data.ToArray());
    }

    [Fact]
    public void Line_without_telnet_bytes_is_unchanged()
    {
        var line = Encoding.ASCII.GetBytes("NOOP");

        Assert.Equal(4, FtpRequest.StripTelnet(line));
    }

    [Fact]
    public void Telnet_subnegotiation_is_removed_whole()
    {
        // IAC SB 'X' 'Y' IAC SE then NOOP. Treating SB as a plain two-byte command would leave
        // the subnegotiation payload "XY" glued to the front of the verb.
        byte[] line = [255, 250, (byte)'X', (byte)'Y', 255, 240, (byte)'N', (byte)'O', (byte)'O', (byte)'P'];

        var length = FtpRequest.StripTelnet(line);

        Assert.Equal("NOOP", Encoding.ASCII.GetString(line, 0, length));
        Assert.Equal(FtpCommand.NoOperation, FtpRequest.Parse(line.AsMemory(0, length)).Command);
    }

    [Fact]
    public void Unterminated_telnet_subnegotiation_consumes_the_rest()
    {
        byte[] line = [(byte)'A', 255, 250, (byte)'X', (byte)'Y'];

        var length = FtpRequest.StripTelnet(line);

        Assert.Equal("A", Encoding.ASCII.GetString(line, 0, length));
    }
}

public class LineFramingTests
{
    private static List<string> Frame(params string[] chunks)
    {
        var lines = new List<string>();
        var buffer = new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(string.Concat(chunks)));

        while (FtpConnectionHandler.TryReadLine(ref buffer, out var line))
        {
            lines.Add(Encoding.ASCII.GetString(line.ToArray()));
        }

        return lines;
    }

    [Fact]
    public void Pipelined_commands_are_framed_separately()
    {
        // Regression: the loop used to slice every line from the start of the read buffer, so the
        // second and later commands were re-parsed as a repeat of the first.
        Assert.Equal(["USER a", "PASS b", "PWD"], Frame("USER a\r\nPASS b\r\nPWD\r\n"));
    }

    [Fact]
    public void Bare_line_feed_is_accepted()
    {
        Assert.Equal(["USER a", "PWD"], Frame("USER a\nPWD\n"));
    }

    [Fact]
    public void Partial_line_is_left_in_the_buffer()
    {
        Assert.Equal(["USER a"], Frame("USER a\r\nPAS"));
    }

    [Fact]
    public void Empty_line_frames_as_empty()
    {
        Assert.Equal(["", "PWD"], Frame("\r\nPWD\r\n"));
    }
}
