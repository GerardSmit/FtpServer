using System.Buffers;
using System.Text;
using FtpServer.Extensions;
using FtpServer.IO;
using Zio;

namespace FtpServer.Tests;

public class ArgumentParsingTests
{
    private static ReadOnlySequence<byte> Seq(string value) => new(Encoding.ASCII.GetBytes(value));

    [Theory]
    [InlineData("127,0,0,1,195,80", "127.0.0.1", 50000)]
    [InlineData("10,0,0,5,0,21", "10.0.0.5", 21)]
    [InlineData(" 127 , 0 , 0 , 1 , 4 , 1 ", "127.0.0.1", 1025)]
    public void PORT_accepts_a_valid_host_port(string argument, string address, int port)
    {
        Assert.True(Seq(argument).TryGetDataPort(out var endPoint));
        Assert.Equal(address, endPoint!.Address.ToString());
        Assert.Equal(port, endPoint.Port);
    }

    [Theory]
    [InlineData("1,2,3")]                 // too few fields
    [InlineData("1,2,3,4,5,6,7,8")]       // too many fields
    [InlineData("1,2,3,4,5")]
    [InlineData("256,0,0,1,0,21")]        // octet out of range
    [InlineData("1,2,3,4,0,0")]           // port 0
    [InlineData("a,b,c,d,e,f")]
    [InlineData("")]
    public void PORT_rejects_malformed_arguments(string argument)
    {
        Assert.False(Seq(argument).TryGetDataPort(out _));
    }

    [Theory]
    [InlineData("|1|127.0.0.1|21|", "127.0.0.1", 21)]
    [InlineData("!1!10.0.0.1!5000!", "10.0.0.1", 5000)]
    [InlineData("|2|::1|21|", "::1", 21)]
    public void EPRT_accepts_the_rfc2428_form(string argument, string address, int port)
    {
        Assert.True(Seq(argument).TryGetExtendedPort(out var endPoint, out _));
        Assert.Equal(address, endPoint!.Address.ToString());
        Assert.Equal(port, endPoint.Port);
    }

    [Theory]
    [InlineData("|1|127.0.0.1|21")]        // missing the mandatory trailing delimiter
    [InlineData("|1|127.0.0.1|99999|")]    // port out of range - used to throw
    [InlineData("|1|127.0.0.1|0|")]
    [InlineData("|1|::1|21|")]             // address family does not match net-prt
    [InlineData("|2|127.0.0.1|21|")]
    [InlineData("|1|notanaddress|21|")]
    [InlineData("|1|127.0.0.1|21|extra")]
    [InlineData(" 1 127.0.0.1 21 ")]       // delimiter must not be a space
    [InlineData("")]
    public void EPRT_rejects_malformed_arguments(string argument)
    {
        Assert.False(Seq(argument).TryGetExtendedPort(out _, out _));
    }

    [Fact]
    public void EPRT_reports_an_unsupported_network_protocol()
    {
        Assert.False(Seq("|3|127.0.0.1|21|").TryGetExtendedPort(out _, out var protocol));
        Assert.Equal(3, protocol);
    }

    [Theory]
    [InlineData("file.txt", null, null)]
    [InlineData("file.txt,0,5", 0L, 5L)]
    [InlineData("file.txt 0 5", 0L, 5L)]
    [InlineData("\"my file.txt\"", null, null)]
    [InlineData("\"my file.txt\" 1 2", 1L, 2L)]
    public void Checksum_argument_parses_path_and_range(string argument, long? start, long? end)
    {
        Assert.True(Seq(argument).TryGetChecksumRequest(UPath.Root, Encoding.ASCII, out var request));
        Assert.Equal(start, request.Start);
        Assert.Equal(end, request.End);
    }

    [Fact]
    public void Checksum_range_supports_offsets_beyond_int_range()
    {
        // The range used to be parsed as int, so nothing past 2 GB could be addressed.
        Assert.True(Seq("big.bin 0 4294967296").TryGetChecksumRequest(UPath.Root, Encoding.ASCII, out var request));
        Assert.Equal(4294967296L, request.End);
    }

    [Theory]
    [InlineData("a,b.txt")]
    [InlineData("report 2023")]
    [InlineData("report 0 5")]
    public void Checksum_argument_prefers_an_existing_file_over_the_range_heuristic(string argument)
    {
        var expected = UPath.Root / argument;

        Assert.True(Seq(argument).TryGetChecksumRequest(UPath.Root, Encoding.ASCII, out var request, path => path == expected));
        Assert.Equal(expected, request.Path);
        Assert.Null(request.Start);
        Assert.Null(request.End);
    }

    [Fact]
    public void Checksum_argument_falls_back_to_the_range_when_no_such_file_exists()
    {
        Assert.True(Seq("report 2023").TryGetChecksumRequest(UPath.Root, Encoding.ASCII, out var request, _ => false));
        Assert.Equal(UPath.Root / "report", request.Path);
        Assert.Equal(2023L, request.End);
    }

    [Theory]
    [InlineData("file.txt,5,1")]  // start after end
    [InlineData("file.txt,x,y")]
    [InlineData("")]
    public void Checksum_argument_rejects_malformed_ranges(string argument)
    {
        Assert.False(Seq(argument).TryGetChecksumRequest(UPath.Root, Encoding.ASCII, out _));
    }

    [Theory]
    [InlineData("UTF8", "utf8", true)]
    [InlineData("ALL", "all", true)]
    [InlineData("ALL", "ALL", true)]
    [InlineData("ALL", "ALLL", false)]
    public void Keyword_comparison_ignores_case(string expected, string actual, bool matches)
    {
        Assert.Equal(matches, Seq(actual).EqualsIgnoreCase(Encoding.ASCII.GetBytes(expected)));
    }

    [Theory]
    [InlineData("0", true, 0)]
    [InlineData("65535", true, 65535)]
    [InlineData("+5", false, 0)]
    [InlineData(" 5", false, 0)]
    [InlineData("-1", false, 0)]
    [InlineData("", false, 0)]
    [InlineData("99999999999999999999", false, 0)]
    public void Int_parsing_is_strict(string argument, bool expected, int value)
    {
        Assert.Equal(expected, Seq(argument).TryGetInt32(out var parsed));

        if (expected)
        {
            Assert.Equal(value, parsed);
        }
    }
}

public class ListingFormatTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Recent_entries_show_a_time()
    {
        var formatted = FtpListingFormatter.FormatDate(Now.AddDays(-3), Now);

        Assert.Matches(@"^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}$", formatted);
    }

    [Fact]
    public void Old_entries_show_a_year()
    {
        // Clients infer the year from this form; without it every old file appears to be from
        // the current year.
        var formatted = FtpListingFormatter.FormatDate(new DateTimeOffset(2019, 3, 4, 11, 22, 33, TimeSpan.Zero), Now);

        Assert.Matches(@"^Mar \d{2}  2019$", formatted);
    }

    [Fact]
    public void Future_entries_show_a_year()
    {
        var formatted = FtpListingFormatter.FormatDate(Now.AddYears(2), Now);

        Assert.Matches(@"^[A-Z][a-z]{2} \d{2}  \d{4}$", formatted);
    }

    [Theory]
    [InlineData("normal.txt", "normal.txt")]
    [InlineData("with\r\nnewline", "with??newline")]
    [InlineData("with\ttab", "with?tab")]
    public void Control_characters_cannot_forge_listing_lines(string name, string expected)
    {
        Assert.Equal(expected, FtpListingFormatter.SanitiseName(name));
    }

    [Fact]
    public void Timestamps_use_the_rfc3659_form()
    {
        Assert.Equal("20190304112233", FtpListingFormatter.FormatTimestamp(new DateTimeOffset(2019, 3, 4, 11, 22, 33, TimeSpan.Zero)));
    }
}
