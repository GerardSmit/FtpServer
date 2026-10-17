namespace FtpServer;

/// <summary>
/// Protection level for the data connection, as negotiated by PROT.
/// </summary>
/// <remarks>
/// RFC 4217 section 9 defines only C and P for TLS. S (safe) and E (confidential) exist in
/// RFC 2228 for other security mechanisms and are answered 521 here, so they have no
/// representation in this enum: a level the server cannot actually apply must never be
/// storable, or the data connection ends up protected differently from what the client asked for.
/// </remarks>
public enum FtpDataConnectionMode
{
    /// <summary>
    /// No protection is applied. Data is sent in plaintext without encryption.
    /// </summary>
    /// <remarks>
    /// PROT C
    /// </remarks>
    Clear,

    /// <summary>
    /// Provides both encryption and integrity protection for the data connection.
    /// </summary>
    /// <remarks>
    /// PROT P
    /// </remarks>
    Private,
}
