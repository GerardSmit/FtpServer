namespace FtpServer;

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
    /// Provides data integrity protection but does not encrypt the data.
    /// This level ensures that the data has not been tampered with during transit.
    /// </summary>
    /// <remarks>
    /// PROT S
    /// </remarks>
    Safe,

    /// <summary>
    /// Provides encryption for the data to ensure confidentiality but does not include integrity protection.
    /// </summary>
    /// <remarks>
    /// PROT E
    /// </remarks>
    Confidential,

    /// <summary>
    /// Provides both encryption and integrity protection for the data connection.
    /// This is the most secure option, ensuring that data is both encrypted and has not been altered during transit.
    /// </summary>
    /// <remarks>
    /// PROT P
    /// </remarks>
    Private
}
