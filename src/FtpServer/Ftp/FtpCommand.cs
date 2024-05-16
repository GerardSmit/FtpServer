namespace FtpServer;

[GenerateCommandExtensions]
public enum FtpCommand
{
    Unknown,

    /// <summary>
    /// Abort an active file transfer.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("ABOR")]
    Abort,

    /// <summary>
    /// Account information.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("ACCT")]
    AccountInformation,

    /// <summary>
    /// Authentication/Security Data.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("ADAT")]
    AuthenticationSecurityData,

    /// <summary>
    /// Allocate sufficient disk space to receive a file.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("ALLO")]
    AllocateDiskSpace,

    /// <summary>
    /// Append (with create).
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("APPE")]
    Append,

    /// <summary>
    /// Authentication/Security Mechanism.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("AUTH")]
    AuthenticationSecurityMechanism,

    /// <summary>
    /// Get the available space.
    /// </summary>
    /// <remarks>
    /// Streamlined FTP Command Extensions
    /// </remarks>
    [FtpCommand("AVBL")]
    GetAvailableSpace,

    /// <summary>
    /// Clear Command Channel.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("CCC")]
    ClearCommandChannel,

    /// <summary>
    /// Change to Parent Directory.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("CDUP")]
    ChangeToParentDirectory,

    /// <summary>
    /// Confidentiality Protection Command.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("CONF")]
    ConfidentialityProtection,

    /// <summary>
    /// Client / Server Identification.
    /// </summary>
    /// <remarks>
    /// Streamlined FTP Command Extensions
    /// </remarks>
    [FtpCommand("CSID")]
    ClientServerIdentification,

    /// <summary>
    /// Change working directory.
    /// </summary>
    /// <remarks>
    /// RFC 697
    /// </remarks>
    [FtpCommand("CWD")]
    ChangeWorkingDirectory,

    /// <summary>
    /// Delete file.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("DELE")]
    DeleteFile,

    /// <summary>
    /// Get the directory size.
    /// </summary>
    /// <remarks>
    /// Streamlined FTP Command Extensions
    /// </remarks>
    [FtpCommand("DSIZ")]
    GetDirectorySize,

    /// <summary>
    /// Privacy Protected Channel.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("ENC")]
    PrivacyProtectedChannel,

    /// <summary>
    /// Specifies an extended address and port to which the server should connect.
    /// </summary>
    /// <remarks>
    /// RFC 2428
    /// </remarks>
    [FtpCommand("EPRT")]
    ExtendedPort,

    /// <summary>
    /// Enter extended passive mode.
    /// </summary>
    /// <remarks>
    /// RFC 2428
    /// </remarks>
    [FtpCommand("EPSV")]
    ExtendedPassiveMode,

    /// <summary>
    /// Get the feature list implemented by the server.
    /// </summary>
    /// <remarks>
    /// RFC 2389
    /// </remarks>
    [FtpCommand("FEAT")]
    FeatureList,

    /// <summary>
    /// Returns usage documentation on a command if specified, else a general help document is returned.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("HELP")]
    Help,

    /// <summary>
    /// Identify desired virtual host on server, by name.
    /// </summary>
    /// <remarks>
    /// RFC 7151
    /// </remarks>
    [FtpCommand("HOST")]
    IdentifyVirtualHost,

    /// <summary>
    /// Language Negotiation.
    /// </summary>
    /// <remarks>
    /// RFC 2640
    /// </remarks>
    [FtpCommand("LANG")]
    LanguageNegotiation,

    /// <summary>
    /// Returns information of a file or directory if specified, else information of the current working directory is returned.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("LIST")]
    ListInformation,

    /// <summary>
    /// Specifies a long address and port to which the server should connect.
    /// </summary>
    /// <remarks>
    /// RFC 1639
    /// </remarks>
    [FtpCommand("LPRT")]
    LongPort,

    /// <summary>
    /// Enter long passive mode.
    /// </summary>
    /// <remarks>
    /// RFC 1639
    /// </remarks>
    [FtpCommand("LPSV")]
    LongPassiveMode,

    /// <summary>
    /// Return the last-modified time of a specified file.
    /// </summary>
    /// <remarks>
    /// RFC 3659
    /// </remarks>
    [FtpCommand("MDTM")]
    LastModifiedTime,

    /// <summary>
    /// Modify the creation time of a file.
    /// </summary>
    /// <remarks>
    /// The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP
    /// </remarks>
    [FtpCommand("MFCT")]
    ModifyCreationTime,

    /// <summary>
    /// Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).
    /// </summary>
    /// <remarks>
    /// The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP
    /// </remarks>
    [FtpCommand("MFF")]
    ModifyFact,

    /// <summary>
    /// Modify the last modification time of a file.
    /// </summary>
    /// <remarks>
    /// The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP
    /// </remarks>
    [FtpCommand("MFMT")]
    ModifyLastModificationTime,

    /// <summary>
    /// Integrity Protected Command.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("MIC")]
    IntegrityProtectedCommand,

    /// <summary>
    /// Make directory.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("MKD")]
    MakeDirectory,

    /// <summary>
    /// Lists the contents of a directory in a standardized machine-readable format.
    /// </summary>
    /// <remarks>
    /// RFC 3659
    /// </remarks>
    [FtpCommand("MLSD")]
    ListDirectoryContents,

    /// <summary>
    /// Provides data about exactly the object named on its command line in a standardized machine-readable format.
    /// </summary>
    /// <remarks>
    /// RFC 3659
    /// </remarks>
    [FtpCommand("MLST")]
    ListObjectDetails,

    /// <summary>
    /// Sets the transfer mode (Stream, Block, or Compressed).
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("MODE")]
    SetTransferMode,

    /// <summary>
    /// Returns a list of file names in a specified directory.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("NLST")]
    ListFileNames,

    /// <summary>
    /// No operation (dummy packet; used mostly on keepalives).
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("NOOP")]
    NoOperation,

    /// <summary>
    /// Select options for a feature (for example OPTS UTF8 ON).
    /// </summary>
    /// <remarks>
    /// RFC 2389
    /// </remarks>
    [FtpCommand("OPTS")]
    SelectFeatureOptions,

    /// <summary>
    /// Authentication password.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("PASS")]
    AuthenticationPassword,

    /// <summary>
    /// Enter passive mode.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("PASV")]
    PassiveMode,

    /// <summary>
    /// Protection Buffer Size.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("PBSZ")]
    ProtectionBufferSize,

    /// <summary>
    /// Specifies an address and port to which the server should connect.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("PORT")]
    Port,

    /// <summary>
    /// Data Channel Protection Level.
    /// </summary>
    /// <remarks>
    /// RFC 2228
    /// </remarks>
    [FtpCommand("PROT")]
    DataChannelProtection,

    /// <summary>
    /// Print working directory. Returns the current directory of the host.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("PWD")]
    PrintWorkingDirectory,

    /// <summary>
    /// Disconnect.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("QUIT")]
    Disconnect,

    /// <summary>
    /// Re-initializes the connection.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("REIN")]
    ReinitializeConnection,

    /// <summary>
    /// Restart transfer from the specified point.
    /// </summary>
    /// <remarks>
    /// RFC 3659
    /// </remarks>
    [FtpCommand("REST")]
    RestartTransfer,

    /// <summary>
    /// Retrieve a copy of the file.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("RETR")]
    RetrieveFile,

    /// <summary>
    /// Remove a directory.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("RMD")]
    RemoveDirectory,

    /// <summary>
    /// Remove a directory tree.
    /// </summary>
    /// <remarks>
    /// Streamlined FTP Command Extensions
    /// </remarks>
    [FtpCommand("RMDA")]
    RemoveDirectoryTree,

    /// <summary>
    /// Rename from.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("RNFR")]
    RenameFrom,

    /// <summary>
    /// Rename to.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("RNTO")]
    RenameTo,

    /// <summary>
    /// Sends site-specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("SITE")]
    SiteSpecificCommands,

    /// <summary>
    /// Return the size of a file.
    /// </summary>
    /// <remarks>
    /// RFC 3659
    /// </remarks>
    [FtpCommand("SIZE")]
    FileSize,

    /// <summary>
    /// Mount file structure.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("SMNT")]
    MountFileStructure,

    /// <summary>
    /// Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections).
    /// </summary>
    /// <remarks>
    /// FTP Extension Allowing IP Forwarding (NATs)
    /// </remarks>
    [FtpCommand("SPSV")]
    SinglePortPassiveMode,

    /// <summary>
    /// Returns information on the server status, including the status of the current connection.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("STAT")]
    ServerStatus,

    /// <summary>
    /// Accept the data and to store the data as a file at the server site.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("STOR")]
    StoreFile,

    /// <summary>
    /// Store file uniquely.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("STOU")]
    StoreFileUniquely,

    /// <summary>
    /// Set file transfer structure.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("STRU")]
    FileTransferStructure,

    /// <summary>
    /// Return system type.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("SYST")]
    SystemType,

    /// <summary>
    /// Get a thumbnail of a remote image file.
    /// </summary>
    /// <remarks>
    /// Streamlined FTP Command Extensions
    /// </remarks>
    [FtpCommand("THMB")]
    GetThumbnail,

    /// <summary>
    /// Sets the transfer mode (ASCII/Binary).
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("TYPE")]
    SetTransferType,

    /// <summary>
    /// Authentication username.
    /// </summary>
    /// <remarks>
    /// RFC 959
    /// </remarks>
    [FtpCommand("USER")]
    AuthenticationUsername,

    /// <summary>
    /// Change to the parent of the current working directory.
    /// </summary>
    /// <remarks>
    /// RFC 775
    /// </remarks>
    [FtpCommand("XCUP")]
    ChangeToParentDirectoryExtended,

    /// <summary>
    /// Make a directory.
    /// </summary>
    /// <remarks>
    /// RFC 775
    /// </remarks>
    [FtpCommand("XMKD")]
    MakeDirectoryExtended,

    /// <summary>
    /// Print the current working directory.
    /// </summary>
    /// <remarks>
    /// RFC 775
    /// </remarks>
    [FtpCommand("XPWD")]
    PrintWorkingDirectoryExtended,

    /// <summary>
    /// RFC 743
    /// </summary>
    [FtpCommand("XRCP")]
    XRemoteCopy,

    /// <summary>
    /// Remove the directory.
    /// </summary>
    /// <remarks>
    /// RFC 775
    /// </remarks>
    [FtpCommand("XRMD")]
    RemoveDirectoryExtended,

    /// <summary>
    /// RFC 743
    /// </summary>
    [FtpCommand("XRSQ")]
    XRemoteSearchQuery,

    /// <summary>
    /// Send, mail if cannot.
    /// </summary>
    /// <remarks>
    /// RFC 737
    /// </remarks>
    [FtpCommand("XSEM")]
    SendOrMail,

    /// <summary>
    /// Send to terminal.
    /// </summary>
    /// <remarks>
    /// RFC 737
    /// </remarks>
    [FtpCommand("XSEN")]
    SendToTerminal,
}