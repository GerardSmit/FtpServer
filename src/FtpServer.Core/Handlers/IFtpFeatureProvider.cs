namespace FtpServer.Handlers;

/// <summary>
/// Adds lines to FEAT for a session: register it in the service collection. FEAT may be sent before
/// the login, so a feature that depends on the user checks <see cref="FtpSession.IsAuthenticated"/>.
/// </summary>
public interface IFtpFeatureProvider
{
    /// <summary>The features, one per line, without the leading space FEAT puts before each.</summary>
    IEnumerable<string> GetFeatures(FtpSession session);
}
