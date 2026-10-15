namespace Snail.MCP.Security;

/// <summary>What the server writes to its log, as source-generated messages.</summary>
internal static partial class Log
{
    [LoggerMessage(1, LogLevel.Information, "The egress proxy listens on port {Port}")]
    public static partial void ProxyListening(ILogger logger, int port);

    [LoggerMessage(2, LogLevel.Information, "The egress proxy refused {Host}:{Port}")]
    public static partial void ProxyRefused(ILogger logger, string host, int port);

    [LoggerMessage(3, LogLevel.Debug, "An egress proxy connection ended")]
    public static partial void ProxyConnectionEnded(ILogger logger, Exception exception);

}
