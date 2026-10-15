using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Tools;

namespace Snail.MCP.Security.Extensions;

/// <summary>Composition root: which features the server has, and where it answers.</summary>
public static class SecurityServerExtensions
{
    extension(WebApplicationBuilder builder)
    {
        /// <summary>The tools, the scans and the settings, read from the settings file and the <c>SNAIL_MCP_SECURITY_</c> variables only.</summary>
        public WebApplicationBuilder ConfigureSecurityServer()
        {
            builder.Services
                .AddOptions<SecurityOptions>()
                .Bind(SecuritySettings.Read())
                .ValidateOnStart();

            builder.Services.AddScans();

            builder.Services
                .AddMcpServer(options =>
                {
                    options.ServerInfo = Snail.Sdk.Mcp.Hosting.ServerIdentity.Of(typeof(SecurityServerExtensions).Assembly);
                    options.ServerInstructions = ServerGuidance.Instructions;
                })
                .RefuseWhatWasNotGranted()
                .WithHttpTransport()
                .WithTools<SecurityTools>()
                .WithTools<DiagnosticsTools>();

            return builder;
        }
    }

    extension(WebApplication app)
    {
        /// <summary>The MCP endpoint and the health check.</summary>
        public WebApplication UseSecurityEndpoints()
        {
            app.MapMcp("/mcp");
            app.MapGet("/healthz", () => Results.Ok());

            return app;
        }
    }
}
