using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Tools;
using Snail.Sdk.Mcp.Hosting.Jobs;
using Snail.Sdk.Mcp.Http;

namespace Snail.MCP.Security.Extensions;

/// <summary>Composition root: which features the server has, and where it answers.</summary>
public static class SecurityServerExtensions
{
    extension(WebApplication)
    {
        /// <summary>The host of the server: the port of its URL on every interface inside a container, the loopback URL itself on a machine.</summary>
        /// <remarks>
        /// Snail.Sdk.Mcp.Http's host either way — stderr, the idle trim, and with <c>MapLocalMcp</c> the refusal of a browser's
        /// request. The server built a host of its own before and lost that refusal: a request with <c>Origin</c> was answered
        /// 200, as Snail.MCP.Documents' was on 2026-10-16. A container's published port does not reach its loopback, so there
        /// the port is opened on every interface and the published port is the boundary.
        /// </remarks>
        public static WebApplicationBuilder CreateSecurityBuilder(string[] args)
        {
            Uri url = SecuritySettings.Url;
            bool isInContainer = string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase);

            return isInContainer ? McpHttpHost.CreateContainerBuilder(args, url.Port) : McpHttpHost.CreateBuilder(args, url);
        }
    }

    extension(WebApplicationBuilder builder)
    {
        /// <summary>The tools, the scans and the settings, read from the settings file and the <c>SNAIL_MCP_SECURITY_</c> variables only.</summary>
        /// <remarks>
        /// A session for every client (<c>WithLocalHttpTransport</c>): the MCP SDK's HTTP transport is stateless by default,
        /// and a stateless server has no stream to tell a subscriber of a job's end — the job client's wait for a scan never
        /// ended, not even on its own cancellation.
        /// </remarks>
        public WebApplicationBuilder ConfigureSecurityServer()
        {
            builder.Services
                .AddOptions<SecurityOptions>()
                .Bind(SecuritySettings.Read())
                .ValidateOnStart();

            builder.Services.AddScans();
            builder.Services.AddSingleton<ScanJobs>();

            builder.Services
                .AddMcpServer(options =>
                {
                    options.ServerInfo = Snail.Sdk.Mcp.Hosting.ServerIdentity.Of(typeof(SecurityServerExtensions).Assembly);
                    options.ServerInstructions = ServerGuidance.Instructions;
                })
                .RefuseWhatWasNotGranted()
                .WithLocalHttpTransport()
                .WithTools<SecurityTools>()
                .WithTools<DiagnosticsTools>()
                .WithJobs(SecuritySettings.Name);

            return builder;
        }
    }

    extension(WebApplication app)
    {
        /// <summary>The MCP endpoint behind the refusal of browsers, and the health check.</summary>
        public WebApplication UseSecurityEndpoints()
        {
            app.MapLocalMcp();
            app.MapGet("/healthz", () => Results.Ok());

            return app;
        }
    }
}
