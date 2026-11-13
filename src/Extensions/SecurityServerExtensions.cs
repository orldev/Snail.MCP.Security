using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Tools;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Discovery;
using Snail.Sdk.Mcp.Hosting.Jobs;
using Snail.Sdk.Mcp.Hosting.Sessions;
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
        /// request — at the endpoint its settings name (<see cref="McpEndpoint"/>): HTTP alone, since the server never runs
        /// as a child process, at <c>Url</c> (<c>SNAIL_MCP_SECURITY_URL</c>) or a <c>Port</c>. A container's published port
        /// does not reach its loopback, so there the port is opened on every interface and the published port is the boundary
        /// (<see cref="McpReach.LoopbackOrContainer"/>); on a machine anything beyond loopback is refused at start, naming the
        /// variable that asked for it, since the findings it answers name a copy's secrets and weak spots.
        /// </remarks>
        /// <param name="args">The program's arguments.</param>
        /// <param name="settings">The server's settings, read once for the process (<see cref="SecuritySettings.Read()"/>).</param>
        public static WebApplicationBuilder CreateSecurityBuilder(string[] args, IConfiguration settings) =>
            McpHttpHost.CreateBuilder(args, McpEndpoint.ReadHttp(settings, SecuritySettings.DefaultUrl, new McpEndpointOptions { Reach = McpReach.LoopbackOrContainer, Server = SecuritySettings.Name }));
    }

    extension(WebApplicationBuilder builder)
    {
        /// <summary>The tools, the scans and the settings, which come from the settings file and the <c>SNAIL_MCP_SECURITY_</c> variables only.</summary>
        /// <remarks>
        /// A session for every client (<c>WithLocalHttpTransport</c>): the MCP SDK's HTTP transport is stateless by default,
        /// and a stateless server has no stream to tell a subscriber of a job's end — the job client's wait for a scan never
        /// ended, not even on its own cancellation. The tools a session's address grants (<c>?tool=</c>) are held at the door
        /// (<c>WithSessionGrant</c>): a tool it was not granted is left out of its list, and a call to it is refused in
        /// the answer envelope. A call that leaves out a required parameter or names one a tool does not take is refused
        /// before the tool runs (<c>WithArgumentCheck</c>): <c>check</c> for <c>checks</c> no longer scans everything.
        /// </remarks>
        /// <param name="settings">The same settings the host was made from: read once, so the endpoint and the options never see two readings of a file being edited.</param>
        public WebApplicationBuilder ConfigureSecurityServer(IConfiguration settings)
        {
            builder.Services
                .AddOptions<SecurityOptions>()
                .Bind(settings)
                .ValidateOnStart();
            builder.Services.AddSingleton<IValidateOptions<SecurityOptions>, SecurityOptionsValidation>();

            builder.Services.AddCompliance();
            builder.Services.AddScans(settings);
            builder.Services.AddSites();
            builder.Services.AddSingleton<ScanJobs>();
            builder.Services.AddSingleton<SiteJobs>();

            builder.Services
                .AddMcpServer(options =>
                {
                    options.ServerInfo = ServerIdentity.Of(typeof(SecurityServerExtensions).Assembly);
                    options.ServerInstructions = ServerGuidance.Instructions;
                })
                .ExplainFailures()
                .WithLocalHttpTransport()
                .WithSessionGrant()
                .WithArgumentCheck()
                .WithTools<SecurityTools>()
                .WithTools<SiteTools>()
                .WithTools<DiagnosticsTools>()
                .WithJobs(SecuritySettings.Name, JobOwners.TaskOfCopy(WorkspacesOf, SessionCopy.IsTaskId));

            return builder;
        }
    }

    extension(WebApplication app)
    {
        /// <summary>The MCP endpoint behind the refusal of browsers, and the health check.</summary>
        public WebApplication UseSecurityEndpoints()
        {
            app.MapLocalMcp();
            app.MapHealth();

            return app;
        }
    }

    /// <summary>The folder every task's copies lie under, which names whose jobs a request may read and watch.</summary>
    /// <remarks>
    /// Every step of a task opens the server with its own copy under the task's folder, so the steps of one task share
    /// their scans and no other task reaches them; a request that names no copy owns nothing and sees no scan. A scan is
    /// started with the task as its owner (<see cref="ScanJobs"/>), the owner <see cref="JobOwners.TaskOfCopy"/> reads.
    /// </remarks>
    private static string WorkspacesOf(IServiceProvider services) => services.GetRequiredService<IOptions<SecurityOptions>>().Value.WorkspacesRoot;
}
