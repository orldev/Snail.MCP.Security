using Microsoft.Extensions.DependencyInjection.Extensions;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Toolkit.Nomad.Extensions;

namespace Snail.MCP.Security.Extensions;

/// <summary>The scans feature: the session's copy, Nomad, the scanners, the history and the egress proxy.</summary>
public static class SecurityRegistrationExtensions
{
    extension(IServiceCollection services)
    {
        /// <summary>Everything a tool reaches through <see cref="Scans"/>, with Nomad at the address the settings name.</summary>
        /// <param name="settings">The server's settings, the same reading <see cref="SecurityOptions"/> is bound from.</param>
        /// <remarks>
        /// Nomad's address is <see cref="SecurityOptions.NomadAddress"/> of the same reading the options are bound from, so the
        /// scanner's messages and the client it calls name one address. It is read from the settings rather than from the
        /// bound options: Nomad's options are validated at the start too, and reading the bound options there failed with
        /// their refusal a second time, so every refused setting was said twice.
        /// </remarks>
        public IServiceCollection AddScans(IConfiguration settings)
        {
            services.AddSingleton(TimeProvider.System);
            services.AddSingleton<SessionCopy>();
            services.TryAddSingleton<NomadBatch>();
            services.AddSingleton<IScanner, NomadScanner>();
            services.AddSingleton<IScanHistory>(_ => FileScanHistory.InDataFolder());
            services.AddSingleton<IFixes, NuGetFixes>();
            services.AddHttpClient(NuGetFixes.Client, client => client.Timeout = TimeSpan.FromSeconds(60)).ConfigurePrimaryHttpMessageHandler(NuGetFixes.Handler);
            services.AddSingleton<Scans>();
            services.AddNomad(nomad => nomad.Address = settings[nameof(SecurityOptions.NomadAddress)] ?? new SecurityOptions().NomadAddress);
            services.AddHostedService<EgressProxy>();

            return services;
        }

        /// <summary>The sites feature: the ownership proof, the site scanners through Nomad, and the checks of a site's public DNS.</summary>
        /// <remarks>
        /// The ownership key is read on first use, not at the start: a broken key file refuses the site tools in the
        /// SDK's words while the scans of copies go on.
        /// </remarks>
        public IServiceCollection AddSites()
        {
            services.TryAddSingleton(TimeProvider.System);
            services.AddHttpClient(DohDns.Client, client => client.Timeout = TimeSpan.FromSeconds(10));
            services.AddSingleton<ISiteDns, DohDns>();
            services.AddSingleton<IProofKey>(_ => FileProofKey.InDataFolder());
            services.AddSingleton<Ownership>();
            services.TryAddSingleton<NomadBatch>();
            services.AddSingleton<ISiteScanner, NomadSiteScanner>();
            services.AddSingleton<Sites>();

            return services;
        }
    }
}
