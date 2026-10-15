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
        public IServiceCollection AddScans()
        {
            services.AddSingleton(TimeProvider.System);
            services.AddHttpContextAccessor();
            services.AddSingleton<SessionCopy>();
            services.AddSingleton<SessionGrant>();
            services.AddSingleton<IScanner, NomadScanner>();
            services.AddSingleton<IScanHistory>(_ => FileScanHistory.InDataFolder());
            services.AddSingleton<Scans>();
            services.AddNomad(nomad => nomad.Address = SecuritySettings.Read()[nameof(SecurityOptions.NomadAddress)] ?? new SecurityOptions().NomadAddress);
            services.AddHostedService<EgressProxy>();

            return services;
        }
    }
}
