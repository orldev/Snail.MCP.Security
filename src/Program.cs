using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Extensions;
using Snail.Sdk.Mcp.Hosting;

try
{
    var settings = SecuritySettings.Read();
    var app = WebApplication.CreateSecurityBuilder(args, settings)
        .ConfigureSecurityServer(settings)
        .Build()
        .UseSecurityEndpoints();

    await app.RunAsync();

    return 0;
}
catch (StartRefusedException refused)
{
    await Console.Error.WriteLineAsync(refused.Message);

    return 1;
}
