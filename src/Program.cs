using Snail.MCP.Security.Extensions;
using Snail.Sdk.Mcp.Hosting;

try
{
    var app = WebApplication.CreateSecurityBuilder(args)
        .ConfigureSecurityServer()
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
