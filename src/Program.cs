using Snail.MCP.Security.Extensions;

var app = WebApplication.CreateSecurityBuilder(args)
    .ConfigureSecurityServer()
    .Build()
    .UseSecurityEndpoints();

await app.RunAsync();
