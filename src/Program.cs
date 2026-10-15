using Snail.MCP.Security.Extensions;

var app = WebApplication.CreateBuilder(args)
    .ConfigureSecurityServer()
    .Build()
    .UseSecurityEndpoints();

await app.RunAsync();

/// <summary>The entry point, named so the contract tests can host the server in memory.</summary>
public partial class Program;
