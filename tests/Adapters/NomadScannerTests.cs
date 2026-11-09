using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting.Sessions;
using Snail.Toolkit.Nomad;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>The scan's job against a Nomad that answers from a script: what the scanner does when the scan does not go as planned.</summary>
public sealed class NomadScannerTests
{
    private static readonly WorkspacePlace<string> Copy = new("task-1", "/workspaces/task-1/step-1");

    /// <summary>A client that gives up mid-scan must not leave the scanners reading the copy for the rest of the scan time.</summary>
    [Fact]
    public async Task ScanAsync_CancelledWhileRunning_StopsTheJob()
    {
        var nomad = new ScriptedNomad(_ => (HttpStatusCode.OK, "[]"));
        using var scanner = Scanner(nomad, new SecurityOptions());
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scanner.ScanAsync(Copy, Checks.Copy, cancel.Token));

        Assert.Equal(["DELETE /v1/job/sec-task-1?purge=true", "POST /v1/jobs", "DELETE /v1/job/sec-task-1"], nomad.Requests.Where(IsJobChange));
    }

    /// <summary>Nomad refusing the job is every check not run, in Nomad's words, never an exception the client sees as "an error occurred".</summary>
    [Fact]
    public async Task ScanAsync_NomadRefusesTheJob_EveryCheckDidNotRunWithNomadsWords()
    {
        var nomad = new ScriptedNomad(request => request.StartsWith("POST", StringComparison.Ordinal)
            ? (HttpStatusCode.InternalServerError, "rpc error: no path to region")
            : (HttpStatusCode.OK, "[]"));
        using var scanner = Scanner(nomad, new SecurityOptions());

        var outcome = await scanner.ScanAsync(Copy, Checks.Copy, CancellationToken.None);

        Assert.Empty(outcome.Findings);
        Assert.All(outcome.Runs, run => Assert.False(run.HasRun));
        Assert.All(outcome.Runs, run => Assert.Contains("no path to region", run.Note, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanAsync_JobThatOutlastsTheScanTime_IsStoppedAndEveryCheckDidNotRun()
    {
        var nomad = new ScriptedNomad(_ => (HttpStatusCode.OK, "[]"));
        using var scanner = Scanner(nomad, new SecurityOptions { ScanSeconds = 1 });

        var outcome = await scanner.ScanAsync(Copy, [Check.Code], CancellationToken.None);

        var run = Assert.Single(outcome.Runs);
        Assert.False(run.HasRun);
        Assert.Contains("did not finish in 1 s", run.Note, StringComparison.Ordinal);
        Assert.Equal("DELETE /v1/job/sec-task-1", nomad.Requests.Where(IsJobChange).Last());
    }

    private static bool IsJobChange(string request) =>
        request.StartsWith("DELETE", StringComparison.Ordinal) || request.StartsWith("POST", StringComparison.Ordinal);

    private static NomadScanner Scanner(ScriptedNomad nomad, SecurityOptions settings)
    {
        var http = new HttpClient(nomad) { BaseAddress = new Uri("http://nomad:4646/") };
        var client = new NomadClient(http, Options.Create(new NomadOptions { Address = "http://nomad:4646" }));

        return new NomadScanner(client, new NoFixes(), Options.Create(settings), TimeProvider.System);
    }

    private sealed class NoFixes : IFixes
    {
        public Task<string?> FixedInAsync(string package, string advisory, CancellationToken cancellationToken) => Task.FromResult<string?>(null);
    }

    /// <summary>Nomad as a script: a stop and a registration are acknowledged, every other request answered as the test says.</summary>
    private sealed class ScriptedNomad(Func<string, (HttpStatusCode Status, string Body)> answer) : HttpMessageHandler
    {
        private const string Acknowledged = """{"EvalID":"e","JobModifyIndex":1}""";

        public ConcurrentQueue<string> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string line = $"{request.Method} {request.RequestUri?.PathAndQuery}";
            Requests.Enqueue(line);

            (HttpStatusCode status, string body) = answer(line);
            bool isAcknowledged = status == HttpStatusCode.OK && (request.Method == HttpMethod.Delete || request.Method == HttpMethod.Post);
            var response = new HttpResponseMessage(status) { Content = new StringContent(isAcknowledged ? Acknowledged : body, Encoding.UTF8, "application/json") };

            return Task.FromResult(response);
        }
    }
}
