using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Configuration;
using Snail.Toolkit.Nomad;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>The site scan's job against a Nomad that answers from a script: a scan given up on stops the scanners at the customer's site.</summary>
public sealed class NomadSiteScannerTests
{
    private static readonly Site Shop = new("shop.example.com");

    private static readonly IReadOnlyList<IPAddress> Addresses = [IPAddress.Parse("93.184.215.14")];

    /// <summary>A client that gives up mid-scan must not leave the scanners at the customer's site for the rest of the scan time.</summary>
    [Fact]
    public async Task ScanAsync_CancelledWhileRunning_StopsTheJob()
    {
        var nomad = new ScriptedNomad(_ => (HttpStatusCode.OK, "[]"));
        using var scanner = Scanner(nomad, new SecurityOptions());
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scanner.ScanAsync(Shop, Addresses, [Check.Tls, Check.Services], cancel.Token));

        Assert.Equal(["DELETE /v1/job/sec-site-shop.example.com?purge=true", "POST /v1/jobs", "DELETE /v1/job/sec-site-shop.example.com"], nomad.Requests.Where(IsJobChange));
    }

    [Fact]
    public async Task ScanAsync_NomadRefusesTheJob_EveryCheckDidNotRunWithNomadsWords()
    {
        var nomad = new ScriptedNomad(request => request.StartsWith("POST", StringComparison.Ordinal)
            ? (HttpStatusCode.InternalServerError, "rpc error: no path to region")
            : (HttpStatusCode.OK, "[]"));
        using var scanner = Scanner(nomad, new SecurityOptions());

        var outcome = await scanner.ScanAsync(Shop, Addresses, [Check.Headers, Check.Services], CancellationToken.None);

        Assert.Empty(outcome.Findings);
        Assert.Equal(2, outcome.Runs.Count);
        Assert.All(outcome.Runs, run => Assert.Contains("no path to region", run.Note, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanAsync_JobThatOutlastsTheScanTime_IsStoppedAndEveryCheckDidNotRun()
    {
        var nomad = new ScriptedNomad(_ => (HttpStatusCode.OK, "[]"));
        using var scanner = Scanner(nomad, new SecurityOptions { ScanSeconds = 1 });

        var outcome = await scanner.ScanAsync(Shop, Addresses, [Check.Services], CancellationToken.None);

        var run = Assert.Single(outcome.Runs);
        Assert.False(run.HasRun);
        Assert.Contains("did not finish in 1 s", run.Note, StringComparison.Ordinal);
        Assert.Equal("DELETE /v1/job/sec-site-shop.example.com", nomad.Requests.Where(IsJobChange).Last());
    }

    /// <summary>nmap failing leaves TLS to Nuclei, which proves it; Nuclei failing leaves TLS, headers and exposure unproven.</summary>
    [Fact]
    public void Covered_EachScanner_AnswersForItsOwnChecks()
    {
        IReadOnlyCollection<Check> every = [Check.Tls, Check.Headers, Check.Exposure, Check.Services];

        Assert.Equal([Check.Tls, Check.Headers, Check.Exposure], NomadSiteScanner.Covered(SiteJob.Nuclei, every));
        Assert.Equal([Check.Services], NomadSiteScanner.Covered(SiteJob.Nmap, every));
    }

    private static bool IsJobChange(string request) =>
        request.StartsWith("DELETE", StringComparison.Ordinal) || request.StartsWith("POST", StringComparison.Ordinal);

    private static NomadSiteScanner Scanner(ScriptedNomad nomad, SecurityOptions settings)
    {
        var http = new HttpClient(nomad) { BaseAddress = new Uri("http://nomad:4646/") };
        var client = new NomadClient(http, Options.Create(new NomadOptions { Address = "http://nomad:4646" }));

        return new NomadSiteScanner(new NomadBatch(client, TimeProvider.System), Options.Create(settings));
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
