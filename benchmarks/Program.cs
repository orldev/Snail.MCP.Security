using BenchmarkDotNet.Running;
using Snail.MCP.Security.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(ScanBenchmarks).Assembly).Run(args);
