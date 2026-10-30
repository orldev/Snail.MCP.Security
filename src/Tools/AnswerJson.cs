using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Snail.MCP.Security.Tools;

/// <summary>The generated JSON of what a scan's job ends with: the scan as its answer carries it.</summary>
[JsonSerializable(typeof(JsonObject))]
public sealed partial class AnswerJson : JsonSerializerContext;
