using System.Net;
using System.Text;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

string allNodesCsvFilename = string.Empty;
string existNodesCsvFilename = string.Empty;
try
{
    using HttpClient client = new();
    const string URL = "https://onionoo.torproject.org/details?search=type:relay%20running:true";
    using Stream responseStream = await client.GetStreamAsync(URL);

    allNodesCsvFilename = Path.GetTempFileName();
    using FileStream allNodesFS = File.OpenWrite(allNodesCsvFilename);
    using StreamWriter allNodesSW = new(allNodesFS);
    allNodesSW.WriteLine("fingerprint, ipaddr, port");

    existNodesCsvFilename = Path.GetTempFileName();
    using FileStream exitNodesFS = File.OpenWrite(existNodesCsvFilename);
    using StreamWriter exitNodesSW = new(exitNodesFS);
    exitNodesSW.WriteLine("fingerprint, ipaddr, port");

    using StreamReader streamReader = new(responseStream);
    for (string? line = null; (line = await streamReader.ReadLineAsync()) != null;)
    {
        if (!line.StartsWith("{\"nickname\":") || line.Length < 3)
            continue;

        if (line.EndsWith(','))
            line = line[..^1];

        TorNode? node = JsonSerializer.Deserialize<TorNode>(line);
        if (node == null)
            continue;

        await allNodesSW.WriteLineAsync(node.ToCSV());
        if (node.Flags.Select(i => i.ToLower()).Contains("exit"))
            await exitNodesSW.WriteLineAsync(node.ToCSV());
    }

    string currentDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
    File.Move(allNodesCsvFilename, Path.Combine(currentDirectory, "tor-nodes.csv"), true);
    File.Move(existNodesCsvFilename, Path.Combine(currentDirectory, "tor-exit-nodes.csv"), true);
}
catch
{
    if (File.Exists(allNodesCsvFilename))
        File.Delete(allNodesCsvFilename);

    if (File.Exists(existNodesCsvFilename))
        File.Delete(existNodesCsvFilename);
}


#nullable disable
class TorNode
{
    // [JsonPropertyName("nickname")]
    // public string Nickname { get; set; }

    [JsonPropertyName("fingerprint")]
    public string Fingerprint { get; set; }

    [JsonPropertyName("or_addresses")]
    public string[] OrAddresses { get; set; }

    // [JsonPropertyName("last_seen")]
    // public DateTimeOffset LastSeen { get; set; }

    // [JsonPropertyName("last_changed_address_or_port")]
    // public DateTime LastChangedAddressOrPort { get; set; }

    // [JsonPropertyName("first_seen")]
    // public DateTime FirstSeen { get; set; }

    // [JsonPropertyName("running")]
    // public bool IsRunning { get; set; }

    [JsonPropertyName("flags")]
    public string[] Flags { get; set; }

    // [JsonPropertyName("country")]
    // public string CountryCode { get; set; }

    // [JsonPropertyName("as")]
    // public string ASN { get; set; }

    // [JsonPropertyName("last_restarted")]
    // public DateTime LastRestarted { get; set; }

    // [JsonPropertyName("bandwidth_rate")]
    // public uint BandwidthRate { get; set; }

    // [JsonPropertyName("bandwidth_burst")]
    // public uint BandwidthBurst { get; set; }

    // [JsonPropertyName("observed_bandwidth")]
    // public uint ObservedBandwidth { get; set; }

    // [JsonPropertyName("advertised_bandwidth")]
    // public uint AdvertisedBandwidth { get; set; }

    // [JsonPropertyName("contact")]
    // [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    // public string Contact { get; set; }

    // [JsonPropertyName("platform")]
    // public string Platform { get; set; }

    // [JsonPropertyName("version")]
    // public string Version { get; set; }

    // [JsonPropertyName("exit_addresses")]
    // [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    // public string[] ExitAddresses { get; set; }

    public string ToCSV()
    {
        StringBuilder sb = new();
        foreach (string ipPort in OrAddresses)
        {
            Uri uri = new($"tcp://{ipPort}");
            IPAddress ip = IPAddress.Parse(uri.Host);
            sb.AppendLine($"{Fingerprint}, {ip.ToString()}, {uri.Port}");
        }
        return sb.ToString()[..^1];
    }
}
#nullable enable
