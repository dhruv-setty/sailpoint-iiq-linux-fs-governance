using System.IO.Compression;
using System.Net;
using System.Text;

namespace OntapNfs.Tests;

/// <summary>A unique temporary directory removed on dispose; stands in for an NFS mount root.</summary>
internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ontapnfs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string Combine(params string[] parts) => System.IO.Path.Combine(new[] { Path }.Concat(parts).ToArray());

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

internal static class Wars
{
    /// <summary>Writes a minimal WAR (ZIP with WEB-INF/web.xml) and returns its path.</summary>
    public static string Create(string directory, string name = "app.war", bool withWebInf = true)
    {
        var path = System.IO.Path.Combine(directory, name);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        var entry = zip.CreateEntry(withWebInf ? "WEB-INF/web.xml" : "index.html");
        using var w = new StreamWriter(entry.Open());
        w.Write(withWebInf ? "<web-app/>" : "<html/>");
        return path;
    }
}

/// <summary>
/// HttpMessageHandler that answers from a route table keyed by "METHOD path"
/// (path without query) and records every request with its body.
/// </summary>
internal sealed class FakeOntapHandler : HttpMessageHandler
{
    private readonly Dictionary<string, Queue<Func<HttpRequestMessage, HttpResponseMessage>>> _routes = new(StringComparer.Ordinal);

    public List<RecordedRequest> Requests { get; } = new();

    public FakeOntapHandler On(string method, string path, HttpStatusCode status, string json)
        => On(method, path, _ => Json(status, json));

    public FakeOntapHandler On(string method, string path, Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        var key = method + " " + path;
        if (!_routes.TryGetValue(key, out var queue))
        {
            queue = new Queue<Func<HttpRequestMessage, HttpResponseMessage>>();
            _routes[key] = queue;
        }

        queue.Enqueue(responder);
        return this;
    }

    public IEnumerable<RecordedRequest> Writes => Requests.Where(r => r.Method != "GET");

    public static HttpResponseMessage Json(HttpStatusCode status, string json)
        => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add(new RecordedRequest(request.Method.Method, request.RequestUri!.AbsolutePath, request.RequestUri.Query, body, request.Headers.Authorization?.ToString()));
        var key = request.Method.Method + " " + request.RequestUri.AbsolutePath;
        if (!_routes.TryGetValue(key, out var queue) || queue.Count == 0)
        {
            return Json(HttpStatusCode.NotFound, "{\"error\":{\"message\":\"no fake route for " + key + "\",\"code\":\"4\"}}");
        }

        // The last responder for a route repeats; earlier ones are used once each.
        var responder = queue.Count > 1 ? queue.Dequeue() : queue.Peek();
        return responder(request);
    }
}

internal sealed record RecordedRequest(string Method, string Path, string Query, string? Body, string? Authorization);
