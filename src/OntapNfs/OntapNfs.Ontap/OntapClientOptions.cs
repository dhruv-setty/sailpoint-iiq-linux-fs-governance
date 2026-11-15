namespace OntapNfs.Ontap;

/// <summary>
/// Connection settings for the ONTAP REST API. Credentials come from the
/// environment or a secret store at run time and are never committed.
/// </summary>
public sealed class OntapClientOptions
{
    /// <summary>Environment variable holding the cluster management URL, for example https://cluster1.example.com.</summary>
    public const string BaseUrlVariable = "ONTAP_BASE_URL";

    /// <summary>Environment variable holding the API user.</summary>
    public const string UsernameVariable = "ONTAP_USERNAME";

    /// <summary>Environment variable holding the API password.</summary>
    public const string PasswordVariable = "ONTAP_PASSWORD";

    /// <summary>Cluster or SVM management base URL.</summary>
    public required Uri BaseUri { get; init; }

    /// <summary>API user, ideally a role limited to the endpoints this client uses.</summary>
    public required string Username { get; init; }

    /// <summary>API password.</summary>
    public required string Password { get; init; }

    /// <summary>Per request timeout.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Interval between job status polls.</summary>
    public TimeSpan JobPollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>How long to wait for an asynchronous job.</summary>
    public TimeSpan JobTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Reads options from <see cref="BaseUrlVariable"/>, <see cref="UsernameVariable"/> and <see cref="PasswordVariable"/>.</summary>
    /// <param name="getVariable">Lookup, replaceable in tests; defaults to <see cref="Environment.GetEnvironmentVariable(string)"/>.</param>
    public static OntapClientOptions FromEnvironment(Func<string, string?>? getVariable = null)
    {
        getVariable ??= Environment.GetEnvironmentVariable;
        var url = Require(getVariable, BaseUrlVariable);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException($"{BaseUrlVariable} must be an absolute https URL.");
        }

        return new OntapClientOptions
        {
            BaseUri = uri,
            Username = Require(getVariable, UsernameVariable),
            Password = Require(getVariable, PasswordVariable),
        };
    }

    /// <summary>Never prints the password.</summary>
    public override string ToString() => $"{BaseUri} as {Username}";

    private static string Require(Func<string, string?> get, string name)
    {
        var value = get(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Environment variable {name} is not set.");
        }

        return value;
    }
}
