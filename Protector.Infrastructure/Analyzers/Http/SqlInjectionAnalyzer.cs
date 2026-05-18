using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Infrastructure.Analyzers.Http;

public sealed class SqlInjectionAnalyzer : HttpAnalyzerBase
{
    public override string Name => "SQL Injection Analyzer";

    public SqlInjectionAnalyzer(IHttpClientFactory factory) : base(factory) { }

    private static readonly string[] Payloads =
    [
        "'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"",
        "1; DROP TABLE users--", "1' AND SLEEP(2)--", "' UNION SELECT NULL--"
    ];

    // Patterns in response body that indicate a SQL error was thrown
    private static readonly string[] ErrorSignatures =
    [
        "sql syntax", "mysql_fetch", "ORA-", "SQLite3::", "SQLSTATE",
        "syntax error", "unclosed quotation mark", "microsoft ole db",
        "postgresql", "pg_query", "mssql_query", "sqlite_query",
        "supplied argument is not a valid mysql", "division by zero"
    ];

    public override async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        var query = System.Web.HttpUtility.ParseQueryString(target.BaseUrl.Query);

        if (query.Count == 0)
            return vulnerabilities;

        foreach (string? paramName in query)
        {
            if (paramName is null) continue;

            foreach (var payload in Payloads)
            {
                ct.ThrowIfCancellationRequested();

                var testUrl = InjectPayload(target.BaseUrl.ToString(), paramName, payload);
                var response = await TryGetAsync(testUrl, ct);
                if (response is null) continue;

                var body = await response.Content.ReadAsStringAsync(ct);
                var lowerBody = body.ToLowerInvariant();

                var matchedSignature = ErrorSignatures
                    .FirstOrDefault(sig => lowerBody.Contains(sig));

                if (matchedSignature is not null)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = $"SQL Injection in parameter '{paramName}'",
                        Description = $"Parameter '{paramName}' is vulnerable to SQL injection. " +
                                      $"The application returned a database error when injecting payload.",
                        Severity = Severity.Critical,
                        Category = VulnerabilityCategory.SqlInjection,
                        Url = target.BaseUrl.ToString(),
                        Parameter = paramName,
                        Payload = payload,
                        Evidence = $"Response contained SQL error signature: '{matchedSignature}'",
                        Remediation = "Use parameterized queries or prepared statements. " +
                                      "Never concatenate user input directly into SQL queries.",
                        CweId = "CWE-89",
                        OwaspCategory = "A03:2021 Injection"
                    });

                    break; // one confirmed vuln per parameter is enough
                }
            }
        }

        return vulnerabilities;
    }
}
