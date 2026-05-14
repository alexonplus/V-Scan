using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Infrastructure.Analyzers.Http;

public sealed class SslAnalyzer : HttpAnalyzerBase
{
    public override string Name => "SSL/TLS Analyzer";

    public SslAnalyzer(IHttpClientFactory factory) : base(factory) { }

    public override async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        var host = target.BaseUrl.Host;

        // Skip non-HTTPS targets
        if (!target.BaseUrl.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            vulnerabilities.Add(new Vulnerability
            {
                Title = "Site not using HTTPS",
                Description = "The target site is served over plain HTTP. " +
                              "All traffic including credentials can be intercepted.",
                Severity = Severity.Critical,
                Category = VulnerabilityCategory.SslTls,
                Url = target.BaseUrl.ToString(),
                Evidence = $"URL scheme is '{target.BaseUrl.Scheme}'",
                Remediation = "Enable HTTPS with a valid TLS certificate. " +
                              "Redirect all HTTP traffic to HTTPS.",
                CweId = "CWE-319",
                OwaspCategory = "A02:2021 Cryptographic Failures"
            });
            return vulnerabilities;
        }

        // Check certificate validity
        var certVulns = await CheckCertificateAsync(host, target.BaseUrl.ToString(), ct);
        vulnerabilities.AddRange(certVulns);

        // Check for HTTP redirect (HTTPS site should redirect HTTP)
        var httpUrl = $"http://{host}{target.BaseUrl.PathAndQuery}";
        var httpResponse = await TryGetAsync(httpUrl, ct);
        if (httpResponse is not null &&
            (int)httpResponse.StatusCode is not (>= 300 and < 400))
        {
            vulnerabilities.Add(new Vulnerability
            {
                Title = "HTTP traffic not redirected to HTTPS",
                Description = "The server serves content over HTTP without redirecting to HTTPS.",
                Severity = Severity.Medium,
                Category = VulnerabilityCategory.SslTls,
                Url = httpUrl,
                Evidence = $"HTTP request returned status {(int)httpResponse.StatusCode} instead of a redirect",
                Remediation = "Configure your web server to redirect all HTTP requests to HTTPS. " +
                              "In ASP.NET Core call app.UseHttpsRedirection().",
                CweId = "CWE-319",
                OwaspCategory = "A02:2021 Cryptographic Failures"
            });
        }

        return vulnerabilities;
    }

    private async Task<IEnumerable<Vulnerability>> CheckCertificateAsync(
        string host, string url, CancellationToken ct)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(host, 443, ct);

            using var sslStream = new SslStream(
                tcpClient.GetStream(),
                false,
                (_, cert, _, errors) =>
                {
                    if (cert is X509Certificate2 x509)
                    {
                        // Check expiry
                        if (x509.NotAfter < DateTime.UtcNow)
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Title = "SSL certificate has expired",
                                Description = $"The certificate expired on {x509.NotAfter:yyyy-MM-dd}.",
                                Severity = Severity.Critical,
                                Category = VulnerabilityCategory.SslTls,
                                Url = url,
                                Evidence = $"NotAfter: {x509.NotAfter:yyyy-MM-dd}",
                                Remediation = "Renew the SSL certificate immediately.",
                                CweId = "CWE-298",
                                OwaspCategory = "A02:2021 Cryptographic Failures"
                            });
                        }
                        else if (x509.NotAfter < DateTime.UtcNow.AddDays(30))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Title = "SSL certificate expires within 30 days",
                                Description = $"The certificate will expire on {x509.NotAfter:yyyy-MM-dd}.",
                                Severity = Severity.Medium,
                                Category = VulnerabilityCategory.SslTls,
                                Url = url,
                                Evidence = $"NotAfter: {x509.NotAfter:yyyy-MM-dd}",
                                Remediation = "Renew the SSL certificate before it expires.",
                                CweId = "CWE-298",
                                OwaspCategory = "A02:2021 Cryptographic Failures"
                            });
                        }
                    }
                    return errors == SslPolicyErrors.None;
                });

            await sslStream.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }, ct);
        }
        catch (AuthenticationException ex)
        {
            vulnerabilities.Add(new Vulnerability
            {
                Title = "SSL certificate validation failed",
                Description = "The server's SSL certificate could not be validated.",
                Severity = Severity.Critical,
                Category = VulnerabilityCategory.SslTls,
                Url = url,
                Evidence = ex.Message,
                Remediation = "Ensure the certificate is issued by a trusted CA, " +
                              "the domain matches, and the certificate is not expired.",
                CweId = "CWE-295",
                OwaspCategory = "A02:2021 Cryptographic Failures"
            });
        }
        catch { /* network unreachable — skip */ }

        return vulnerabilities;
    }
}
