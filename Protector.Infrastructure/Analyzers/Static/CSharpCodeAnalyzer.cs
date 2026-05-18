using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Analyzers.Static;

public sealed class CSharpCodeAnalyzer : IStaticCodeAnalyzer
{
    public string Name => "C# Static Code Analyzer";
    public IEnumerable<string> SupportedExtensions => [".cs"];

    public async Task<IEnumerable<Vulnerability>> AnalyzeFileAsync(
        string filePath,
        CancellationToken ct = default)
    {
        var source = await File.ReadAllTextAsync(filePath, ct);

        // Roslyn parses the file into a syntax tree — a structured representation of code
        var tree = CSharpSyntaxTree.ParseText(source);
        var root = await tree.GetRootAsync(ct);

        var vulnerabilities = new List<Vulnerability>();

        vulnerabilities.AddRange(FindSqlInjections(root, filePath));
        vulnerabilities.AddRange(FindHardcodedSecrets(root, filePath));
        vulnerabilities.AddRange(FindInsecureDeserialization(root, filePath));
        vulnerabilities.AddRange(FindAllowAnonymousOnSensitiveRoutes(root, filePath));
        vulnerabilities.AddRange(FindWeakCryptography(root, filePath));

        return vulnerabilities;
    }

    // Finds SQL queries built by concatenating strings with variables:
    // e.g. "SELECT * FROM users WHERE id = " + userId  <-- dangerous
    private static IEnumerable<Vulnerability> FindSqlInjections(SyntaxNode root, string filePath)
    {
        var sqlKeywords = new[] { "SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM" };

        // Look for binary expressions: something + something
        var binaryExpressions = root
            .DescendantNodes()
            .OfType<BinaryExpressionSyntax>()
            .Where(b => b.IsKind(SyntaxKind.AddExpression));

        foreach (var expr in binaryExpressions)
        {
            var leftText = expr.Left.ToString();

            // Check if the left side is a SQL string literal
            var isSqlString = sqlKeywords.Any(kw =>
                leftText.Contains(kw, StringComparison.OrdinalIgnoreCase));

            // Check if the right side is a variable (not another string literal)
            var rightIsVariable = expr.Right is not LiteralExpressionSyntax;

            if (isSqlString && rightIsVariable)
            {
                var line = expr.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                yield return new Vulnerability
                {
                    Title = "Potential SQL Injection via string concatenation",
                    Description = $"SQL query is built by concatenating a variable directly into the string. " +
                                  $"An attacker who controls the variable can manipulate the query.",
                    Severity = Severity.Critical,
                    Category = VulnerabilityCategory.SqlInjection,
                    FilePath = filePath,
                    LineNumber = line,
                    Evidence = expr.ToString().Trim(),
                    Remediation = "Use parameterized queries: new SqlCommand(\"SELECT * FROM users WHERE id = @id\") " +
                                  "and cmd.Parameters.AddWithValue(\"@id\", userId)",
                    CweId = "CWE-89",
                    OwaspCategory = "A03:2021 Injection"
                };
            }
        }
    }

    // Finds hardcoded passwords, API keys, and secrets in variable assignments:
    // e.g. string password = "mySecret123"  <-- dangerous
    private static IEnumerable<Vulnerability> FindHardcodedSecrets(SyntaxNode root, string filePath)
    {
        var secretPatterns = new[]
        {
            "password", "passwd", "secret", "apikey", "api_key",
            "token", "connectionstring", "privatekey", "accesskey"
        };

        // Look for variable declarations with string literal values
        var assignments = root
            .DescendantNodes()
            .OfType<VariableDeclaratorSyntax>()
            .Where(v =>
                v.Initializer?.Value is LiteralExpressionSyntax lit &&
                lit.IsKind(SyntaxKind.StringLiteralExpression) &&
                !string.IsNullOrWhiteSpace(lit.Token.ValueText) &&
                lit.Token.ValueText.Length > 4); // skip empty/short strings

        foreach (var variable in assignments)
        {
            var name = variable.Identifier.Text.ToLowerInvariant();
            var matchedPattern = secretPatterns.FirstOrDefault(p => name.Contains(p));

            if (matchedPattern is not null)
            {
                var line = variable.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                yield return new Vulnerability
                {
                    Title = $"Hardcoded secret in variable '{variable.Identifier.Text}'",
                    Description = $"A sensitive value is hardcoded directly in source code. " +
                                  $"Anyone with access to the repository can read it.",
                    Severity = Severity.High,
                    Category = VulnerabilityCategory.SensitiveDataExposure,
                    FilePath = filePath,
                    LineNumber = line,
                    Evidence = $"{variable.Identifier.Text} = \"***\"",
                    Remediation = "Move secrets to environment variables or a secrets manager " +
                                  "(e.g. Azure Key Vault, AWS Secrets Manager, .NET User Secrets).",
                    CweId = "CWE-798",
                    OwaspCategory = "A02:2021 Cryptographic Failures"
                };
            }
        }
    }

    // Finds usage of BinaryFormatter — a known unsafe deserializer in .NET:
    // e.g. new BinaryFormatter().Deserialize(stream)  <-- dangerous
    // Microsoft officially deprecated it and recommends against using it
    private static IEnumerable<Vulnerability> FindInsecureDeserialization(SyntaxNode root, string filePath)
    {
        var dangerousTypes = new[] { "BinaryFormatter", "SoapFormatter", "NetDataContractSerializer" };

        var objectCreations = root
            .DescendantNodes()
            .OfType<ObjectCreationExpressionSyntax>()
            .Where(o => dangerousTypes.Any(t =>
                o.Type.ToString().Contains(t)));

        foreach (var creation in objectCreations)
        {
            var line = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

            yield return new Vulnerability
            {
                Title = $"Insecure deserialization using {creation.Type}",
                Description = $"{creation.Type} can deserialize arbitrary types and execute code " +
                              $"during deserialization. This is a known remote code execution vector.",
                Severity = Severity.Critical,
                Category = VulnerabilityCategory.InsecureDeserialization,
                FilePath = filePath,
                LineNumber = line,
                Evidence = creation.ToString().Trim(),
                Remediation = "Replace with System.Text.Json or Newtonsoft.Json with TypeNameHandling.None. " +
                              "Never deserialize untrusted data with BinaryFormatter.",
                CweId = "CWE-502",
                OwaspCategory = "A08:2021 Software and Data Integrity Failures"
            };
        }
    }

    // Finds [AllowAnonymous] on controller actions that have sensitive names:
    // e.g. [AllowAnonymous] on DeleteUser() or AdminPanel()  <-- suspicious
    private static IEnumerable<Vulnerability> FindAllowAnonymousOnSensitiveRoutes(
        SyntaxNode root, string filePath)
    {
        var sensitiveNames = new[]
        {
            "admin", "delete", "remove", "upload", "import",
            "export", "config", "setting", "user", "role"
        };

        var methods = root
            .DescendantNodes()
            .OfType<MethodDeclarationSyntax>()
            .Where(m => m.AttributeLists
                .SelectMany(al => al.Attributes)
                .Any(a => a.Name.ToString().Contains("AllowAnonymous")));

        foreach (var method in methods)
        {
            var methodName = method.Identifier.Text.ToLowerInvariant();
            var matchedName = sensitiveNames.FirstOrDefault(n => methodName.Contains(n));

            if (matchedName is not null)
            {
                var line = method.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                yield return new Vulnerability
                {
                    Title = $"[AllowAnonymous] on sensitive method '{method.Identifier.Text}'",
                    Description = $"The method '{method.Identifier.Text}' allows unauthenticated access " +
                                  $"but its name suggests it may perform a sensitive operation.",
                    Severity = Severity.Medium,
                    Category = VulnerabilityCategory.Authorization,
                    FilePath = filePath,
                    LineNumber = line,
                    Evidence = $"[AllowAnonymous] on {method.Identifier.Text}()",
                    Remediation = "Verify that [AllowAnonymous] is intentional. " +
                                  "Consider using [Authorize] with appropriate roles instead.",
                    CweId = "CWE-306",
                    OwaspCategory = "A01:2021 Broken Access Control"
                };
            }
        }
    }

    // Finds use of weak/broken cryptographic algorithms:
    // e.g. MD5.Create() or new SHA1Managed()  <-- weak hashing
    private static IEnumerable<Vulnerability> FindWeakCryptography(SyntaxNode root, string filePath)
    {
        var weakAlgorithms = new[] { "MD5", "SHA1", "SHA1Managed", "DES", "RC2", "TripleDES" };

        var memberAccesses = root
            .DescendantNodes()
            .OfType<MemberAccessExpressionSyntax>()
            .Where(m => weakAlgorithms.Any(a =>
                m.Expression.ToString().Contains(a)));

        foreach (var access in memberAccesses)
        {
            var line = access.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            var algorithmName = weakAlgorithms.First(a => access.Expression.ToString().Contains(a));

            yield return new Vulnerability
            {
                Title = $"Weak cryptographic algorithm: {algorithmName}",
                Description = $"{algorithmName} is considered cryptographically broken and should not " +
                              $"be used for security-sensitive operations like password hashing.",
                Severity = Severity.High,
                Category = VulnerabilityCategory.StaticAnalysisCSharp,
                FilePath = filePath,
                LineNumber = line,
                Evidence = access.ToString().Trim(),
                Remediation = algorithmName is "MD5" or "SHA1" or "SHA1Managed"
                    ? "Use BCrypt, Argon2, or PBKDF2 for passwords. Use SHA-256/SHA-512 for checksums."
                    : "Replace with AES-256 for symmetric encryption.",
                CweId = "CWE-327",
                OwaspCategory = "A02:2021 Cryptographic Failures"
            };
        }
    }
}
