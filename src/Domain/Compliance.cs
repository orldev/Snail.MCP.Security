namespace Snail.MCP.Security.Domain;

/// <summary>A measure of the Spanish National Security Scheme or a letter of NIS2's Article 21(2), with its official title.</summary>
public sealed record Reference(string Code, string Title);

/// <summary>What a finding of each check touches in ENS and NIS2: the measures it falls under, as a reference for the human, not a certification.</summary>
/// <remarks>
/// <para>
/// ENS is Real Decreto 311/2022, Anexo II, read in the BOE's consolidated text (BOE-A-2022-7191); NIS2 is Directive (EU)
/// 2022/2555, Article 21(2), read in EUR-Lex (CELEX 32022L2555). Titles are the official ones.
/// </para>
/// <para>
/// Two readings are interpretation rather than the letter: op.acc.5 and op.acc.6 are written for the authentication of
/// people, and a token or a cloud key in code is a machine's credential; a cryptographic key adds op.exp.10 and NIS2's
/// cryptography letter (h). A site's findings fall under the measures of communications (mp.com), of web services and of
/// e-mail (mp.s.1, mp.s.2); open services under configuration, maintenance and the secure perimeter. As of October 2026 Spain has not transposed NIS2 — the draft law of 14 January 2025 is still
/// in passage — so for Spanish entities it is the obligation to come, and RDL 12/2018 the one in force.
/// </para>
/// </remarks>
public static class Compliance
{
    private static readonly Reference Maintenance = new("op.exp.4", "Mantenimiento y actualizaciones de seguridad");
    private static readonly Reference SupplyChainEns = new("op.ext.3", "Protección de la cadena de suministro");
    private static readonly Reference ExternalUsers = new("op.acc.5", "Mecanismo de autenticación (usuarios externos)");
    private static readonly Reference OrganisationUsers = new("op.acc.6", "Mecanismo de autenticación (usuarios de la organización)");
    private static readonly Reference Keys = new("op.exp.10", "Protección de claves criptográficas");
    private static readonly Reference Configuration = new("op.exp.2", "Configuración de seguridad");
    private static readonly Reference ConfigurationManagement = new("op.exp.3", "Gestión de la configuración de seguridad");
    private static readonly Reference Development = new("mp.sw.1", "Desarrollo de aplicaciones");
    private static readonly Reference Acceptance = new("mp.sw.2", "Aceptación y puesta en servicio");

    private static readonly Reference Perimeter = new("mp.com.1", "Perímetro seguro");
    private static readonly Reference Confidentiality = new("mp.com.2", "Protección de la confidencialidad");
    private static readonly Reference Integrity = new("mp.com.3", "Protección de la integridad y de la autenticidad");
    private static readonly Reference Mail = new("mp.s.1", "Protección del correo electrónico");
    private static readonly Reference Web = new("mp.s.2", "Protección de servicios y aplicaciones web");

    private static readonly Reference SupplyChain = new("NIS2 21(2)(d)", "supply chain security");
    private static readonly Reference Lifecycle = new("NIS2 21(2)(e)", "security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure");
    private static readonly Reference Cryptography = new("NIS2 21(2)(h)", "policies and procedures regarding the use of cryptography and, where appropriate, encryption");
    private static readonly Reference AccessControl = new("NIS2 21(2)(i)", "human resources security, access control policies and asset management");

    /// <summary>The ENS measures a finding falls under.</summary>
    public static IReadOnlyList<Reference> Ens(Finding finding) => finding.Check switch
    {
        Check.Packages => [Maintenance, SupplyChainEns],
        Check.Secrets when IsKey(finding) => [OrganisationUsers, ExternalUsers, Keys],
        Check.Secrets => [OrganisationUsers, ExternalUsers],
        Check.Config => [Configuration, ConfigurationManagement],
        Check.Code => [Development, Acceptance],
        Check.Tls => [Confidentiality, Integrity, Web],
        Check.Headers => [Web, Configuration],
        Check.Mail => [Mail],
        Check.Exposure => [Web, Configuration],
        _ => [Configuration, Maintenance, Perimeter]
    };

    /// <summary>The letters of NIS2's Article 21(2) a finding falls under.</summary>
    public static IReadOnlyList<Reference> Nis2(Finding finding) => finding.Check switch
    {
        Check.Packages => [Lifecycle, SupplyChain],
        Check.Secrets when IsKey(finding) => [AccessControl, Cryptography],
        Check.Secrets => [AccessControl],
        Check.Tls => [Cryptography, Lifecycle],
        Check.Exposure or Check.Services => [Lifecycle, AccessControl],
        _ => [Lifecycle]
    };

    /// <summary>Whether a secret is a cryptographic key rather than a token or a password.</summary>
    private static bool IsKey(Finding finding) => finding.Rule.Contains("private-key", StringComparison.OrdinalIgnoreCase);
}
