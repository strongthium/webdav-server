using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Strongthium.WebDavServer.Dav;

/// <summary>The XML of WebDAV's requests and answers.</summary>
public static class DavXml
{
    public static readonly XNamespace D = "DAV:";
    public static readonly XNamespace OC = "http://owncloud.org/ns";
    public static readonly XNamespace NC = "http://nextcloud.org/ns";
    public static readonly XNamespace MS = "urn:schemas-microsoft-com:";

    /// <summary>The most a request's XML may be. Only a file's content can be larger.</summary>
    public const int MaxRequestBytes = 1024 * 1024;

    /// <summary>
    /// Reads a request's XML with everything that makes XML dangerous turned off: no DTDs, so no entity bombs and no external
    /// entities reading the server's files (XXE); no resolver to fetch anything with; a limit on size. Null for an empty body.
    /// Throws <see cref="XmlException"/> for what can't be read, which is a 400.
    /// </summary>
    public static async Task<XDocument?> ReadAsync(HttpContext context)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await context.Request.Body.ReadAsync(chunk, context.RequestAborted)) > 0)
        {
            if (buffer.Length + read > MaxRequestBytes) throw new XmlException("The request's XML is too large.");
            buffer.Write(chunk, 0, read);
        }
        if (buffer.Length == 0) return null;
        buffer.Position = 0;
        return Parse(buffer);
    }

    public static XDocument Parse(Stream stream)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 1024,
            MaxCharactersInDocument = MaxRequestBytes * 2,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
        };
        using var reader = XmlReader.Create(stream, settings);
        return XDocument.Load(reader, LoadOptions.None);
    }

    public static XElement Multistatus(IEnumerable<XElement> responses) =>
        new(D + "multistatus",
            new XAttribute(XNamespace.Xmlns + "d", D.NamespaceName),
            new XAttribute(XNamespace.Xmlns + "oc", OC.NamespaceName),
            new XAttribute(XNamespace.Xmlns + "nc", NC.NamespaceName),
            responses);

    public static XElement Status(int code) => new(D + "status", $"HTTP/1.1 {code} {Reason(code)}");

    public static string Reason(int code) => code switch
    {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        207 => "Multi-Status",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        412 => "Precondition Failed",
        423 => "Locked",
        424 => "Failed Dependency",
        507 => "Insufficient Storage",
        _ => "",
    };

    public static byte[] ToBytes(XElement root)
    {
        using var stream = new MemoryStream();
        var settings = new XmlWriterSettings { Encoding = new UTF8Encoding(false), Indent = false, Async = false };
        using (var writer = XmlWriter.Create(stream, settings))
        {
            new XDocument(new XDeclaration("1.0", "utf-8", null), root).Save(writer);
        }
        return stream.ToArray();
    }

    public static async Task WriteAsync(HttpContext context, int status, XElement root)
    {
        var bytes = ToBytes(root);
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/xml; charset=utf-8";
        context.Response.ContentLength = bytes.Length;
        if (!HttpMethods.IsHead(context.Request.Method)) await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
    }

    /// <summary>An error with the precondition or postcondition it comes from, as RFC 4918 section 16 has it.</summary>
    public static Task WriteErrorAsync(HttpContext context, int status, XElement condition) =>
        WriteAsync(context, status, new XElement(D + "error", new XAttribute(XNamespace.Xmlns + "d", D.NamespaceName), condition));

    /// <summary>Allows a larger body than the XML limit, for an upload. Null is no limit.</summary>
    public static void AllowBody(HttpContext context, long? bytes)
    {
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } feature) feature.MaxRequestBodySize = bytes;
    }
}
