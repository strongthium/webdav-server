using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Strongthium.WebDavServer.Storage;

/// <summary>
/// Puts a finished file in the place of another in one step, so that nobody ever sees half of it or none of it, and someone
/// downloading the old one carries on with the old one. Linux's rename does exactly this. Windows' ordinary one refuses if the
/// old file is open at all, which on a file server it often is, so it's asked for the same behaviour by name (POSIX rename
/// semantics, on NTFS since Windows 10 1809). Where that's not there, the old file steps aside first, which leaves a moment
/// without either, and is still better than refusing the upload.
/// </summary>
public static partial class AtomicFile
{
    public static void Replace(string source, string destination)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.Move(source, destination, overwrite: true);
            return;
        }

        var tries = 0;
        while (true)
        {
            try
            {
                ReplaceOnWindows(source, destination);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException && ++tries < 5)
            {
                // A virus scanner or an indexer can have a file open without sharing it, for a moment.
                Thread.Sleep(50 * tries);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ReplaceOnWindows(string source, string destination)
    {
        if (TryPosixRename(source, destination)) return;
        if (!File.Exists(destination))
        {
            File.Move(source, destination);
            return;
        }
        var aside = source + ".old";
        File.Move(destination, aside);
        try
        {
            File.Move(source, destination);
        }
        catch
        {
            File.Move(aside, destination);
            throw;
        }
        try
        {
            File.Delete(aside);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Someone is still reading it. It's in the server's own folder, and goes in a later sweep.
        }
    }

    private const uint Delete = 0x00010000, Synchronize = 0x00100000;
    private const uint ShareAll = 7, OpenExisting = 3;
    private const int FileRenameInfoEx = 22;
    private const uint ReplaceIfExists = 1, PosixSemantics = 2;

    [SupportedOSPlatform("windows")]
    private static bool TryPosixRename(string source, string destination)
    {
        using var handle = CreateFileW(@"\\?\" + source, Delete | Synchronize, ShareAll, 0, OpenExisting, 0, 0);
        if (handle.IsInvalid) return false;

        // FILE_RENAME_INFO: flags, a handle's worth of root directory, the name's length in bytes, then the name itself.
        var name = Encoding.Unicode.GetBytes(@"\\?\" + destination);
        var rootOffset = IntPtr.Size;
        var lengthOffset = rootOffset + IntPtr.Size;
        var nameOffset = lengthOffset + sizeof(uint);
        var buffer = new byte[nameOffset + name.Length + sizeof(char)];
        BitConverter.TryWriteBytes(buffer, ReplaceIfExists | PosixSemantics);
        BitConverter.TryWriteBytes(buffer.AsSpan(lengthOffset), (uint)name.Length);
        name.CopyTo(buffer, nameOffset);
        if (SetFileInformationByHandle(handle, FileRenameInfoEx, buffer, (uint)buffer.Length)) return true;

        // 1 and 87 are what a volume that doesn't know this says: the caller then does it the other way.
        var error = Marshal.GetLastPInvokeError();
        if (error is 1 or 50 or 87 or 124) return false;
        throw new IOException(new Win32Exception(error).Message, error);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string name, uint access, uint share, nint security, uint creation, uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, byte[] buffer, uint size);
}
