/* efb_platform_write.h - v0.1 - public domain data structures - nickscha 2025

A C89 standard compliant, single header, nostdlib (no C Standard Library) utility to write a file using OS-specific APIs.

Supports:
 - Windows (Win32 API)
 - Linux / macOS (POSIX)
 - BSDs (FreeBSD, NetBSD, OpenBSD, Haiku)

LICENSE

  Placed in the public domain and also MIT licensed.
  See end of file for detailed license information.

*/
#ifndef EFB_PLATFORM_WRITE_H
#define EFB_PLATFORM_WRITE_H

/* #############################################################################
 * # COMPILER SETTINGS
 * #############################################################################
 */
/* Check if using C99 or later (inline is supported) */
#if __STDC_VERSION__ >= 199901L
#define EFB_PLATFORM_INLINE inline
#define EFB_PLATFORM_API extern
#elif defined(__GNUC__) || defined(__clang__)
#define EFB_PLATFORM_INLINE __inline__
#define EFB_PLATFORM_API static
#elif defined(_MSC_VER)
#define EFB_PLATFORM_INLINE __inline
#define EFB_PLATFORM_API static
#else
#define EFB_PLATFORM_INLINE
#define EFB_PLATFORM_API static
#endif

#ifdef _WIN32
#define EFB_WIN32_GENERIC_WRITE (0x40000000L)
#define EFB_WIN32_CREATE_ALWAYS 2
#define EFB_WIN32_FILE_ATTRIBUTE_NORMAL 0x00000080

#ifndef _WINDOWS_
#define EFB_WIN32_API(r) __declspec(dllimport) r __stdcall

EFB_WIN32_API(int)
CloseHandle(void *hObject);

EFB_WIN32_API(void *)
CreateFileA(
    const char *lpFileName,
    unsigned long dwDesiredAccess,
    unsigned long dwShareMode,
    void *,
    unsigned long dwCreationDisposition,
    unsigned long dwFlagsAndAttributes,
    void *hTemplateFile);

EFB_WIN32_API(int)
WriteFile(
    void *hFile,
    const void *lpBuffer,
    unsigned long nNumberOfBytesToWrite,
    unsigned long *lpNumberOfBytesWritten,
    void *lpOverlapped);

#endif /* _WINDOWS_   */

EFB_PLATFORM_API EFB_PLATFORM_INLINE int efb_platform_write(char *filename, unsigned char *buffer, unsigned long size)
{
    void *hFile;
    unsigned long bytes_written;
    int success;

    hFile = CreateFileA(filename, EFB_WIN32_GENERIC_WRITE, 0, 0, EFB_WIN32_CREATE_ALWAYS, EFB_WIN32_FILE_ATTRIBUTE_NORMAL, 0);
    success = WriteFile(hFile, buffer, size, &bytes_written, 0);
    success = CloseHandle(hFile);

    return (success && (bytes_written == size));
}

#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__HAIKU__)

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

EFB_PLATFORM_API EFB_PLATFORM_INLINE int efb_platform_write(char *filename, unsigned char *buffer, unsigned long size)
{
    int fd;
    ssize_t written;

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
    {
        return 0;
    }

    written = write(fd, buffer, size);
    close(fd);

    return (written == (ssize_t)size);
}

#else
#error "efb_platform_write: unsupported operating system. please provide your own write binary file implementation"
#endif

#endif /* EFB_PLATFORM_WRITE_H */
