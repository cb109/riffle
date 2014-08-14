# :coding: utf-8
# :copyright: Copyright (c) 2014 Martin Pengelly-Phillips
# :license: See LICENSE.txt.

'''Windows data types and API wrapper functions taken from jaraco.windows
by Jason R. Coombs (https://pypi.python.org/pypi/jaraco.windows).

'''

import ctypes


NULL = 0
OPEN_EXISTING = 3
VOLUME_NAME_DOS = 0
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_SHARE_DELETE = 4
FILE_FLAG_BACKUP_SEMANTICS = 0x2000000
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
BOOLEAN = ctypes.c_byte
HANDLE = ctypes.c_void_p
DWORD = ctypes.c_ulong
LPVOID = ctypes.c_void_p
LPWSTR = ctypes.c_wchar_p
INVALID_HANDLE_VALUE = HANDLE(-1).value


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ('length', DWORD),
        ('p_security_descriptor', LPVOID),
        ('inherit_handle', BOOLEAN)
    )

LPSECURITY_ATTRIBUTES = ctypes.POINTER(SECURITY_ATTRIBUTES)


GetFileAttributes = ctypes.windll.kernel32.GetFileAttributesW
CreateFile = ctypes.windll.kernel32.CreateFileW
CreateFile.argtypes = (
    LPWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE
)
GetFinalPathNameByHandle = ctypes.windll.kernel32.GetFinalPathNameByHandleW
GetFinalPathNameByHandle.restype = DWORD
GetFinalPathNameByHandle.argtypes = (
    HANDLE, LPWSTR, DWORD, DWORD,
)
CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = (ctypes.wintypes.HANDLE,)
CloseHandle.restype = ctypes.wintypes.BOOLEAN


def isReparsePoint(path):
    '''Determine if the *path* is a NTFS reparse point.

    Return False if the file does not exist or the file attributes cannot
    be determined.

    '''
    res = GetFileAttributes(path)
    return (
        res != INVALID_FILE_ATTRIBUTES
        and bool(res & FILE_ATTRIBUTE_REPARSE_POINT)
    )


def getFinalPath(path):
    '''Determine the ultimate location of *path*.
    Useful for resolving symlink targets.
    This functions wraps the GetFinalPathNameByHandle from the Windows
    SDK.

    Note, this function fails if a handle cannot be obtained (such as
    for C:\Pagefile.sys on a stock windows system). Consider using
    trace_symlink_target instead.

    '''
    try:
        desiredAccess = NULL
        shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        securityAttributes = LPSECURITY_ATTRIBUTES()  # NULL pointer
        hFile = CreateFile(
            path, desiredAccess, shareMode, securityAttributes,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL
        )

        if hFile == INVALID_HANDLE_VALUE:
            raise WindowsError()

        buf_size = GetFinalPathNameByHandle(
            hFile, LPWSTR(), 0, VOLUME_NAME_DOS
        )
        buf = ctypes.create_unicode_buffer(buf_size)
        result_length = GetFinalPathNameByHandle(
            hFile, buf, len(buf), VOLUME_NAME_DOS
        )
        finalPath = buf[:result_length]
    except:
        raise
    finally:
        CloseHandle(hFile)

    return finalPath
