import enum
import ctypes
import argparse
from ctypes import wintypes
from collections import namedtuple


AddressSpace = namedtuple('AddressSpace', ['min_address', 'max_address'])


class MEMORY_STATE(enum.IntEnum):
    MEM_COMMIT      = 0x1000
    MEM_FREE        = 0x10000
    MEM_RESERVE     = 0x2000
    MEM_DECOMMIT    = 0x4000
    MEM_RELEASE     = 0x8000


class MEMORY_TYPES(enum.IntEnum):
    MEM_IMAGE   = 0x1000000
    MEM_MAPPED  = 0x40000
    MEM_PRIVATE = 0x20000


class MEMORY_PROTECTION(enum.IntEnum):
    PAGE_EXECUTE            = 0x10
    PAGE_EXECUTE_READ       = 0x20
    PAGE_EXECUTE_READWRITE  = 0x40
    PAGE_EXECUTE_WRITECOPY  = 0x80
    PAGE_NOACCESS           = 0x01
    PAGE_READONLY           = 0x02
    PAGE_READWRITE          = 0x04
    PAGE_WRITECOPY          = 0x08
    PAGE_GUARD              = 0x100
    PAGE_NOCACHE            = 0x200
    PAGE_WRITECOMBINE       = 0x400


class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', wintypes.DWORD),
        ('AllocationBase', wintypes.DWORD),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', wintypes.DWORD),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
    ]


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_ulonglong),
        ('AllocationBase', ctypes.c_ulonglong),
        ('AllocationProtect', wintypes.DWORD),
        ('__alignment1', wintypes.DWORD),
        ('RegionSize', ctypes.c_ulonglong),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
        ('__alignment2', wintypes.DWORD),
    ]


PTR_SIZE = ctypes.sizeof(ctypes.c_void_p)
if PTR_SIZE == 8:       # 64-bit python
    MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION64
    DWORD_PTR = ctypes.c_ulonglong
elif PTR_SIZE == 4:     # 32-bit python
    MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION32
    DWORD_PTR = ctypes.c_ulong


class SYSTEM_INFO(ctypes.Structure):
    class _U(ctypes.Union):
        class _S(ctypes.Structure):
            _fields_ = (
                ('wProcessorArchitecture', wintypes.WORD),
                ('wReserved', wintypes.WORD)
            )
        _fields_ = (
            ('dwOemId', wintypes.DWORD), # obsolete
            ('_s', _S)
        )
        _anonymous_ = ('_s',)

    _fields_ = (
        ('_u', _U),
        ('dwPageSize', wintypes.DWORD),
        ('lpMinimumApplicationAddress', wintypes.LPVOID),
        ('lpMaximumApplicationAddress', wintypes.LPVOID),
        ('dwActiveProcessorMask', DWORD_PTR),
        ('dwNumberOfProcessors', wintypes.DWORD),
        ('dwProcessorType', wintypes.DWORD),
        ('dwAllocationGranularity', wintypes.DWORD),
        ('wProcessorLevel', wintypes.WORD),
        ('wProcessorRevision', wintypes.WORD)
    )

    _anonymous_ = ('_u',)


LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


wintypes.LUID = LUID
wintypes.PLUID = ctypes.POINTER(wintypes.LUID)


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes",  wintypes.DWORD),
    ]


wintypes.LUID_AND_ATTRIBUTES = LUID_AND_ATTRIBUTES
wintypes.PLUID_AND_ATTRIBUTES = ctypes.POINTER(wintypes.LUID_AND_ATTRIBUTES)


class TOKEN_PRIVILEGES(ctypes.Structure):
     _fields_ = [                                            
		('PrivilegeCount', wintypes.DWORD),		      
        ('Privileges', LUID_AND_ATTRIBUTES * 512) 
	]			                  


PTOKEN_PRIVILEGES = ctypes.POINTER(TOKEN_PRIVILEGES)
wintypes.TOKEN_PRIVILEGES = TOKEN_PRIVILEGES
wintypes.PTOKEN_PRIVILEGES = ctypes.POINTER(wintypes.TOKEN_PRIVILEGES)


# WINAPI Templates for argument/return types

ctypes.windll.kernel32.GetSystemInfo.argtypes = (LPSYSTEM_INFO,)
ctypes.windll.kernel32.GetSystemInfo.restype = None


ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE


ctypes.windll.kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.c_void_p,
    ctypes.c_size_t
]


ctypes.windll.advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE)
]
ctypes.windll.advapi32.OpenProcessToken.restype = wintypes.BOOL


ctypes.windll.advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPWSTR,
    wintypes.LPWSTR,
    ctypes.POINTER(LUID),
]
ctypes.windll.advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL


ctypes.windll.advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,
    wintypes.BOOL,
    wintypes.PTOKEN_PRIVILEGES,
    wintypes.DWORD,
    wintypes.PTOKEN_PRIVILEGES,
    wintypes.LPDWORD
]
ctypes.windll.advapi32.OpenProcessToken.restype = wintypes.BOOL

# END of WINAPI Templates


def output_attributes(mbi: ctypes.Structure, address: int):

    try:
        mem_type = f"{str(MEMORY_TYPES(mbi.Type))} [{hex(mbi.Type)}]"
        mem_protect = f"{str(MEMORY_PROTECTION(mbi.Protect))} [{hex(mbi.Protect)}]"
        mem_allocprotect = f"{str(MEMORY_PROTECTION(mbi.AllocationProtect))} [{hex(mbi.AllocationProtect)}]"
        mem_state = f"{str(MEMORY_STATE(mbi.State))} [{hex(mbi.State)}]"
        print(f"ADDRESS: {hex(address)}\n\t{mem_type}\n\t{mem_protect}\n\t{mem_allocprotect}\n\t{mem_state}")
    except ValueError:
        # Likely caused by inaccessible memory
        print(f"ADDRESS: {hex(address)} - Likely inaccesible")


def get_mem_attributes(hProcess: int, address: int) -> ctypes.Structure:

    mbi = MEMORY_BASIC_INFORMATION()

    result = ctypes.windll.kernel32.VirtualQueryEx(
        hProcess,
        address,
        ctypes.byref(mbi),
        ctypes.sizeof(mbi)
    )

    if result > 0:
        return mbi
    else:
        return None


def get_address_space() -> namedtuple:

    sys_info = SYSTEM_INFO()
    sys_info_ptr = ctypes.byref(sys_info)

    ctypes.windll.kernel32.GetSystemInfo(sys_info_ptr)

    min_address = sys_info.lpMinimumApplicationAddress
    max_address = sys_info.lpMaximumApplicationAddress

    address_space = AddressSpace(
        min_address=min_address,
        max_address=max_address
    )

    return address_space


def get_process_handle(pid: int) -> int:

    hProcess = ctypes.windll.kernel32.OpenProcess(
        0x1F0FFF,   # PROCESS_ALL_ACCESS
        False,
        pid
    )

    return hProcess


def get_process_token() -> wintypes.HANDLE:

    hToken = wintypes.HANDLE()

    result = ctypes.windll.advapi32.OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(),
        0xF01FF,    # TOKEN_ALL_ACCESS
        hToken
    )

    if not result > 0:
        return None

    return hToken

def enable_sedebugprivilge(hToken: ctypes.c_void_p) -> bool:

    luid = LUID()
    
    lookup_privilege_value = ctypes.windll.advapi32.LookupPrivilegeValueW(
        None,
        'SeDebugPrivilege',
        ctypes.byref(luid)
    )

    if not lookup_privilege_value > 0:
        print("[!] Couldn't lookup privilege value")
        return False

    tp = TOKEN_PRIVILEGES()

    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 0x00000002    # SE_PRIVILEGE_ENABLED

    adjust_token_privileges = ctypes.windll.advapi32.AdjustTokenPrivileges(
        hToken,
        False,
        tp,
        0x0,
        None,
        None
    )

    if adjust_token_privileges == 0:
        return False
    else:
        return True


def main():

    parser = argparse.ArgumentParser(
        description='Retrieve memory attributes for given address or all regions of the process ID'
    )

    parser.add_argument(
        '--pid',
        required=True,
        type=int,
        help='Process ID that contains memory region'
    )
    parser.add_argument(
        '--address',
        required=False,
        type=lambda v: int(v, 16),
        help='Hex address of region to retrieve MBI of'
    )
    parser.add_argument(
        '--all',
        required=False,
        action='store_true',
        help='Retrieve MBI of all regions'
    )

    args = parser.parse_args()

    process_token = get_process_token()

    if process_token:
        print("[+] Retrieved token to process")

    else:
        print("[!] Couldn't get process token")

    if enable_sedebugprivilge(hToken=process_token):
        print("[+] Adjusted privileges for current process")

    else:
        print("[!] Error in AdjustTokenPrivileges")
        exit()

    pid = args.pid

    hProcess = get_process_handle(pid=pid)

    if hProcess > 0:
        print(f"[+] Obtained valid handle to PID: {pid}")

    else:
        print(f"[!] Couldn't obtain handle to PID: {pid}")
        exit()

    # Retrieve only the memory attributes for the given address
    if args.address:
        address = args.address

        mbi = get_mem_attributes(hProcess=hProcess, address=address)

        output_attributes(mbi=mbi)

    # Retrieve the memory attributes of all the regions in process memory
    elif args.all:
        address_space = get_address_space()

        page_ptr = address_space.min_address

        while page_ptr < address_space.max_address:

            mbi = get_mem_attributes(hProcess=hProcess, address=page_ptr)

            output_attributes(mbi=mbi, address=page_ptr)

            page_ptr += mbi.RegionSize


if __name__ == "__main__":
    main()
