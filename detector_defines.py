# coding: utf-8

from ctypes import *

BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
QWORD     = c_uint64
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong

INFINITE                   = 0xFFFFFFFF
DBG_CONTINUE               = 0x00010002
DBG_EXCEPTION_NOT_HANDLED  = 0x80010001
PROCESS_ALL_ACCESS         = 0x001F0FFF
THREAD_ALL_ACCESS          = 0x001F03FF
CONTEXT_FULL               = 0x00010007
CONTEXT_DEBUG_REGISTERS    = 0x00010010
EXCEPTION_DEBUG_EVENT      = 0x00000001
EXCEPTION_ACCESS_VIOLATION = 0xC0000005


class EXCEPTION_RECORD(Structure):
    pass
    
EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
]

class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("FirstChance",      DWORD),
    ]

class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
    ]   

class DEBUG_EVENT(Structure):
    _fields_ = [
        ("DebugEventCode", DWORD),
        ("ProcessId",      DWORD),
        ("ThreadId",       DWORD),
        ("u",              DEBUG_EVENT_UNION),
    ]

class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]

class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]

    def dum_regs(self):
        print("[*]Registers Dump")
        print("EIP: 0x%08x" % self.Eip)
        print("ESP: 0x%08x" % self.Esp)
        print("EBP: 0x%08x" % self.Ebp)
        print("EAX: 0x%08x" % self.Eax)
        print("EBX: 0x%08x" % self.Ebx)
        print("ECX: 0x%08x" % self.Ecx)
        print("EDX: 0x%08x\n" % self.Edx)