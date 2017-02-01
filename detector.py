# coding: utf-8

from ctypes import *
from ctypes.wintypes import *
from detector_defines import *
from capstone import *
import sys

kernel32 = windll.kernel32

class detector():

    def __init__(self):
        self.h_process = None
        self.pid = None
        self.active = False
        self.h_thread = None
        self.context = None
        self.software_breakpoints = {}
        self.exception_address = None

    def open_process(self, pid):    
        return kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

    def attach(self, pid):
        self.h_process = self.open_process(pid)

        if kernel32.DebugActiveProcess(pid):
            self.active = True
            self.pid = int(pid)
            print("[*] Attached process")
        else:
            print("[*] Faild Attach Process")

    def run(self):
        while self.active == True:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            self.h_thread = self.open_thread(debug_event.ThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)
            if debug_event.DebugEventCode == EXCEPTION_DEBUG_EVENT:
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print("[*] Access Violation Detected.")
                    print("[*] Exception Address: 0x%08x\n" % self.exception_address)
                    self.context.dum_regs()
                    buff = self.read_exception_instruction(self.exception_address)
                    self.print_exception_instruction(buff, self.exception_address)
                    stack_mem = self.read_stack_memory(self.context.Esp, self.context.Ebp)
                    self.print_stack_memory(stack_mem)
                    self.active = False
                    

            kernel32.ContinueDebugEvent(
                debug_event.ProcessId,
                debug_event.ThreadId,
                continue_status)
    
    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            return True
        else:
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        
        if h_thread is not 0:
            return h_thread
        else:
            print("[*] Could not open thread")
            return False

    def get_thread_context(self, thread_id=None, h_thread=None):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if h_thread is None:
            h_thread = self.open_thread(thread_id)
        kernel32.SuspendThread(thread_id)

        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.ResumeThread(h_thread)
            return context
        else:
            kernel32.ResumeThread(h_thread)
            return False

    def read_exception_instruction(self, address):
        buff_size = 32
        buff_mem = create_string_buffer(buff_size)
        number_of_bytes_read = c_int32(0)
        kernel32.ReadProcessMemory(self.h_process, address, pointer(buff_mem), sizeof(buff_mem), pointer(number_of_bytes_read))
        return buff_mem.raw

    def print_exception_instruction(self, data, address):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        exception_datas = md.disasm(data, address)
        print("[*] Exception Instruction")
        for i in md.disasm(data, address):
            print("0x%08x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))
            break

    def read_stack_memory(self, esp, ebp):
        stack_size = ebp - esp
        stack_mem = create_string_buffer(stack_size)
        number_of_bytes_read = c_int32(0)
        kernel32.ReadProcessMemory(self.h_process, esp, pointer(stack_mem), sizeof(stack_mem), pointer(number_of_bytes_read))
        return stack_mem.raw
    
    def print_stack_memory(self, data):
        esp = self.context.Esp
        ebp = self.context.Ebp
        print("[*] Stack")
        i = 0
        for raw_byte in data:
            if i%8 == 0:
                print("")
                sys.stdout.write("0x%08x: " % esp)
                esp += 0x8
            sys.stdout.write("0x%02x  " % ord(raw_byte))
            i += 1
            