#ifndef ANTI_DEBUG_TOOL

#define ANTI_DEBUG_TOOL 1

#define BSOD_TITAN_HIDE 1 
#define BSOD_HYPER_HIDE 1 
#include "lazy_importer.h"
#include "NtApiDef.h"  
#include <iostream>


//Read this https://www.unknowncheats.me/forum/anti-cheat-bypass/314342-read-unknown-kernel-address-safe.html
#ifdef BSOD_TITAN_HIDE
#define BSOD_DO_TITAN_HIDE(handle) \
        for (auto i = 0xFFFFF80000000000; i < 0xFFFFFFFF00000000; i += 0x1000)  \
            LI_FN(NtQueryInformationProcess).nt_cached()(handle, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(i), lenght, NULL);
#else
#define BSOD_DO_TITAN_HIDE(handle) 
#endif // BSOD_TITAN_HIDE
 
/*
Русские не сдаются!!!
 https://github.com/x64dbg/ScyllaHide/blob/a0e5b8f2b1d90be65022545d25288f389368a94d/HookLibrary/HookHelper.cpp#L380
 return NULL by Access(STATUS_ACCESS_DENIED)
*/
#define BREAK_INFO() \
    HANDLE uniq_process_id = NtCurrentTeb()->ClientId.UniqueProcess; \
    HANDLE uniq_thread_id = NtCurrentTeb()->ClientId.UniqueThread; \
    NtCurrentTeb()->ClientId.UniqueProcess = reinterpret_cast<HANDLE>(1); \
    NtCurrentTeb()->ClientId.UniqueThread = reinterpret_cast<HANDLE>(1);  

#define RESTORE_INFO() \
    NtCurrentTeb()->ClientId.UniqueProcess = uniq_process_id; \
    NtCurrentTeb()->ClientId.UniqueThread = uniq_thread_id; 

namespace bad_code_detector
{
    namespace util
    {
        /*
        https://blog.katastros.com/a?ID=00300-286ebcf9-a156-4f98-b894-07cb9e2c7c6b
        OB_TYPE_INDEX_EVENT_PAIR under debugging ??
        */
        __forceinline auto get_number_handle() -> uint64_t
        {
            PVOID buffer = NULL;
            ULONG ret_lenght = NULL;
            uint64_t handle_number = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

            nt_status =  LI_FN(NtQuerySystemInformation).nt_cached()(SystemHandleInformation, &ret_lenght, ret_lenght, &ret_lenght);
            while (nt_status == STATUS_INFO_LENGTH_MISMATCH) {
                if (buffer != NULL)
                    VirtualFree(buffer, 0, MEM_RELEASE);

                buffer = VirtualAlloc(NULL, ret_lenght, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                nt_status = LI_FN(NtQuerySystemInformation).nt_cached()(SystemHandleInformation, buffer, ret_lenght, &ret_lenght);
            }

            if (!NT_SUCCESS(nt_status))
            {
                if (buffer != NULL)
                    VirtualFree(buffer, 0, MEM_RELEASE);
                return NULL;
            }
            auto handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);
            for (ULONG i = 0; i < handle_info->NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                if (handleInfo.UniqueProcessId == reinterpret_cast<USHORT>(NtCurrentTeb()->ClientId.UniqueProcess))
                    handle_number++;
            }
            VirtualFree(buffer, 0, MEM_RELEASE);
            return handle_number;
        }
        
        __forceinline auto strlen(const char* string) -> INT
        {
            INT cnt = 0;
            if (string)
            {
                for (; *string != 0; ++string) ++cnt;
            }
            return cnt;
        }

        __forceinline auto wtolower(INT c) -> INT
        {
            if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
            if (c >= L'À' && c <= L'ß') return c - L'À' + L'à';
            if (c == L'¨') return L'¸';
            return c;
        }

        __forceinline int stricmp(const CHAR* cs, const CHAR* ct)
        {
            if (cs && ct)
            {
                while (tolower(*cs) == tolower(*ct))
                {
                    if (*cs == 0 && *ct == 0) return 0;
                    if (*cs == 0 || *ct == 0) break;
                    cs++;
                    ct++;
                }
                return tolower(*cs) - tolower(*ct);
            }
            return -1;
        }

        __forceinline auto wstricmp(const WCHAR* cs, const WCHAR* ct) -> INT
        {
            if (cs && ct)
            {
                while (wtolower(*cs) == wtolower(*ct))
                {
                    if (*cs == 0 && *ct == 0) return 0;
                    if (*cs == 0 || *ct == 0) break;
                    cs++;
                    ct++;
                }
                return wtolower(*cs) - wtolower(*ct);
            }
            return -1;
        }

        __declspec(noinline) auto get_windows_number() -> INT
        {

            auto NtMajorVersion = *reinterpret_cast<PBYTE>(0x7FFE026C);
            if (NtMajorVersion == 10)
            {
                auto NtBuildNumber = *reinterpret_cast<PINT>(0x7FFE0260);//NtBuildNumber
                if (NtBuildNumber >= 22000)
                    return WINDOWS_NUMBER_11;
                return WINDOWS_NUMBER_10;
            }
            else if (NtMajorVersion == 5)
                return WINDOWS_NUMBER_XP;//Windows XP
            else if (NtMajorVersion == 6)
            {
                switch (*reinterpret_cast<PBYTE>(0x7FFE0270))  //0x7FFE0270 NtMinorVersion
                {
                case 1:
                    return WINDOWS_NUMBER_7;//windows 7
                case 2:
                    return WINDOWS_NUMBER_8; //window 8
                case 3:
                    return WINDOWS_NUMBER_8_1; //windows 8.1
                default:
                    return WINDOWS_NUMBER_11;//windows 11
                }

            }
            return NULL;
        }
    
        __declspec(noinline) auto get_address_driver(const CHAR* module_name) -> uint64_t 
        {
            PVOID buffer = NULL;
            DWORD ret_lenght = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            uint64_t base_address = NULL;
            PRTL_PROCESS_MODULES module_info;

            nt_status = LI_FN(NtQuerySystemInformation).nt_cached()(SystemModuleInformation, buffer, ret_lenght, &ret_lenght);

            while (nt_status == STATUS_INFO_LENGTH_MISMATCH)
            {
                if (buffer != NULL)
                    VirtualFree(buffer, NULL, MEM_RELEASE);

                buffer = VirtualAlloc(nullptr, ret_lenght, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                nt_status = LI_FN(NtQuerySystemInformation).nt_cached()(SystemModuleInformation, buffer, ret_lenght, &ret_lenght);
            }

            if (!NT_SUCCESS(nt_status))
            {
                if (buffer != NULL)
                    VirtualFree(buffer, NULL, MEM_RELEASE);
                return NULL;
            }

            module_info = static_cast<PRTL_PROCESS_MODULES>(buffer);
            if (!module_info)
                return NULL;

            for (ULONG i = NULL; i < module_info->NumberOfModules; ++i)
            {
                if (stricmp(reinterpret_cast<char*>(module_info->Modules[i].FullPathName) + module_info->Modules[i].OffsetToFileName, module_name) == NULL)
                {
                    base_address = reinterpret_cast<uint64_t>(module_info->Modules[i].ImageBase);
                    VirtualFree(buffer, NULL, MEM_RELEASE);
                    return base_address;
                }
            }
            VirtualFree(buffer, NULL, MEM_RELEASE);
            return NULL;
        }


}

    __declspec(noinline) void mem_function()
    {
        __nop();
    }

    /*
    * https://github.com/mrexodia/TitanHide/issues/44
    *Detect SharpOD,ScyllaHide ,TitanHide
    */
    __declspec(noinline) auto is_bad_hide_context() -> bool
    {
        auto mem_address = reinterpret_cast<uint64_t>(&mem_function);
        CONTEXT ctx = { 0 };
        CONTEXT ctx2 = { 0 };
       
        ctx.Dr0 = mem_address;
        ctx.Dr7 = 1;
        ctx.ContextFlags = 0x10;
        ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        //Crash SharpOD/ScyllaHide
        if (NT_SUCCESS(LI_FN(NtSetContextThread).nt_cached()(NtCurrentThread, reinterpret_cast<PCONTEXT>(1))))
            return TRUE;
        if (NT_SUCCESS(LI_FN(NtGetContextThread).nt_cached()(NtCurrentThread, reinterpret_cast<PCONTEXT>(1))))
            return TRUE;

        if (!NT_SUCCESS(LI_FN(NtSetContextThread).nt_cached()(NtCurrentThread, &ctx)))
            return FALSE;
        if (!NT_SUCCESS(LI_FN(NtGetContextThread).nt_cached()(NtCurrentThread, &ctx2)))
            return FALSE;
        if (ctx2.Dr0 != ctx.Dr0 ||
            ctx2.Dr0 != mem_address ||
            ctx2.Dr1 ||
            ctx2.Dr2 ||
            ctx2.Dr3 ||
            !ctx2.Dr7)
            return TRUE;
         
#ifdef BSOD_HYPER_HIDE
        /*
        https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L874
        No check UM address? 
        */
        uint64_t kernel_address = bad_code_detector::util::get_address_driver("ntoskrnl.exe");

        if (kernel_address == NULL)
            kernel_address = 0xFFFFF80000000000;

        for (size_t i = NULL,sucess_number = NULL; sucess_number == NULL && i < 0x100 * 0x100; kernel_address += 0x1000, i++)
        {
            auto nt_status =  LI_FN(NtGetContextThread).nt_cached()(NtCurrentThread, reinterpret_cast<PCONTEXT>(kernel_address));
            if (STATUS_ACCESS_VIOLATION != nt_status)
                sucess_number++;
        } 
#endif // BSOD_HYPER_HIDE
             

        ctx2.Dr0 = NULL;
        ctx2.Dr7 = NULL;
        ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        LI_FN(NtSetContextThread).nt_cached()(NtCurrentThread, &ctx2);

        return FALSE;
    }

    /*
    Detect   HyperHide and need check windows >= 8.1+
    https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L624
    */
    __declspec(noinline) auto is_system_debug_control_hook() -> bool
    {
        auto nt_status = LI_FN(NtSystemDebugControl).nt_cached()((SYSDBG_COMMAND)0x25, NULL, NULL, NULL, NULL, NULL);

        if (util::get_windows_number() >= WINDOWS_NUMBER_10 && nt_status == STATUS_DEBUGGER_INACTIVE)
            return TRUE;
        return FALSE;
    }

    /*
    Detect TitanHide, SharpOD  and ScyllaHide (+ break ScyllaHide)
    https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ps/psquery.c#L2784=
    can add check by  OpenProcess with PROCESS_TERMINATE
    */
    __declspec(noinline) auto is_debug_flag_hooked() -> bool
    {
        HANDLE bug_handle = NULL;
        uint32_t debug_flag = NULL;
        uint32_t  safe_value = NULL;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
        
        //Crash ScyllaHide 
        nt_status = LI_FN(NtSetInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugFlags, reinterpret_cast<PVOID>(1), sizeof(debug_flag));
        if (NT_SUCCESS(nt_status))
            return TRUE;
        
        bug_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)NtCurrentTeb()->ClientId.UniqueProcess);
        if (bug_handle)
        { 
            nt_status = LI_FN(NtSetInformationProcess).nt_cached()(bug_handle, ProcessDebugFlags, &debug_flag, sizeof(debug_flag));
            LI_FN(NtClose).nt_cached()(bug_handle);
            if (NT_SUCCESS(nt_status))
                return TRUE;
        }

        nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugFlags, &debug_flag, sizeof(debug_flag), NULL);
        safe_value = debug_flag; //Safe value for present some problem 

        if (!NT_SUCCESS(nt_status))
            return FALSE;

        debug_flag = !debug_flag;

        nt_status = LI_FN(NtSetInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugFlags, &debug_flag, sizeof(debug_flag));

        //Can't set value
        if (!NT_SUCCESS(nt_status))
            return FALSE;

        nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugFlags, &debug_flag, sizeof(debug_flag), NULL);

        if (NT_SUCCESS(nt_status) && debug_flag != NULL)
            return TRUE;

        LI_FN(NtSetInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugFlags, &safe_value, sizeof(safe_value));
        return FALSE;
    }

    /*
    Detect SharpOD,ScyllaHide,TitanHide,HyperHide
    */
    __declspec(noinline) auto is_bad_hide_thread() -> bool
    {
        bool is_thread_hide = NULL;
        INT mem_lenght_check = 0x101;
        ULONG return_lenght = NULL;
        HANDLE hide_thread = NULL;
        HANDLE bug_handle = NULL; 
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

        //Hide thread by bug (only SharpOD/ScyllaHide  via UM)
        bug_handle = OpenThread(THREAD_SET_INFORMATION, NULL, (DWORD)NtCurrentTeb()->ClientId.UniqueThread);
        if (bug_handle)
        {
            BREAK_INFO();
            nt_status = LI_FN(NtSetInformationThread).nt_cached()(bug_handle, ThreadHideFromDebugger, NULL, NULL);
            RESTORE_INFO();
            LI_FN(NtClose).nt_cached()(bug_handle);
        }

        auto thread_handle = CreateThread(NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL);
        if (thread_handle) //Check on lazy NtQueryInformationThread
        {
            nt_status = LI_FN(NtQueryInformationThread).nt_cached()(thread_handle, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
            if ((NT_SUCCESS(nt_status) && (is_thread_hide || return_lenght != 1)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                return TRUE;

            nt_status = LI_FN(NtSetInformationThread).nt_cached()(thread_handle, ThreadHideFromDebugger, NULL, NULL);
            if ((NT_SUCCESS(nt_status)))
            {
                nt_status = LI_FN(NtQueryInformationThread).nt_cached()(thread_handle, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
                LI_FN(NtClose).nt_cached()(bug_handle);
                if ((NT_SUCCESS(nt_status) && (!is_thread_hide || return_lenght != 1)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                    return TRUE;
            }
            LI_FN(NtClose).nt_cached()(thread_handle);
        }
        
        //Bug with Access (only SharpOD/ScyllaHide  via UM)
        bug_handle = OpenThread(THREAD_QUERY_INFORMATION, NULL, (DWORD)NtCurrentTeb()->ClientId.UniqueThread);
        if (bug_handle)
        {
            nt_status = LI_FN(NtSetInformationThread).nt_cached()(bug_handle, ThreadHideFromDebugger, NULL, NULL);
            LI_FN(NtClose).nt_cached()(bug_handle);
            if (nt_status != STATUS_ACCESS_DENIED) //STATUS_ACCESS_DENIED should be by ObReferenceObjectByHandle 
                return TRUE;
        }
        
        nt_status = LI_FN(NtCreateThreadEx).nt_cached()(&hide_thread, THREAD_ALL_ACCESS_VISTA, NULL, NtCurrentProcess, (LPTHREAD_START_ROUTINE)NULL, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, NULL, NULL, NULL, NULL);
        if (NT_SUCCESS(nt_status) && hide_thread) //Check on lazy NtCreateThreadEx  & NtQueryInformationThread
        {
            nt_status = LI_FN(NtQueryInformationThread).nt_cached()(hide_thread, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
            LI_FN(NtClose).nt_cached()(hide_thread);
            //Thread should be don't hided
            if ((NT_SUCCESS(nt_status) && (return_lenght != 1 || is_thread_hide)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                return TRUE;
        }

        nt_status = LI_FN(NtCreateThreadEx).nt_cached()(&hide_thread, THREAD_ALL_ACCESS_VISTA, NULL, NtCurrentProcess, (LPTHREAD_START_ROUTINE)NULL, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_CREATE_SUSPENDED, NULL, NULL, NULL, NULL);
        if (NT_SUCCESS(nt_status) && hide_thread) //Check on lazy NtCreateThreadEx  & NtQueryInformationThread
        {
            nt_status = LI_FN(NtQueryInformationThread).nt_cached()(hide_thread, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
            LI_FN(NtClose).nt_cached()(hide_thread);
            //Thread should be hided 
            if ((NT_SUCCESS(nt_status) && (return_lenght != 1 || !is_thread_hide)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                return TRUE;
        }

        nt_status = LI_FN(NtSetInformationThread).nt_cached()(NtCurrentThread, ThreadHideFromDebugger, &is_thread_hide, reinterpret_cast<ULONG>(L"I_love_colby_<3"));//forever 
        if (NT_SUCCESS(nt_status))
            return TRUE;

        nt_status = LI_FN(NtSetInformationThread).nt_cached()(reinterpret_cast<HANDLE>(0xFFFF), ThreadHideFromDebugger, NULL, NULL);
        if (NT_SUCCESS(nt_status))
            return TRUE;

        //Now hide own thread(we terminate created thread)
        nt_status = LI_FN(NtSetInformationThread).nt_cached()(NtCurrentThread, ThreadHideFromDebugger, NULL, NULL);
        if (NT_SUCCESS(nt_status))
        {
            nt_status = LI_FN(NtQueryInformationThread).nt_cached()(NtCurrentThread, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
            /*
            ScyllaHide and SharpOD don'h hook NtQueryInformationThread(ThreadHideFromDebugger)
            HyperHide return STATUS_DATATYPE_MISALIGNMENT (bug in ProbeForRead ?)
           */
            if ((NT_SUCCESS(nt_status) && (return_lenght != 1 || !is_thread_hide)) || nt_status == STATUS_INFO_LENGTH_MISMATCH || nt_status == STATUS_DATATYPE_MISALIGNMENT)
                return TRUE;

            // try check on write BOOL(not BYTE by system) value and under HyperrHide some-time mem_lenght_check == 0x100 (return FALSE via thread don't hide) 🚬 
            nt_status = LI_FN(NtQueryInformationThread).nt_cached()(NtCurrentThread, ThreadHideFromDebugger, &mem_lenght_check, sizeof(is_thread_hide), &return_lenght);
            if ((NT_SUCCESS(nt_status) && (return_lenght != 1 || mem_lenght_check != 0x101)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                return TRUE;
        }
        return FALSE;
    }

    /*
    Detect TitanHide,SharpOD,ScyllaHide and deattach DebugPort from UM plugin
    VMP detect leak,so don't use this https://github.com/mrexodia/TitanHide/issues/70
    */
    __declspec(noinline) auto is_debug_object_hooked() -> bool
    {

        ULONG return_lenght = NULL;
        uint64_t number_handle = NULL;
        HANDLE debug_object = NULL;
        HANDLE bug_handle = NULL;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

#ifdef _WIN64
        DWORD lenght = sizeof(HANDLE);
#else
        DWORD lenght = sizeof(ULONG);
#endif
        nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, lenght, &return_lenght);
        
        if (nt_status != STATUS_PORT_NOT_SET || debug_object != NULL || return_lenght != lenght)
        {
            LI_FN(NtRemoveProcessDebug).nt_cached()(NtCurrentProcess, debug_object);
            return TRUE;
        }

        //https://forum.tuts4you.com/topic/40011-vmprotect-312-build-886-anti-debug-method-improved/?do=findComment&comment=192827
        nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, lenght, (PULONG)&debug_object);
        if (nt_status != STATUS_PORT_NOT_SET || reinterpret_cast<ULONG>(debug_object) != lenght)
            return TRUE;

        //VMP 3.6.1410
        debug_object = reinterpret_cast<HANDLE>(1);
        nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, lenght, reinterpret_cast<PULONG>(0x1));
        if (debug_object != reinterpret_cast<HANDLE>(1) || NT_SUCCESS(nt_status))
        {
            BSOD_DO_TITAN_HIDE(NtCurrentProcess);
            return TRUE;
        }
        debug_object = NULL;

       //Bug like VMP:https://github.com/mrexodia/TitanHide/blob/fb7085e5956bc04c4e3add3fbaf73b1bcd432728/TitanHide/hooks.cpp#L465
        nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(NULL, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(1), lenght, reinterpret_cast<PULONG>(0x1));
        if (nt_status != STATUS_ACCESS_VIOLATION &&  nt_status != STATUS_DATATYPE_MISALIGNMENT)
        {
            BSOD_DO_TITAN_HIDE(NtCurrentProcess);
            return TRUE;
        }

        number_handle = bad_code_detector::util::get_number_handle();
		
        bug_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)NtCurrentTeb()->ClientId.UniqueProcess);
        if (bug_handle)
        {
            debug_object = reinterpret_cast<HANDLE>(1);

            if (bug_handle) //need for macro(yes,bad code)
            {
                BREAK_INFO();
                nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(bug_handle, ProcessDebugObjectHandle, &debug_object, lenght, reinterpret_cast<PULONG>(0x1));
                RESTORE_INFO();
            }
            if (debug_object != reinterpret_cast<HANDLE>(1) || NT_SUCCESS(nt_status))
            {
                BREAK_INFO();
                BSOD_DO_TITAN_HIDE(bug_handle);
                RESTORE_INFO();
                LI_FN(NtClose).nt_cached()(bug_handle);
                return TRUE;
            } 
            debug_object = NULL;

            BREAK_INFO();
            nt_status = LI_FN(NtQueryInformationProcess).nt_cached()(bug_handle, ProcessDebugObjectHandle, &debug_object, lenght, &return_lenght);
            RESTORE_INFO();
            if (nt_status != STATUS_PORT_NOT_SET || debug_object != NULL || return_lenght != lenght)
            {
                //Remove DebugPort
                LI_FN(NtRemoveProcessDebug).nt_cached()(NtCurrentProcess, debug_object);
                LI_FN(NtClose).nt_cached()(bug_handle); 
                return TRUE;
            }

            for (INT i = NULL; i < 0x100; i++)
            {
                BREAK_INFO();
                LI_FN(NtQueryInformationProcess).nt_cached()(bug_handle, ProcessDebugObjectHandle, &debug_object, lenght, &return_lenght);
                //overwrite handle by system for bypass if anti-anti-debug tool close handle
                LI_FN(NtQueryInformationProcess).nt_cached()(bug_handle, ProcessDebugObjectHandle, &return_lenght, lenght, &return_lenght);
                RESTORE_INFO();
            }
            //if anti-anti-debug tool call original function and don't close handle,than handle was leak 
            if (bad_code_detector::util::get_number_handle() - number_handle > 0x75)
            {
                LI_FN(NtClose).nt_cached()(bug_handle);
                return TRUE;
            }
            LI_FN(NtClose).nt_cached()(bug_handle);
        }
        else
        {
            for (INT i = 0; i < 0x100; i++)
            {
                LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, lenght, &return_lenght);
                //overwrite handle by system for bypass if anti-anti-debug tool close handle
                LI_FN(NtQueryInformationProcess).nt_cached()(NtCurrentProcess, ProcessDebugObjectHandle, &return_lenght, lenght, &return_lenght);

            }
            //if anti-anti-debug tool call original function and don't close handle,than handle was leak 
            if (bad_code_detector::util::get_number_handle() - number_handle > 0x75)
                return TRUE;
        }
        return FALSE;
    }

    /*
    HyperHide bug:https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L594
    ScyllaHide bug:https://github.com/x64dbg/ScyllaHide/blob/2276f1477132e99c96f31552bce7b4d2925fb918/HookLibrary/HookedFunctions.cpp#L1041
    TitanHide bug:https://github.com/mrexodia/TitanHide/blob/77337790dac809bde3ff8d739deda24d67979668/TitanHide/hooks.cpp#L426
    SharpOD -  detect
    https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/NtQueryObject_AllTypesInformation.cpp
    Explanation: we create a debug object, but go through all the objects and
    if their number is less than 1 (we created at least 1), then there is a hook
    */
    __declspec(noinline) auto is_bad_number_object_system() -> bool
    {
        HANDLE debug_object = NULL;
        uint8_t* object_location = NULL;
        uint64_t number_debug_object_system = NULL;
        uint64_t number_debug_handle_system = NULL;
        uint64_t number_debug_object_process = NULL;
        uint64_t number_debug_handle_process = NULL;
        uint64_t tmp = NULL;
        ULONG lenght = NULL;
        PVOID buffer = NULL;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
        OBJECT_ATTRIBUTES object_attrib;
        POBJECT_TYPE_INFORMATION object_process = NULL;
        POBJECT_TYPE_INFORMATION object_type_info = NULL;
        POBJECT_ALL_INFORMATION  object_all_info = NULL;

        InitializeObjectAttributes(&object_attrib, NULL, NULL, NULL, NULL);
        nt_status = LI_FN(NtCreateDebugObject).nt_cached()(&debug_object, DEBUG_ALL_ACCESS, &object_attrib, 0);
        if (NT_SUCCESS(nt_status))
        {
            //TitanHide very bad hook https://github.com/mrexodia/TitanHide/blob/fb7085e5956bc04c4e3add3fbaf73b1bcd432728/TitanHide/hooks.cpp#L397
           
            //Get correct lenght
            nt_status = LI_FN(NtQueryObject).nt_cached()(debug_object, ObjectTypeInformation, &lenght, sizeof(ULONG), &lenght);
           
            buffer = VirtualAlloc(NULL, lenght, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (buffer == NULL)
            {
                LI_FN(NtClose).nt_cached()(debug_object);
                return FALSE;
            }
            nt_status = LI_FN(NtQueryObject).nt_cached()(debug_object, ObjectTypeInformation, buffer, lenght, &lenght);
            object_process = reinterpret_cast<POBJECT_TYPE_INFORMATION>(buffer);
            //SharpOD don't hook ObjectTypeInformation
            if (object_process->TotalNumberOfObjects != 1 && util::wstricmp(L"DebugObject", object_process->TypeName.Buffer) == NULL)
            {
                VirtualFree(buffer, NULL, MEM_RELEASE);
                LI_FN(NtClose).nt_cached()(debug_object);
                return TRUE;
            } 
            number_debug_handle_process = object_process->TotalNumberOfHandles;
            number_debug_object_process = object_process->TotalNumberOfObjects;
            VirtualFree(buffer, NULL, MEM_RELEASE);

            //Get correct lenght
            nt_status = LI_FN(NtQueryObject).nt_cached()(NULL, ObjectTypesInformation, &lenght, sizeof(ULONG), &lenght);

            buffer = VirtualAlloc(NULL, lenght, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (buffer == NULL)
            {
                LI_FN(NtClose).nt_cached()(debug_object);
                return FALSE;
            }
            //https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ob/obquery.c#L406
            nt_status = LI_FN(NtQueryObject).nt_cached()(NtCurrentProcess, ObjectTypesInformation, buffer, lenght, NULL);

            if (!NT_SUCCESS(nt_status))
            {
                LI_FN(NtClose).nt_cached()(debug_object);
                VirtualFree(buffer, NULL, MEM_RELEASE);
                return FALSE;
            }

            object_all_info = reinterpret_cast<POBJECT_ALL_INFORMATION>(buffer);
            object_location = reinterpret_cast<UCHAR*>(object_all_info->ObjectTypeInformation);
            for (ULONG i = NULL; i < object_all_info->NumberOfObjectsTypes; i++)
            {
                object_type_info = reinterpret_cast<POBJECT_TYPE_INFORMATION>(object_location);

                // The debug object will always be present
                if (util::wstricmp(L"DebugObject", object_type_info->TypeName.Buffer) == NULL)
                {
                    if (object_type_info->TotalNumberOfObjects > NULL)
                        number_debug_object_system += object_type_info->TotalNumberOfObjects;
                    if (object_type_info->TotalNumberOfHandles > NULL)
                        number_debug_handle_system += object_type_info->TotalNumberOfHandles;
                }
                  
                object_location = (uint8_t*)object_type_info->TypeName.Buffer;
                object_location += object_type_info->TypeName.MaximumLength;
                tmp = ((uint64_t)object_location) & -(int)sizeof(void*);

                if ((uint64_t)tmp != (uint64_t)object_location)
                    tmp += sizeof(PVOID);
                object_location = ((uint8_t*)tmp);
            }
            VirtualFree(buffer, NULL, MEM_RELEASE);
            LI_FN(NtClose).nt_cached()(debug_object);
            return  number_debug_object_system < 1 ||
                    number_debug_object_system < number_debug_object_process ||
                    number_debug_handle_system < number_debug_handle_process;
        }
        return FALSE;
    }
     
}
#endif // !ANTI_DEBUG_TOOL
