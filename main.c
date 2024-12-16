/* main.c */

#include <windows.h>
#include <winuser.h>
#include <winternl.h>
#include <shlwapi.h>
#include <psapi.h>

#include <stdio.h>

typedef NTSTATUS(NTAPI *ntget_next_process_t)(_In_ HANDLE process_handle,
                                              _In_ ACCESS_MASK desired_access,
                                              _In_ ULONG handle_attributes,
                                              _In_ ULONG flags,
                                              _Out_ PHANDLE new_process_handle);

static ntget_next_process_t ntget_next_process;

int main(int argc, char *argv[])
{
    HMODULE kernel32_module;
    HANDLE current = NULL;
    HANDLE proc_handle;
    LPVOID remote_buf;
    char proc_name[MAX_PATH];
    DWORD pid = -1;
    char err_buf[512];

    if (argc < 3) {
        printf("usage: injector.exe <target process name> <dll>\n");
        return -1;
    }

    kernel32_module = GetModuleHandle("ntdll.dll");
    ntget_next_process = (ntget_next_process_t)GetProcAddress(
        kernel32_module,
        "NtGetNextProcess");

    while (!ntget_next_process(current, MAXIMUM_ALLOWED, 0, 0, &current)) {
        GetProcessImageFileNameA(current, proc_name, MAX_PATH);
        if (lstrcmpiA(argv[1], PathFindFileNameA((LPCSTR)proc_name)) == 0) {
            pid = GetProcessId(current);
            break;
        }
    }

    if (pid == -1) {
        printf("[-] find process %s failure: %ld\n", argv[1], GetLastError());
        return -1;
    }
    printf("[+] find process %s success, pid is %ld\n", argv[1], pid);

    proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc_handle) {
        printf("[-] open process %s failure: %ld\n", argv[1], GetLastError());
        return -1;
    }
    printf("[+] open process %s success, handle %p\n", argv[1], proc_handle);

    remote_buf = VirtualAllocEx(proc_handle,
                                NULL,
                                strlen(argv[2]) + 1,
                                (MEM_RESERVE | MEM_COMMIT),
                                PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        printf("[-] virtual alloc failure: %ld\n", GetLastError());
        goto error;
    }
    printf("[+] alloc remote buffer in process %s success\n", argv[1]);

    if (!WriteProcessMemory(proc_handle,
                            remote_buf,
                            argv[2],
                            strlen(argv[2]) + 1,
                            NULL)) {
        printf("[-] write process memory failure: %ld\n", GetLastError());
        goto error_free_remote_buf;
    }
    printf("[+] write data to remote buffer %p success\n", remote_buf);

    if (!CreateRemoteThread(proc_handle,
                            NULL,
                            0,
                            (LPTHREAD_START_ROUTINE)GetProcAddress(
                                GetModuleHandle("kernel32.dll"),
                                "LoadLibraryA"),
                            remote_buf,
                            0,
                            NULL)) {
        printf("[-] create remote thread failure: %ld\n", GetLastError());
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       GetLastError(),
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       err_buf,
                       sizeof(err_buf),
                       NULL);
        printf("[-] error message: %s\n", err_buf);
        goto error_free_remote_buf;
    }
    printf("[+] create remote thread in process %s success\n", argv[1]);
    printf("[+] inject %s to %s success\n", argv[2], argv[1]);

    CloseHandle(proc_handle);

    return 0;

error_free_remote_buf:
    VirtualFree(remote_buf, 7, MEM_RELEASE);
error:
    CloseHandle(proc_handle);
    return -1;
}
