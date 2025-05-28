#include <Windows.h>
#include <stdio.h>
#include <string.h>

#define STOP_ARG "xakep"

BOOL CreateProcessWithBlockDllPolicy(LPSTR lpProcessPath, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    STARTUPINFOEXA SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    SIZE_T sAttrSize = 0;

    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    InitializeProcThreadAttributeList(NULL, 1, 0, &sAttrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);
    if (!pAttrList) {
        printf("[!] HeapAlloc failed\n");
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &sAttrSize)) {
        printf("[!] InitializeProcThreadAttributeList Failed With Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(dwPolicy), NULL, NULL)) {
        printf("[!] UpdateProcThreadAttribute Failed With Error: %d\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    SiEx.lpAttributeList = pAttrList;

    BOOL bRet = CreateProcessA(
        NULL,
        lpProcessPath,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &SiEx.StartupInfo,
        &Pi);

    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);

    if (!bRet) {
        printf("[!] CreateProcessA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return TRUE;
}

BOOL ApplyMitigationPolicyToCurrentProcess() {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { 0 };
    policy.MicrosoftSignedOnly = 1;  

    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy))) {
        printf("[!] SetProcessMitigationPolicy failed with error: %d\n", GetLastError());
        return FALSE;
    }

    DWORD pid = GetCurrentProcessId();
    printf("[+] SetProcessMitigationPolicy applied successfully to current process. PID = %u\n", pid);
    return TRUE;
}


int main(int argc, char* argv[]) {
    if (argc == 2 && strcmp(argv[1], STOP_ARG) == 0) {
        printf("[+] Process is now protected with the Block DLL Policy\n");
        int i = 0;
        while (true) {
            printf("Protected process running - iteration %d\n", i++);
            Sleep(1000);
        }
        return 0;
    }

    printf("Choose mode of operation:\n");
    printf("1 - Apply SetProcessMitigationPolicy to current process\n");
    printf("2 - Launch protected child process with blocked DLL via CreateProcess\n");
    printf("3 - Launch NOT protected child process without blocked DLL via CreateProcess\n");
    printf("Enter 1 or 2 or 3 and press Enter: \n");

    int choice = 0;
    if (scanf_s("%d", &choice) != 1) {
        printf("Input error\n");
        return -1;
    }

    if (choice == 1) {
        if (!ApplyMitigationPolicyToCurrentProcess()) {
            return -1;
        }
        printf("[+] Running current process with SetProcessMitigationPolicy protection\n");
        int i = 0;
        while (true) {
            printf("Protected current process iteration %d\n", i++);
            Sleep(1000);
        }
    }
    else if (choice == 2) {
        CHAR pcFilename[MAX_PATH];
        if (!GetModuleFileNameA(NULL, pcFilename, MAX_PATH)) {
            printf("[!] GetModuleFileNameA failed with error: %d\n", GetLastError());
            return -1;
        }

        size_t len = strlen(pcFilename) + strlen(STOP_ARG) + 2;
        CHAR* pcCmdLine = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
        if (!pcCmdLine) {
            printf("[!] HeapAlloc failed\n");
            return -1;
        }

        sprintf_s(pcCmdLine, len, "%s %s", pcFilename, STOP_ARG);

        DWORD dwProcessId = 0;
        HANDLE hProcess = NULL, hThread = NULL;
        if (!CreateProcessWithBlockDllPolicy(pcCmdLine, &dwProcessId, &hProcess, &hThread)) {
            HeapFree(GetProcessHeap(), 0, pcCmdLine);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, pcCmdLine);

        printf("[i] Protected process created with PID %d\n", dwProcessId);
        printf("[i] Original process will now exit.\n");
        return 0;  
    }

    else if (choice == 3) {

        DWORD pid = GetCurrentProcessId();
        printf("PID = %u\n", pid);
        printf("[-] Process is not protected with the Block DLL Policy\n");
        int i = 0;
        while (true) {
            printf("Not protected current process iteration %d\n", i++);
            Sleep(1000);
        }
    }

    else {
        printf("Invalid choice\n");
        return -1;
    }

    return 0;
}
