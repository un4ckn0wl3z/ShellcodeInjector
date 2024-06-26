#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <vector>
#include <assert.h>

std::vector<DWORD> EnumThreads(DWORD pid)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return {};
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	Thread32First(hSnapshot, &te);
	std::vector<DWORD> tids;

	while (Thread32First(hSnapshot, &te))
	{
		if (te.th32OwnerProcessID == pid)
		{
			tids.push_back(te.th32ThreadID);
		}
	}

	CloseHandle(hSnapshot);
	return tids;

}

DWORD GetThreadInProcess(DWORD pid)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	Thread32First(hSnapshot, &te);

	while (Thread32Next(hSnapshot, &te))
	{
		if (te.th32OwnerProcessID == pid)
		{
			return te.th32ThreadID;
		}
	}

	CloseHandle(hSnapshot);
	return 0;

}

int main(int argc, const char* argv[])
{
	if (argc < 3)
	{
		printf("Usage: %s <pid> <dllpath>\n", argv[0]);
		return 0;
	}

	DWORD pid = atoi(argv[1]);
	HANDLE hProcess = OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
		FALSE,
		pid);

	if (!hProcess)
	{
		printf("Error opening process (%u)\n", GetLastError());
		return 1;
	}

	auto tid = GetThreadInProcess(pid);
	if (tid == 0)
	{
		printf("Error getting thread\n");
		return 1;
	}

	HANDLE hThread = OpenThread(
		THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 
		FALSE, 
		tid);

	if (!hThread)
	{
		printf("Error opening thread (%u)\n", GetLastError());
		return 1;
	}

	char* p = (char*)VirtualAllocEx(
		hProcess, 
		nullptr, 
		1 << 12, 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_READWRITE);

	assert(p);

	WriteProcessMemory(
		hProcess, 
		p, 
		argv[2], 
		strlen(argv[2]) + 1, 
		nullptr);

	BYTE shellcode[] = "\x51\x49\xBB\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\x48\xB9\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\x48\x83\xEC\x20\x41\xFF\xD3\x48\x83\xC4\x20\x59\x49\xBB\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x41\xFF\xE3";

	auto pLoadLib = GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA");
	assert(pLoadLib);

	memcpy(shellcode + 3, &pLoadLib, sizeof(pLoadLib));
	memcpy(shellcode + 13, &p, sizeof(p));

	SuspendThread(hThread);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);

	memcpy(shellcode + 0x23, &ctx.Rip, sizeof(ctx.Rip));

	WriteProcessMemory(
		hProcess,
		p + 2048,
		shellcode,
		sizeof(shellcode),
		nullptr);

	ctx.Rip = (DWORD64)p + 2048;

	SetThreadContext(hThread, &ctx);

	DWORD oldProtect;
	
	VirtualProtectEx(
		hProcess,
		p,
		1 << 12,
		PAGE_EXECUTE_READ,
		&oldProtect);


	ResumeThread(hThread);

	CloseHandle(hThread);
	CloseHandle(hProcess);


	return 0;
}