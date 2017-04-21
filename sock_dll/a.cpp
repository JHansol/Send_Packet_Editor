#pragma comment(linker, "/BASE:0x70000000 /FIXED") // 주소고정
#include <stdio.h>
#include <windows.h>
#include <urlmon.h>
#include "list.h"
#include<tchar.h>

#pragma comment (lib,"ws2_32.lib")
#pragma comment(lib,"urlmon.lib")

static DWORD addr_send = 0;
static DWORD addr_recv = 0;
static DWORD BackINT;
static DWORD* buf;
static DWORD setretn;
void __declspec(naked) __stdcall HookSend() {
	__asm {
		mov edi, edi
		push ebp
		mov ebp, esp
		// jmp문 기존 5바이트 복구
		mov eax, [ebp + 0x10] //len
		mov BackINT, eax
		mov eax, [ebp + 0xc] // buf
		mov buf, eax
		push eax
		//call ds : OutputDebugString
		//call mas
		jmp setretn // jmp 다음 주소로 , ws2_32.send + 5
	}
}


void Run()
{
	addr_send = (DWORD)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")), "send");
	addr_recv = (DWORD)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")), "recv");

	//TODO: Clean this area up and move these to some inline function

	//LPVOID NewFunc = newrecvs;
	DWORD NewFuncAddr = (DWORD)HookSend;

	BYTE jmp[5] = { 0xE9,0x00,0x00,0x00,0x00 };
	DWORD jmpAddr = (NewFuncAddr - addr_send) - 5;
	memcpy(&jmp[1], &jmpAddr, 4);
	setretn = addr_send + 5;

	DWORD dwProtect;
	VirtualProtect((LPVOID)addr_send, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)addr_send, jmp, 5, 0);
	VirtualProtect((LPVOID)addr_send, 5, dwProtect, &dwProtect);
}

BOOL APIENTRY DllMain(HINSTANCE module, DWORD dwReason, LPVOID lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH) {
		MessageBox(NULL, TEXT("DLL 인젝션 주입 "), TEXT("Linears"), MB_OK);
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Run, NULL, 0, 0); //스레드 생성
		return TRUE;
	}
	return TRUE;
}