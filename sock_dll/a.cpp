#pragma comment(linker, "/BASE:0x70000000 /FIXED") // 주소고정
#include <stdio.h>
#include <windows.h>
#include <urlmon.h>
#include "list.h"
#include<tchar.h>
#include <iostream>
#include <Winsock.h>
#include <string.h>

#pragma comment (lib,"ws2_32.lib")
#pragma comment(lib,"urlmon.lib")
using namespace std;
static DWORD addr_send = 0;
static DWORD WSAaddr_send = 0;
static DWORD addr_recv = 0;
static DWORD BackINT;
static unsigned char* buf;
static DWORD setretn;
static DWORD setretn2;

typedef struct __WSABUF {
	u_long      len;
	unsigned char FAR  *buf;
} WSABUF, FAR * LPWSABUF;

LPWSABUF b1;

unsigned char *replaceAll(unsigned char *s, const char *olds, const char *news, int len) {
	unsigned char *result, *sr;
	size_t i, count = 0;
	size_t oldlen = strlen(olds); if (oldlen < 1) return s;
	size_t newlen = strlen(news);
	if (newlen != oldlen) {
		for (i = 0; s[i] != '\0';) {
			if (memcmp(&s[i], olds, oldlen) == 0) count++, i += oldlen;
			else i++;
		}
	}
	else i = len;
	result = (unsigned char *)malloc(i + 1 + count * (newlen - oldlen));
	if (result == NULL) return NULL;
	sr = result;
	while (*s) {
		if (memcmp(s, olds, oldlen) == 0) {
			memcpy(sr, news, newlen);
			sr += newlen;
			s += oldlen;
		}
		else *sr++ = *s++;
	}
	*sr = '\0';

	return result;
}

void mas() {
	HANDLE han = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwBytesWriten;
	printf("받은 패킷 : ");
	//buf[0] = 0x01;
	for (int i = 0; i < BackINT; i++) {
		printf("%x ", buf[i]);
	}
	printf("\n");
}

void mas2() {
	HANDLE han = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwBytesWriten;
	printf("받은 패킷 : ");
	for (int i = 0; i < b1->len; i++) {
		printf("%x ", b1->buf[i]);
	}
	printf("\n");
	// strtok로 NetFunnel_ID=; 삭제
	b1->buf = replaceAll(b1->buf, "NetFunnel_ID", "N0tF999el_9D", b1->len);
}

void __declspec(naked) __stdcall HookSend() {
	__asm {
		mov edi, edi
		push ebp
		mov ebp, esp
		// jmp문 기존 5바이트 복구
		mov eax, [ebp + 0x10] //len
		mov BackINT, eax
		mov eax, [ebp + 0xc] // buf
		mov [buf], eax
		push eax
		//call ds : OutputDebugString
		call mas
		mov eax, [buf]              // buf값 수정한 뒤 ebx로
		mov [ebp + 0xc], eax           // buf값 수정한값으로 교체
		jmp setretn // jmp 다음 주소로 , ws2_32.send + 5
	}
}

void __declspec(naked) __stdcall HookSend2() {
	__asm {
		mov edi, edi
		push ebp
		mov ebp, esp
		// jmp문 기존 5바이트 복구
		//mov eax, [ebp + 0x14] //len
		//mov BackINT, eax
		mov eax, [ebp + 0xc] // buf
		mov b1, eax
		push eax
		//call ds : OutputDebugString
		call mas2
		mov eax, b1              // buf값 수정한 뒤 ebx로
		mov [ebp + 0xc], eax           // buf값 수정한값으로 교체
		jmp setretn2 // jmp 다음 주소로 , ws2_32.send + 5
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
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	WSAaddr_send = (DWORD)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")), "WSASend");
	DWORD NewFuncAddr2 = (DWORD)HookSend2;
	BYTE jmp2[5] = { 0xE9,0x00,0x00,0x00,0x00 };
	DWORD jmpAddr2 = (NewFuncAddr2 - WSAaddr_send) - 5;
	memcpy(&jmp2[1], &jmpAddr2, 4);
	setretn2 = WSAaddr_send + 5;
	VirtualProtect((LPVOID)WSAaddr_send, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)WSAaddr_send, jmp2, 5, 0);
	VirtualProtect((LPVOID)WSAaddr_send, 5, dwProtect, &dwProtect);

	AllocConsole();
	SetConsoleTitle(TEXT("Linears Packet Sniffer"));
	freopen("CONOUT$", "w", stdout);

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SMALL_RECT rect = { 0, 0, 200, 500 };
	COORD consoleSize = { (short)100, (short)500 };
	SetConsoleWindowInfo(hConsole, TRUE, &rect);
	SetConsoleScreenBufferSize(hConsole, consoleSize);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	std::cout << "L i n e a r s P a c k e t S n i i f f e r:\n";
	std::cout << "//////////////////////////////////////////\n";
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