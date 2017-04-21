#pragma comment(linker, "/BASE:0x70000000 /FIXED") // 주소고정
#include <stdio.h>
#include <windows.h>
#include <urlmon.h>
#include "list.h"
#include<tchar.h>
#pragma comment (lib,"ws2_32.lib")
#pragma comment(lib,"urlmon.lib")
DWORD buf;
DWORD setretn;

struct patch_t
{
	BYTE nPatchType; //OP code, 0xE9 for JMP
	DWORD dwAddress;
};

int WINAPI newrecvs(SOCKET s, char* buf, int len, int flags)
{
	FILE *buffile;
	buffile = fopen("logs.txt", "w");
	fprintf(buffile, "%s", buf);
	fclose(buffile);
	//MessageBox(NULL, TEXT("DLL 인젝션 주입 "), TEXT("Linears"), MB_OK);
	//return send(s, buf, len, flags);
	return 0;
}

BOOL apply_patch(BYTE eType, DWORD dwAddress, const void *pTarget, DWORD *orig_size, BYTE *replaced)
{
	DWORD dwOldValue, dwTemp;
	struct patch_t pWrite =
	{
		eType,
		(DWORD)pTarget - (dwAddress + sizeof(DWORD) + sizeof(BYTE))
	};
	VirtualProtect((LPVOID)dwAddress, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldValue);
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, (LPVOID)replaced, sizeof(pWrite), (PDWORD)orig_size); //Keep track of the bytes we replaced
	BOOL bSuccess = WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, &pWrite, sizeof(pWrite), NULL);
	VirtualProtect((LPVOID)dwAddress, sizeof(DWORD), dwOldValue, &dwTemp);

	return bSuccess;
}


inline void exec_copy(DWORD addr, BYTE *replaced, DWORD orig_size)
{
	DWORD old_val, temp;
	VirtualProtect((LPVOID)addr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &old_val);
	memcpy((void*)addr, replaced, orig_size);
	VirtualProtect((LPVOID)addr, sizeof(DWORD), old_val, &temp);
}


#define MAX_PACKET 4096

////typedef int (WINAPI *tWS)(SOCKET, const char*, int, int); //For base functions

static DWORD WINAPI initialize(LPVOID param);
static void revert();

static int WINAPI repl_recv(SOCKET s, const char *buf, int len, int flags);
static int WINAPI repl_send(SOCKET s, const char *buf, int len, int flags);

//Trampolenes
static int (WINAPI *pRecv)(SOCKET s, const char* buf, int len, int flags) = NULL;
static int (WINAPI *pSend)(SOCKET s, const char* buf, int len, int flags) = NULL;

//Keep track to undo change before closing
static BYTE replaced_send[10];
static BYTE replaced_recv[10];
static DWORD orig_size_send = 0;
static DWORD orig_size_recv = 0;
static DWORD addr_send = 0;
static DWORD addr_recv = 0;

typedef void (WINAPI *tWS_plugin)(SOCKET*, const char*, int*, int*); //For plugin hooks, passes a pointer to all the relevant data EXCEPT buf because that's already a pointer; Pointers can be rather scary.

typedef enum
{
	WS_HANDLER_SEND = 0x1,
	WS_HANDLER_RECV = 0x2
} WS_HANDLER_TYPE;

//I swear the linux linked list implementation is demon magic
struct WS_handler
{
	tWS_plugin func;
	char *comment;
	struct list_head ws_handlers_send; //Contains ordered list of function handlers for send
	struct list_head ws_handlers_recv; //Contains ordered list of function handlers for recv

};

struct WS_plugins
{
	HMODULE plugin;
	struct list_head plugins;
};


struct WS_plugins ws_plugins; //Why is the list of DLLs exposed? So someone can implement a plugin to reload them, of course!
struct WS_handler ws_handlers;

static int WINAPI repl_send(SOCKET s, const char *buf, int len, int flags)
{
	list_for_each(t, &ws_handlers.ws_handlers_send)
		list_entry(t, struct WS_handler, ws_handlers_send)->func(&s, buf, &len, &flags);
	return send(s, buf, len, flags);
}

static int WINAPI repl_recv(SOCKET s, const char *buf, int len, int flags)
{
	list_for_each(t, &ws_handlers.ws_handlers_recv)
		list_entry(t, struct WS_handler, ws_handlers_recv)->func(&s, buf, &len, &flags);
	return pRecv(s, buf, len, flags);
}
int BackINT;
void __declspec(naked) __stdcall HookSend() {
	__asm {
		mov edi, edi
		push ebp
		mov ebp, esp
		// jmp문 기존 5바이트 복구
		mov eax, [ebp + 0x10] //len
		mov BackINT, eax
		mov eax, [ebp + 0xc] // buf
		push eax
		call ds : OutputDebugString
		//call mas
		jmp setretn // jmp 다음 주소로 , ws2_32.send + 5
	}
}

void Run()
{
	DWORD addr;
	BYTE replaced[10];
	DWORD orig_size;

	addr_send = (DWORD)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")), "send");
	addr_recv = (DWORD)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")), "send");

	//TODO: Clean this area up and move these to some inline function

	//LPVOID NewFunc = newrecvs;
	DWORD NewFuncAddr = (DWORD)HookSend;

	BYTE jmp[6] = { 0xE9,0x00,0x00,0x00,0x00 };
	DWORD jmpAddr = (NewFuncAddr - addr_recv) - 5;
	memcpy(&jmp[1], &jmpAddr, 4);
	setretn = addr_recv + 5;

	DWORD dwProtect;
	VirtualProtect((LPVOID)addr_recv, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)addr_recv, jmp, 5, 0);
	VirtualProtect((LPVOID)addr_recv, 5, dwProtect, &dwProtect);

	addr = addr_send;
	/*
	if (apply_patch(0xE9, addr, (void*)(&repl_send), &orig_size_send, replaced_send)) //Note we only store this replaced because this is the original winsock function code, which we need to put back upon closing
	{
		pSend = (tWS)VirtualAlloc(NULL, orig_size_send << 2, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy((void*)pSend, replaced_send, orig_size_send);
		apply_patch(0xE9, (DWORD)pSend + orig_size_send, (void*)(addr + orig_size_send), &orig_size, replaced);
	}

	addr = addr_recv;
	if (apply_patch(0xE9, addr, (void*)(&repl_recv), &orig_size_recv, replaced_recv))
	{
		pRecv = (tWS)VirtualAlloc(NULL, orig_size_recv << 2, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy((void*)pRecv, replaced_recv, orig_size_recv);
		apply_patch(0xE9, (DWORD)pRecv + orig_size_recv, (void*)(addr + orig_size_recv), &orig_size, replaced);
	}*/
	//INIT_LIST_HEAD(&ws_handlers.ws_handlers_send);
	//INIT_LIST_HEAD(&ws_handlers.ws_handlers_recv);
	//INIT_LIST_HEAD(&ws_plugins.plugins);





	HMODULE hMod = GetModuleHandle(TEXT("WS2_32.dll"));
	DWORD ac = (DWORD)GetProcAddress(hMod, "send");
	DWORD setretn = ac + 5;
	DWORD Potin;

	VirtualProtect((LPVOID)ac, 5, PAGE_READWRITE, &Potin);
	/*
	*((LPBYTE)ac + 0) = 0xE9;
	*((LPBYTE)ac + 1) = 0x2A;
	*((LPBYTE)ac + 2) = 0xA1;
	*((LPBYTE)ac + 3) = 0x48;
	*((LPBYTE)ac + 4) = 0xBD;
	*/

	
	DWORD dwAddress;
	hMod = GetModuleHandle(TEXT("WS2_32.dll"));
	ac = (DWORD)GetProcAddress(hMod, "send"); // ac =send함수 주소값
	setretn = ac + 5;  // 리턴주소 = send함수후킹한주소+5
	DWORD* MemBack = new DWORD[8];
	VirtualProtect((LPVOID)ac,5,PAGE_READWRITE,&Potin); // ws2.32.send 부분 5바이트 읽고쓰기권한 부여
	memcpy(MemBack, (void*)ac, 5); // 변경하기전에 오른쪽변수를 왼쪽변수에 백업해두기

	dwAddress = 0x33301040 - (DWORD)ac -5; // hooksend주소값 따오기
	setretn = 0x33301040 - (DWORD)ac - 5;
	// *((LPBYTE)ac + 0) = 0xE9; // jmp로 변경
	//WriteProcessMemory(GetCurrentProcess(), (void*)(ac+0x01), (void*)&dwAddress, 4, NULL);// jmp xx xx xx xx , xx adress wirte
	//WriteProcessMemory(GetCurrentProcess(), (void*)ac, (void*)&MemBack, 5, NULL);// WPM으로 복구
	//memcpy((void*)ac, MemBack, 5); // memcpy로 복구

	VirtualProtect((LPVOID)ac, 5, Potin, &Potin); // 메모리 속성 복원
	
}

BOOL APIENTRY DllMain(HINSTANCE module, DWORD dwReason, LPVOID lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH) {
		MessageBox(NULL, TEXT( "DLL 인젝션 주입 "), TEXT("Linears"), MB_OK);
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Run, NULL, 0, 0); //스레드 생성
		return TRUE;
	}
	return TRUE;
}