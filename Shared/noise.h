#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

// literally junk functions to make the code larger and harder to anaylze
static __declspec(noinline) int junk_func_1(int num1, float num2, HWND wnd);
static __declspec(noinline) double junk_func_2(float num);
static __declspec(noinline) int junk_func_3(int a, int b, int* c);
static __declspec(noinline) int junk_func_4();

// global junk variables that are never really used
static int junk_var_1;
static int junk_var_2;
static int junk_var_3;
static TCHAR junk_var_4[256];
static double junk_var_5 = junk_func_4();

extern "C"
{ // termination routines (implemented in destruction_code.asm)
	void rsp_corrupt_destruction();
	void jmp_rsp_destruction();
	void small_junk();
}

static void __forceinline junk_1()
{
	std::wstring a = std::wstring();
	a.append(junk_var_4);
	if (a.find_first_of('a') != -1)
	{
		int b = junk_func_4();
		junk_var_5 = junk_func_2((float)(b * a[0]));
	}
	int b = 0;
	for (unsigned int i = 0; i < a.size(); i++)
	{
		b += a[i];
	}
	BOOL divide = a.size() != 0;
	junk_func_3(divide ? b / a.size() : b, 0, &b);
}

static void __forceinline suspicious_junk_1()
{
	DWORD oldProtect;
	int yo = 19;
	float arr[0x10];
	ZeroMemory(arr, 0x10);
	for (int i = 0x09; i > 0x5; i--)
		arr[i] = (float)atan2(1.0, 1) + arr[2];
	if (arr[0] == 0) yo = PAGE_READWRITE;
	else
		yo = PAGE_EXECUTE | PAGE_READWRITE;
	VirtualProtect(GetModuleHandle(NULL), 4096, PAGE_READWRITE, &oldProtect);
	HWND wnd = FindWindow(TEXT("myClass"), TEXT("MainWindow"));
	if (wnd != NULL) junk_func_1(0, arr[5], wnd);

}

static void __forceinline suspicious_junk_2()
{
	std::wstring str = L"_CRT";
	DWORD a[5];
	for (int i = 0; i < 5; i++)
	{
		if (i % 2 == 0) a[0] = i;
	}
	BOOL success = HeapSetInformation((HANDLE)0x072389C, HEAP_INFORMATION_CLASS::HeapCompatibilityInformation, a, 20);
	TCHAR buffer[256];
	if (junk_var_3 == NULL) a[4] = 0x1000;
	GetComputerName(buffer, a);
	if (GetLastError() != 0 || !success)
	{
		junk_var_3 = (int)OpenThread(NULL, true, 1);
	}
	std::wstring str2 = buffer;
	if (str2.find(str, 0) != std::wstring::npos && str2.find(L"PC", 0) == std::wstring::npos && str[2] == 'T')
	{
		GetEnvironmentVariable(L"PATH", junk_var_4, 256);
	}
}

static void __forceinline suspicious_junk_3()
{
	char str[] = "$$";
	int a[20];
	ZeroMemory(a, 15 * 4);
	BOOL again = true;
	for (int i = 0; i < 10; i++)
	{
		str[0]++;
		while (str[i % 2] != '$')
		{
			str[i % 2]--;
		}

		BOOL success = GetThreadContext(NULL, (LPCONTEXT)0x7C8910 + a[i]);
		if (!success)
		{
			PROCESS_INFORMATION_CLASS l; l = (PROCESS_INFORMATION_CLASS)0;
			if (junk_func_4() == 0) return;
			a[0] /= 2;
			if (IsWow64Process(NULL, &a[19])) junk_var_1 = 1;
			else junk_var_2 = 2;
		}
	}
}

static __declspec(noinline) int junk_func_1(int num1, float num2, HWND wnd)
{
	RECT rect;
	if (cos(num2) == 36.6)
	{
		if (wnd == NULL) return 0;
		return GetWindowLong(wnd, cos((double)num1));
	}
	else
	{
		if (wnd == NULL) return 0;
		GetWindowRect(wnd, &rect);
		return cos(num2) / rect.left;
	}

	return 1;
}

static __declspec(noinline) double junk_func_2(float num)
{
	if (num == 0) return 0;
	int num1 = sin(num);
	float num2 = num1 + 0.2;
	return atan2((double)num2 * 0.5, num1);
}

static __declspec(noinline) int junk_func_3(int a, int b, int* c)
{
	UINT8 ma[5];
	if (a < 100)
	{
		while (ma[0] < 50)
		{
			for (int i = 0; i < 5; i++) ma[i] += 5;
			small_junk();
		}
		return a * b + ma[0];
	}
	if (a > b && *c != NULL)
	{
		return a * b;
	}
	return 0;
}

static __declspec(noinline) int junk_func_4()
{
	HINSTANCE hInstance = NULL;
	if (junk_func_3(0, (DWORD)hInstance, &junk_var_1) == 1) return 0;
	for (int i = 0; i < 0x100; i++)
	{
		if (junk_var_4[i] % 6 + (5 | junk_var_2) == 0) break;
		junk_var_5++;
	}
	return 1;
}