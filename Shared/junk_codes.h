#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include "winapi_function_signatures.h"
#include "winapi_obfuscation.h"

#pragma warning(push, 0) // Disable all warnings

// literally junk functions to make the code larger and harder to anaylze
static __declspec(noinline) INT_PTR not_inlined_junk_func_1(INT_PTR num1, float num2, HWND wnd);
static __declspec(noinline) double not_inlined_junk_func_2(float num);
static __declspec(noinline) int not_inlined_junk_func_3(int a, int b, int* c);
static __declspec(noinline) int not_inlined_junk_func_4();

// global junk variables that are never really used
static int junk_var_1;
static int junk_var_2;
static INT_PTR junk_var_3;
static wchar_t junk_var_4[256];
static double junk_var_5 = not_inlined_junk_func_4(); // will call the function when the header is included

extern "C"
{ // termination routines (implemented in destruction_code.asm)
	void rsp_corrupt_destruction();
	void jmp_rsp_destruction();
	void small_junk();
}

// Combine all the none inline funcs
static void __forceinline junk()
{
    std::wstring a;
    a.append(junk_var_4);
    if (a.find_first_of(L'a') != std::wstring::npos)
    {
        int b = not_inlined_junk_func_4();
        junk_var_5 = not_inlined_junk_func_2((float)(b * a[0]));
    }
    int b = 0;
    for (unsigned int i = 0; i < a.size(); i++)
        b += a[i];

    bool divide = (a.size() != 0);
    not_inlined_junk_func_3(divide ? (b / a.size()) : b, 0, &b);
}

static void __forceinline suspicious_junk_1()
{
    DWORD oldProtect;
    int yo = 19;
    float arr[0x10];
    ZeroMemory(arr, sizeof(arr));

    for (int i = 9; i > 5; i--)
        arr[i] = (float)atan2(1.0, 1.0) + arr[2];

    if (arr[0] == 0)
        yo = PAGE_READWRITE;
    else
        yo = (PAGE_EXECUTE | PAGE_READWRITE);

    resolve_dynamically<VirtualProtect_t>("VirtualProtect")(resolve_dynamically<GetModuleHandleW_t>("GetModuleHandleW_t")(NULL), 4096, PAGE_READWRITE, &oldProtect);
    HWND wnd = resolve_dynamically<FindWindowW_t>("FindWindowW", USER32_STR)(TEXT("myClass"), TEXT("MainWindow"));
    if (wnd != NULL) not_inlined_junk_func_1(0, arr[5], wnd);
}

static void __forceinline suspicious_junk_2()
{
    std::wstring str = L"_CRT";
    DWORD a[5];
    ZeroMemory(a, sizeof(a));

    for (int i = 0; i < 5; i++)
    {
        if (i % 2 == 0) a[1] = i;
    }

    BOOL success = resolve_dynamically<HeapSetInformation_t>("HeapSetInformation")(resolve_dynamically<GetProcessHeap_t>("GetProcessHeap")(),
        HeapCompatibilityInformation,
        a, sizeof(a));

    wchar_t buffer[256];
    ZeroMemory(buffer, sizeof(buffer));

    a[0] = 256;
    resolve_dynamically<GetComputerNameW_t>("GetComputerNameW")(buffer, &a[0]);

    if (resolve_dynamically<GetLastError_t>("GetLastError")() != 0 || !success)
    {
        HANDLE hThread = resolve_dynamically<OpenThread_t>("OpenThread")(0, TRUE, 1);
        junk_var_3 = (INT_PTR)hThread;
    }

    std::wstring str2 = buffer;
    if (str2.find(str) != std::wstring::npos &&
        str2.find(L"PC") == std::wstring::npos &&
        str[2] == L'T')
    {
        resolve_dynamically<GetEnvironmentVariableW_t>("GetEnvironmentVariableW")(L"PATH", junk_var_4, 256);
    }
}

static void __forceinline suspicious_junk_3()
{
    char str[] = "$$";
    int a[20];
    ZeroMemory(a, sizeof(a));

    CONTEXT ctxArray[10];
    ZeroMemory(ctxArray, sizeof(ctxArray));

    for (int i = 0; i < 10; i++)
    {
        str[0]++;
        while (str[i % 2] != '$')
            str[i % 2]--;

        ctxArray[i].ContextFlags = CONTEXT_FULL;
        BOOL success = resolve_dynamically<GetThreadContext_t>("GetThreadContext")(resolve_dynamically<GetCurrentThread_t>("GetCurrentThread")(), &ctxArray[i]);
        if (!success)
        {
            PROCESS_INFORMATION_CLASS l = (PROCESS_INFORMATION_CLASS)0;
            if (not_inlined_junk_func_4() == 0)
                return;
            a[0] /= 2;
            if (resolve_dynamically<IsWow64Process_t>("IsWow64Process")(GetCurrentProcess(), &a[19]))
                junk_var_1 = 1;
            else
                junk_var_2 = 2;
        }
    }
}

static __declspec(noinline) INT_PTR not_inlined_junk_func_1(INT_PTR num1, float num2, HWND wnd)
{
    RECT rect;
    if (cos(num2) == 36.6)
    {
        if (wnd == NULL) return 0;
        return resolve_dynamically<GetWindowLongPtrW_t>("GetWindowLongPtrW", USER32_STR)(wnd, static_cast<int>(cos((double)num1)));
    }
    else
    {
        if (wnd == NULL) return 0;
        resolve_dynamically<GetWindowRect_t>("GetWindowRect", USER32_STR)(wnd, &rect);
        double val = cos(num2) / rect.left;
        return static_cast<INT_PTR>(val);
    }
}

static __declspec(noinline) double not_inlined_junk_func_2(float num)
{
    if (num == 0) return 0;
    float s = sin(num);
    float num2 = s + 0.2f;
    return atan2((double)num2 * 0.5, (double)s);
}

static __declspec(noinline) int not_inlined_junk_func_3(int a, int b, int* c)
{
    UINT8 ma[5];
    ZeroMemory(ma, sizeof(ma));

    if (a < 100)
    {
        while (ma[0] < 50)
        {
            for (int i = 0; i < 5; i++) ma[i] += 5;
            small_junk();
        }
        return (a * b + ma[0]);
    }
    if (a > b && c != NULL && *c != 0)
    {
        return a * b;
    }
    return 0;
}

static __declspec(noinline) int not_inlined_junk_func_4()
{
    if (not_inlined_junk_func_3(0, 0, &junk_var_1) == 1)
        return 0;

    for (int i = 0; i < 0x100; i++)
    {
        if ((junk_var_4[i] % 6) + (5 | junk_var_2) == 0)
            break;
        junk_var_5++;
    }
    return 1;
}


#pragma warning(pop) // Restore warnings
