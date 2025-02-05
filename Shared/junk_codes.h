#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>


static int junk_var_1;
static int junk_var_2;
static int junk_var_3;
static TCHAR junk_var_4[256];

extern "C" void destruction_1();
extern "C" void destruction_2();
extern "C" void small_junk_1();

static void __forceinline junk_1();
static __declspec(noinline) int junk_func_4();
static double junk_func_2(float num);
static int junk_func_3(int a, int b, int* c);

static double junk_var_5 = junk_func_4();


using namespace std;

static void __forceinline junk_1()
{
	wstring a = wstring();
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

static double junk_func_2(float num)
{
	if (num == 0) return 0;
	int num1 = sin(num);
	float num2 = num1 + 0.2;
	return atan2((double)num2 * 0.5, num1);
}

static int junk_func_3(int a, int b, int* c)
{
	UINT8 ma[5];
	if (a < 100)
	{
		while (ma[0] < 50)
		{
			for (int i = 0; i < 5; i++) ma[i] += 5;
			small_junk_1();
		}
		return a * b + ma[0];
	}
	if (a > b && *c != NULL)
	{
		return a * b;
	}
	return 0;
}