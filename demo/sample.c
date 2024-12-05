#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <dsgetdc.h>
#include "beacon.h"


__declspec(dllimport) int __cdecl MSVCRT$printf(const char *format, ...);

const char* GlobalString = "This is a global string";
int a;

void hello() {
    BeaconPrintf(1, "This GlobalString from beacon internal function \"%s\"\n", GlobalString);

    MSVCRT$printf("Hello, COFF World!\n");
    a = 42;
    MSVCRT$printf("a = %d\n", a);
}

void go() {
    hello();
}
