#pragma once

#include <stdio.h>

#ifndef NDEBUG
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define DebugPrint(fmt, ...) fprintf(stderr, "%s(%d):%s(): ", __FILENAME__, __LINE__, __func__); fprintf(stderr, fmt, __VA_ARGS__)
#else
#define DebugPrint(fmt, ...)
#endif