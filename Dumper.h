#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstring>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
typedef BYTE BYTE;
typedef ULONG64 ULONG64;
typedef ULONG32 ULONG32;
#else
typedef unsigned char BYTE;
typedef unsigned long long ULONG64;
typedef unsigned int ULONG32;
#endif

class Dumper
{
public:
    static bool ReadProgramIntoMemory(std::string DumpPath, std::vector<uint8_t>* out_buffer);
    static bool DumpOffsets(BYTE* Dump, size_t size);
};



