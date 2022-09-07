// obfuscate strings in this lib?
// requires https://github.com/adamyaxley/Obfuscate
// and >= c++ 14 
// #include <util/obfuscate.h>
#include "memytools.h"

#ifndef AY_OBFUSCATE
    #define AY_OBFUSCATE
#endif

#define memydbg yep

#ifdef memydbg
    #define goodcolor   Color(000, 255, 000, 255) // green
    #define okcolor     Color(255, 190, 000, 255) // yellow
#endif


memy_init _memy_init;
memy_init::memy_init() : CAutoGameSystem("")
{
}

modbin* engine_bin = new modbin();
modbin* vgui_bin   = new modbin();
modbin* tier0_bin  = new modbin();
modbin* client_bin = new modbin();
modbin* server_bin = new modbin();

char bins_list[][MAX_PATH] =
{
    {},
    {},
    {},
    {},
    {},
};

modbin* modbins_list[]
{
    engine_bin,
    client_bin,
    server_bin,
    vgui_bin,
    tier0_bin,
};

memy _memy;
memy::memy()
{
    V_strncpy(bins_list[0], AY_OBFUSCATE("engine"),         16);
    V_strncpy(bins_list[1], AY_OBFUSCATE("vguimatsurface"), 16);
    V_strncpy(bins_list[2], AY_OBFUSCATE("tier0"),          16);
    V_strncpy(bins_list[3], AY_OBFUSCATE("client"),         16);
    V_strncpy(bins_list[4], AY_OBFUSCATE("server"),         16);
}

bool memy_init::Init()
{
    // memy();
    memy::InitAllBins();

    Warning("[2] engine bin -> %x\n", engine_bin->addr);
    return true;
}


bool memy::InitAllBins()
{
    // memy();
    size_t sbin_size = sizeof(bins_list) / sizeof(bins_list[0]);

    // loop thru our bins
    for (size_t ibin = 0; ibin < sbin_size; ibin++)
    {
        InitSingleBin(bins_list[ibin], modbins_list[ibin]);
    }

    return true;
}

bool memy::InitSingleBin(const char* binname, modbin* mbin)
{
    // binname + .dll
    char realbinname[256] = {};

    #ifdef _WIN32
        V_snprintf(realbinname, sizeof(realbinname), "%s.dll", binname);

        HMODULE mhandle;
        mhandle = GetModuleHandleA(realbinname);
        if (!mhandle)
        {
            #ifdef dbging
                Warning("memytools::InitSingleBin -> Couldn't grab handle for bin %s = %s!\n", binname, realbinname);
            #endif

            return false;
        }

        MODULEINFO minfo;

        GetModuleInformation(GetCurrentProcess(), mhandle, &minfo, sizeof(minfo));

        mbin->addr = reinterpret_cast<uintptr_t>(minfo.lpBaseOfDll);
        mbin->size = minfo.SizeOfImage;

        if (!mbin->addr || !mbin->size)
        {
            #ifdef memydbg
                ConColorMsg(okcolor, "memy::InitSingleBin -> something fucking EXPLODED\n");
            #endif

            return false;
        }
        
        #ifdef memydbg
            ConColorMsg(okcolor, "memy::InitSingleBin -> mbase %x, msize %i\n", mbin->addr, mbin->size);
        #endif

    #else
        // binname + .so

        // funny special case
        if (strcmp(binname, "engine"))
        {
            #ifdef OF_CLIENT_DLL
                // V_snprintf(realbinname, sizeof(realbinname), "%s.so", binname);
            #else
                V_snprintf(realbinname, sizeof(realbinname), "%s_srv.so", binname);
            #endif
        }
        else
        {
            V_snprintf(realbinname, sizeof(realbinname), "%s.so", binname);
        }

        void*          mbase = nullptr;
        size_t         msize = 0;
        if (GetModuleInformation(binname, &mbase, &msize))
        {
            Warning("memy::InitSingleBin -> GetModuleInformation failed!\n");
            return false;
        }

        mbin->addr = reinterpret_cast<uintptr_t>(mbase);
        mbin->size = msize;
    #endif

    return true;
}

inline bool memy::comparedata(const byte* data, const char* pattern, size_t sigsize)
{
    if (!data || !pattern || !sigsize)
    {
        #ifdef memydbg
            Warning("memy::DataCompare -> Couldn't grab data %p, pattern %p, nor patternsize %i\n", data, pattern, sigsize);
        #endif
        return false;
    }

    for
    (
        size_t head = 0;
        head < sigsize; // sigsize doesn't start from 0 so we don't need to <=
        (head++, pattern++, data++)
    )
    {
        // char at this pos in our pattern
        byte pattern_byte = *(pattern);

        #ifdef dbging
        if (head >= sigsize - 6)
        {
            Warning("memy::DataCompare -> head = %i; char = %.2x\n", head, pattern_byte);
        }
        #endif

        // if it's a wildcard just skip it
        if ( pattern_byte == '\x2A' )
        {
            continue;
        }

        // char at this pos in our memory
        byte data_byte = *(data);

        // if it doesn't match it's bunk; go to the next byte
        if ( pattern_byte != data_byte )
        {
            return false;
        }
    }

    #ifdef memydbg
        Warning("memy::DataCompare -> Grabbed pattern %p = %s, at %p + modsize\n", data, pattern, data);
    #endif

    return true;
}

//---------------------------------------------------------------------------------------------------------
// Finds a pattern of bytes in the engine memory given a signature and a mask
// Returns the address of the first (and hopefully only) match with an optional offset, otherwise nullptr
//---------------------------------------------------------------------------------------------------------    
uintptr_t memy::FindPattern(uintptr_t startaddr, size_t searchsize, const char* pattern, size_t sigsize, size_t offset)
{
    #ifdef memydbg
        char hexstr[128] = {};
        V_binarytohex
        (
            reinterpret_cast<const byte*>(pattern),
            (sigsize * 2) + 1, // sigsize -> bytes + nullterm
            hexstr,
            (sigsize * 2) + 1
        );
    #endif

    if (!startaddr || !searchsize || !pattern)
    {
        #ifdef memydbg
            Warning("memy::FindPattern -> Couldn't grab modbase %x, modsize %i, or pattern %p = %s\n", startaddr, searchsize, pattern, hexstr);
        #endif

        return NULL;
    }

    // iterate thru memory, starting at modbase + i, up to (modbase + i) - sigsize
    for (size_t i = 0; i <= (startaddr - sigsize); i++)
    {
        byte* addr = reinterpret_cast<byte*>(startaddr) + i;

        if (comparedata(addr, pattern , sigsize))
        {
            #ifdef memydbg
                ConColorMsg(goodcolor, "memy::FindPattern -> found pattern %s, %i, %i!\n", hexstr, sigsize, offset);
            #endif

            return reinterpret_cast<uintptr_t>(addr + offset);
        }
    }

    #ifdef memydbg
        Warning("memy::FindPattern -> Failed, pattern %s, %i, %i!\n", hexstr, sigsize, offset);
    #endif

    return NULL;
}


bool memy::SetMemoryProtection(void* addr, size_t protlen, int wantprot)
{
    #ifdef _WIN32
        // VirtualProtect requires a valid pointer to store the old protection value
        DWORD tmp;
        DWORD prot;

        switch (wantprot)
        {
            case (MEM_READ):
            {
                prot = PAGE_READONLY;
                break;
            }
            case (MEM_READ | MEM_WRITE):
            {
                prot = PAGE_READWRITE;
                break;
            }
            case (MEM_READ | MEM_EXEC):
            {
                prot = PAGE_EXECUTE_READ;
                break;
            }
            case (MEM_READ | MEM_WRITE | MEM_EXEC):
            default:
            {
                prot = PAGE_EXECUTE_READWRITE;
                break;
            }
        }

        // BOOL is typedef'd as an int on Windows, sometimes (lol), bang bang it to convert it to a bool proper
        return !!(VirtualProtect(addr, protlen, prot, &tmp));
    #else
    // POSIX
        return mprotect( LALIGN(addr), protlen + LALDIF(addr), wantprot) == 0;
    #endif
}


#if defined (POSIX)
//returns 0 if successful
int memy::GetModuleInformation(const char *name, void **base, size_t *length)
{
    // this is the only way to do this on linux, lol
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 1;

    char buf[PATH_MAX+100];
    while (!feof(f))
    {
        if (!fgets(buf, sizeof(buf), f))
            break;

        char *tmp = strrchr(buf, '\n');
        if (tmp)
            *tmp = '\0';

        char *mapname = strchr(buf, '/');
        if (!mapname)
            continue;

        char perm[5];
        unsigned long begin, end;
        sscanf(buf, "%lx-%lx %4s", &begin, &end, perm);

        if (strcmp(basename(mapname), name) == 0 && perm[0] == 'r' && perm[2] == 'x')
        {
            *base = (void*)begin;
            *length = (size_t)end-begin;
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return 2;
}
#endif



