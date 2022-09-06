
#include "cbase.h"
#include <util/obfuscate.h>
#include "memytools.h"

#define memydbg yep

#ifdef memydbg
    #define goodcolor   Color(90, 240, 90, 255) // green
    #define okcolor     Color(246, 190, 0, 255) // yellow
#endif



modbin* engine_bin   = new modbin{ 0xFEEF, 0x69 };
modbin* client_bin   = new modbin{ 0xFEEF, 0x69 };
modbin* server_bin   = new modbin{ 0xFEEF, 0x69 };
modbin* vgui_bin     = new modbin{ 0xFEEF, 0x69 };
modbin* tier0_bin    = new modbin{ 0xFEEF, 0x69 };

char bins_list[][MAX_PATH] =
{
    "engine",
    "client",
    "server",
    "vguimatsurface",
    "tier0",
};

modbin* modbins_list[]
{
    engine_bin,
    client_bin,
    server_bin,
    vgui_bin,
    tier0_bin,
};

memy_init _memy_init;
memy_init::memy_init() : CAutoGameSystem("")
{
}

memy _memy;
memy::memy()
{
}



bool memy_init::Init()
{
    memy::InitAllBins();

    Warning("[2] engine bin -> %x\n", engine_bin->addr);
    return true;

/*
    if (!engine_bin || !vgui_bin)
    {
    #ifdef dbging
        const char* failedinit = AY_OBFUSCATE("Failed init!\n");
        Warning(AY_OBFUSCATE("%s"), failedinit);
    #else
        // CHooks::setinsecure();
    #endif
    }
    return true;*/
}


bool memy::InitAllBins()
{
    // memy();
    size_t sbin_size = sizeof(bins_list) / sizeof(bins_list[0]);
    Warning("-> sbin size = %i\n", sbin_size);

    Warning("engine bin 0 -> %x\n", engine_bin->addr);
    Warning("engine bin 0 -> %p\n", engine_bin);

    // loop thru our bins
    for (size_t ibin = 0; ibin < sbin_size; ibin++)
    {
        InitSingleBin(bins_list[ibin], modbins_list[ibin]);
        Warning("->mbin %s -> %x %x\n", bins_list[ibin], modbins_list[ibin]->addr, modbins_list[ibin]->size);
    }

    Warning("engine bin 1 -> %x\n", engine_bin->addr);

    return true;
}

bool memy::InitSingleBin(const char* binname, modbin* mbin)
{
    Warning("-> ::InitSingleBin\n");
    Warning("mbin bin 0 -> %p\n", mbin);

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
                ConColorMsg(okcolor, "memytools::InitSingleBin -> something fucking EXPLODED\n");
            #endif

            return false;
        }
        
        #ifdef memydbg
            ConColorMsg(okcolor, "memytools::InitSingleBin -> mbase %x, msize %i\n", mbin->addr, mbin->size);
        #endif

    #else
        // binname + .so
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
            Warning("memytools::InitSingleBin -> GetModuleInformation failed!\n");
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
        #ifdef dbging
            Warning("CBinary::DataCompare -> Couldn't grab data %p, pattern %p, nor patternsize %i\n", data, pattern, sigsize);
        #endif
        return false;
    }

    for
    (
        size_t head = 0;
        head < sigsize;             // sigsize doesn't start from 0 so we don't need to <=
        (head++, pattern++, data++)
    )
    {
        // char at this pos in our pattern
        byte pattern_byte = *(pattern);

        #ifdef dbging
        if (head >= sigsize - 6)
        {
            Warning("CBinary::DataCompare -> head = %i; char = %.2x\n", head, pattern_byte);
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
        Warning("CMemyTools::DataCompare -> Grabbed pattern %p = %s, at %p + modsize\n", data, pattern, data);
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
            (sigsize * 2) + 1,
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
                ConColorMsg(goodcolor, "CMemyTools::FindPattern -> found pattern %s, %i, %i!\n", hexstr, sigsize, offset);
            #endif

            return reinterpret_cast<uintptr_t>(addr + offset);
        }
    }

    #ifdef memydbg
        Warning("CMemyTools::FindPattern -> Failed, pattern %s, %i, %i!\n", hexstr, sigsize, offset);
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

        return VirtualProtect(addr, protlen, prot, &tmp);
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



