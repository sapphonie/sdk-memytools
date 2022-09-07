# sdk-memy
pseudolibrary for memory patching/detouring in [Valve Software SDK2013](https://github.com/ValveSoftware/source-sdk-2013) mods. some code stolen from mmod, some from cathook, some written by me

## How to use

```
x.vpc
...
        // <memytools>
        $Folder	"memy"
        {
            $File   "$SRCDIR\game\shared\memy\memytools.h"
            $File   "$SRCDIR\game\shared\memy\bytepatch.hpp"
            $File   "$SRCDIR\game\shared\memy\detourhook.hpp"
            $File   "$SRCDIR\game\shared\memy\memytools.cpp"
            {
                $Configuration
                {
                    $Compiler
                    {
                        $Create/UsePrecompiledHeader    "Not Using Precompiled Headers"
                    }
                }
            }
        }
        // </memytools>
...
            // example files that depend on memy functions
            $File   "$SRCDIR\game\shared\mempatch.h"
            $File   "$SRCDIR\game\shared\mempatch.cpp"
            {
                $Configuration
                {
                    $Compiler
                    {
                        $Create/UsePrecompiledHeader    "Not Using Precompiled Headers"
                    }
                }
            }
...
```
