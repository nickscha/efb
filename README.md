# efb
A C89 standard compliant, single header, nostdlib (no C Standard Library) executable file/format builder (EFB).

EFB can build/write the executable files/formats platform independant (e.g. on Linux you can also build PE, .. formats and vice versa).

For more information please look at the "efb.h" file or take a look at the "examples" or "tests" folder.

> [!WARNING]
> THIS PROJECT IS A WORK IN PROGRESS! ANYTHING CAN CHANGE AT ANY MOMENT WITHOUT ANY NOTICE! USE THIS PROJECT AT YOUR OWN RISK!

## Quick Start

Download or clone efb.h and include it in your project.

```C
#include "efb.h"                /* Executable File Builder                 */
#include "efb_platform_write.h" /* Optional: OS-Specific write file IO API */

int main() {

    /* Define a X86_64 instruction: mov eax, 0; ret */
    unsigned char x86_64_ret[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3};

    /* efb.h does not use File IO and just fills the buffer with the executable file data */
    #define BINARY_CAPACITY 4096
    unsigned char binary_buffer[BINARY_CAPACITY];

    efb_model model = {0};
    model.arch                = EFB_ARCH_X86_64;    /* Specify the target architecture          */
    model.format              = EFB_FORMAT_PE;      /* The executable file format to be used    */
    model.out_binary          = binary_buffer;      /* User provided buffer for executable data */
    model.out_binary_capacity = BINARY_CAPACITY;    /* The maximum size of the buffer           */
    model.code                = x86_64_ret;         /* The instruction binary                   */
    model.code_size           = sizeof(x86_64_ret); /* The size of the instruction binary array */

    /* If efb_build succeeds it fills the out_binary and out_binary_size */
    if(efb_build(&model)) {
       /* By default efb itself does not use file IO to stay nostdlib and platform independant                                */
       /* If you want a small file write implementation (nostdlib but platform dependant) than include "efb_platform_write.h" */ 
       efb_platform_write("ret.exe", model.out_binary, model.out_binary_size)
    }

    return 0;
}
```

## Run Example: nostdlib, freestsanding

In this repo you will find the "examples/efb_win32_nostdlib.c" with the corresponding "build.bat" file which
creates an executable only linked to "kernel32" and is not using the C standard library and executes the program afterwards.

## "nostdlib" Motivation & Purpose

nostdlib is a lightweight, minimalistic approach to C development that removes dependencies on the standard library. The motivation behind this project is to provide developers with greater control over their code by eliminating unnecessary overhead, reducing binary size, and enabling deployment in resource-constrained environments.

Many modern development environments rely heavily on the standard library, which, while convenient, introduces unnecessary bloat, security risks, and unpredictable dependencies. nostdlib aims to give developers fine-grained control over memory management, execution flow, and system calls by working directly with the underlying platform.

### Benefits

#### Minimal overhead
By removing the standard library, nostdlib significantly reduces runtime overhead, allowing for faster execution and smaller binary sizes.

#### Increased security
Standard libraries often include unnecessary functions that increase the attack surface of an application. nostdlib mitigates security risks by removing unused and potentially vulnerable components.

#### Reduced binary size
Without linking to the standard library, binaries are smaller, making them ideal for embedded systems, bootloaders, and operating systems where storage is limited.

#### Enhanced performance
Direct control over system calls and memory management leads to performance gains by eliminating abstraction layers imposed by standard libraries.

#### Better portability
By relying only on fundamental system interfaces, nostdlib allows for easier porting across different platforms without worrying about standard library availability.
