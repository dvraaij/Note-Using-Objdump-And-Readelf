# Examples of Using Objdump and Readelf

Usually, you're not bothered so much with the low-level code the compiler
generates when developing software. But sometimes, however, you are as some
weird, unexplainable error occurs. Or you just want to learn how certain
high-level constructs are actually translated by a compiler.

It is therefore quite valuable to be able to analyze executable files till some
extend with tools like `objdump` and `readelf`. This short note describes some
ways I found to gain more insights in an object file and the low-level code that
a compiler generates.

## 1. Compiling an Example Program

We will use a simple, straightforward piece of code written in Ada as starting
point for the example. The Ada package has specification

```ada
package Foo is

  subtype My_Float is Float range 0.0 .. 200.0;

  procedure Increase;
  procedure Reset;

end Foo;
```

and body (implementation)

```ada

package body Foo is

  Initial_Value : constant := 100.0;

  Value : My_Float := Initial_Value;

  procedure Increase is
  begin
    Value := Value + 5.0;
  end Increase;

  procedure Reset is
  begin
    Value := Initial_Value;
  end Reset;

end Foo;
```

The package can be compiled using (I'm using [GNAT GPL
2016](http://libre.adacore.com/)):

```
$ gcc -g -c ./foo.adb
```

The compiler will now only compile (`-c`) the source code and emit an object
file `foo.o` which contains executable code, some data and some debug
information (`-g`). The object file is what we will analyze. It has not yet been
linked (to for example the Ada runtime libraries) and therefore contains
unresolved symbols. The fact that it has not yet been linked can be beneficial
as external functions (in particular those from the runtime) may add a
significant amount of code and data to the final executable making it harder to
actually find your own code during the analysis.

## 2. The Header and Section Summary

Executable and object files compiled for Linux are stored in the *Executable and
Linkable Format*, or ELF for short (see also the [man page of
ELF](https://man.freebsd.org/elf(5)). The file format contains a header and
various sections. The file header describes, among other things, the target
platform (e.g. ARM or x86) and can be shown by means of the command:

```
$ readelf -h ./foo.o
```

The output is:

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          2208 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         21
  Section header string table index: 18
```

The header shows that the source code was compiled for the AMD x86-64 platform.
The data is stored in [little endian](https://en.wikipedia.org/wiki/Endianness)
and signed integers are represented in [2's
complement](https://en.wikipedia.org/wiki/Signed_number_representations). The
ABI (which defines for example the subprogram calling convention) follows the
[UNIX / System V
standard](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI).

Furthermore, it also states that this is a relocatable type ELF file. This is
typical for objects that are emitted by the compiler but have not yet been
linked; the final location (offset) of data and code in the executable or
library file has not been determined.

The ELF file emitted from the compiler is said to be stored in the *linker view*
of the ELF file format. This is contrary to format of the ELF file emitted by
the linker; a file stored in the *execution view* of the ELF file. Both views
contain different aspects of the file format. For example, ELF files which are
stored in the linker view of the ELF format contain *sections*, those stored in
the execution view contain *segments*.

The object file that was just obtained contains various sections which can be
shown using the command:

```
$ readelf -S -W ./foo.o
```

This command shows the section headers (`-S`). The additional option `-W` allows
the command to use more than 80 columns when showing the output. It's a good
habit to always include this option to prevent any inconvenient truncation of
the output. The output for the sample program is as follows:

```
There are 21 section headers, starting at offset 0x8a0:

  Section Headers:
    [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
    [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
    [ 1] .text             PROGBITS        0000000000000000 000040 00005e 00  AX  0   0  2
    [ 2] .rela.text        RELA            0000000000000000 000580 0000c0 18   I 19   1  8
    [ 3] .data             PROGBITS        0000000000000000 0000a0 000008 00  WA  0   0  4
    [ 4] .bss              NOBITS          0000000000000000 0000a8 000000 00  WA  0   0  1
    [ 5] .rodata           PROGBITS        0000000000000000 0000a8 000014 00   A  0   0  4

    ...

    [19] .symtab           SYMTAB          0000000000000000 000368 0001c8 18     20  15  8
    [20] .strtab           STRTAB          0000000000000000 000530 000050 00      0   0  1
  Key to Flags:
    W (write), A (alloc), X (execute), M (merge), S (strings), l (large)
    I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
    O (extra OS processing required) o (OS specific), p (processor specific)
```

Each section contains some particular data. Most notably:

| Section name  | Contents                                               |
| :-----------: | :----------------------------------------------------- |
| `.text`       | Code                                                   |
| `.rela.text`  | Relocations related to the `.text` section (see below) |
| `.data`       | Initialized (static) data                              |
| `.bss`        | Uninitialized (static) data                            |
| `.rodata`     | Read-only data                                         |
| `.symtab`     | Symbol table                                           |

The `.data` and `.bss` sections ensure the allocation of memory for static
variables (the next section shows an example of static data). Contrary to
*static* variables are *dynamic* variables which are (as is in the name)
dynamically allocated and deallocated on the stack.

The abbreviation `.bss` stands for "Block Started by Symbol" for [historical
reasons](https://en.wikipedia.org/wiki/.bss#Origin). The `bss` section has a
finite size but is not actually stored in the file as its contents are known to
be all zeros (or arbitrary?). This is indicated by the section type `NOBITS`.

## 3. Inspecting the Generated Assembly Code

To show the assembly code stored in the `.text` section, run the command:

```
$ objdump -d -M intel -S ./foo.o
```

This command will display the generated assembly code (`-d`) in Intel syntax
format (`-M intel`) with the source code intermixed (`-S`). The last option
allows us to see which assembly code is generated for a particular high-level
language statement. One may also show the line numbers of the source code
(`-l`) if needed.

> This obviously works only if the source code (which is considered debug
information) is actually embedded in the object file; use option `-g` during
compilation as we did above.*

The output of the command shows three columns. From left-to-right, one may
distinguish

- the offset with respect to the start of the `.text` section in hex format followed by a colon,
- the binary representation of the instruction (opcode and operands) in hex format and
- a (more-or-less) human-readable representation of the instruction in Intel syntax format.

Let's focus on the portion of the output which shows the (re)initialization of
the variable `Value`:

```
000000000000004c <foo__reset>:

  procedure Reset is
  4c: 55                   push   rbp
  4d: 48 89 e5             mov    rbp,rsp
  begin
    Value := Initial_Value;
  50: 8b 05 00 00 00 00    mov    eax,DWORD PTR [rip+0x0]        # 56 <foo__reset+0xa>
  56: 89 05 00 00 00 00    mov    DWORD PTR [rip+0x0],eax        # 5c <foo__reset+0x10>
  end Reset;
  5c: 5d                   pop    rbp
  5d: c3                   ret
```

The first two assembler instructions are part of the *subprogram prologue*. They
prepare the stack frame for the current function (the current base pointer
`rbp`, which points to the stack frame of the calling function, is pushed to the
stack and the current stack pointer `rsp` is copied into the base pointer
register `rbp`).

First observe that the stack is not used in this function as it has no local
variables and calls to other functions. The whole stack frame administration
(including the *subprogram epilogue*; the pop of the base pointer at the end)
does not add any functionality to the code itself; it could even be removed
without impacting the program's function. However, be aware that debuggers do
rely on the existence of a subprogram prologue and epilogue that perform this
stack frame administration. Removing the subprogram's prologue and epilogue can
make debugging more difficult. The debugger can have difficulties (or may even
be incapable) of properly showing local variables or perform stack unwinding.

Now observe the actual body of the subprogram. In particular the incomplete
`mov` commands at offset `50` and `56`. The opcodes to write and read a value in
the register `eax` are indeed `8b 05` and `89 05` respectively as can be found
in volume 2B of the [Intel Software Development
Manual](https://software.intel.com/en-us/articles/intel-sdm), but the operands
seem incomplete; instead of an actual value or reference, `00 00 00 00` is
shown.

The reason for this is that the initialization value 100.0 and the static
variable `Value` are considered to be relocatable symbols which are put in the
sections `.rodate` and `.data` respectively. What the disassembly shows is just
a 4 byte placeholder. The placeholder will be substituted with actual values or
memory references when the final executable file or library is being linked.

## 4. First Look at the Relocatables

The relocatables can be shown by using the command:

```
$ readelf -r -W ./foo.o
```

This command will show the table with all relocatables (`-r`). The output for
the sample program is as follows (only the relocatables related to the `.text`
section are shown):

```
Relocation section '.rela.text' at offset 0x580 contains 8 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000000008  0000000300000002 R_X86_64_PC32          0000000000000000 .data + 0
0000000000000010  0000000600000002 R_X86_64_PC32          0000000000000000 .rodata + 4
0000000000000025  0000000600000002 R_X86_64_PC32          0000000000000000 .rodata + 8
0000000000000034  000000060000000a R_X86_64_32            0000000000000000 .rodata + 0
000000000000003e  0000001100000002 R_X86_64_PC32          0000000000000000 __gnat_rcheck_CE_Range_Check - 4
0000000000000046  0000000300000002 R_X86_64_PC32          0000000000000000 .data + 0
0000000000000052  0000000600000002 R_X86_64_PC32          0000000000000000 .rodata + c
0000000000000058  0000000300000002 R_X86_64_PC32          0000000000000000 .data + 0
...
````

The first column shows the relative memory offset in the `.text` section where a
substitution is required. For the operands at offset `52` and `58` shown in the
former step, the values should indeed be found in the sections `.rodata` and
`.data` (see last column). So how can these relocations be resolved?

### Relocation @ 52 (Type R_X86_64_PC32)

So we know that we have to look in the section `.rodata`, but how do we know
which entity is referenced? First of all, we have to look at the relocation type
which is `R_X86_64_PC32` for the symbol at `52`. The particular relocation type
implies that the 32-bit operand value can be found at the absolute offset, which
will be equal to the instruction pointer (`rip`; also known as the program
counter `PC`) plus a relative offset. This more-or-less explains the so-called
[size directive](http://www.cs.virginia.edu/~evans/cs216/guides/x86.html) and
pointer reference found in the disassembly:

```
DWORD PTR [rip+0x0]
```

The 32-bit operand (`DWORD`) is located at an absolute offset (`PTR`) given by
the current value of the instruction pointer (`rip`) plus a relative offset to
be computed (indicated by `0x0`). An important aspect to remember is that the
instruction pointer will be pointing to the *next* instruction when it is read
here.

So how to obtain the relative offset? The [System V ABI for
AMD64](https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf)
states that the relative offset for a relocation of type `R_X86_64_PC32` can be
computed using the formula:

```
rel. offset = S + A - P
```

with (in this particular example)

```
S  Symbol's Value : 00
A  Addend         : offset(.rodata) + 0c
P  Offset         : 52                  
```

The offset of `.rodata` follows from the section header summary (`readelf -sW`)
and equals `a8`. Hence, the *relative* offset with respect to the instruction
pointer is:

```
S + A - P = 00 + (a8 + 0c) - 52
          = 98
```

The *absolute* offset now is (`rip` will be pointing to the next
instruction!):

```
rip + (S+A-P) = 56 + 98
              = b8
```

The correctness can now be verified by means of the command:

```
$ hexdump -s 0xb8 -n 4 -C ./foo.o
```

This command shows the 4 bytes (`-n 4`) at offset `0xb8` (`-s 0xb8`) in
canonical hexadecimal / character format (`-C`). We can confirm that this is
indeed the value that we expect to be substituted. The output is:

```
000000b8  00 00 c8 42                                       |...B|
000000bc
```

which is indeed the (little endian) [IEEE-754
floating-point](https://en.wikipedia.org/wiki/Single-precision_floating-point_format)
representation of 100.0.

| Value | IEEE-754 binary format  |
| ----: | :---------------------: |
|   5.0 | `00 00 a0 40`           | 
| 200.0 | `00 00 48 43`           |   
| 100.0 | `00 00 c8 42`           |  

Note that the offset within the section `.rodata` can found to be:

```
  abs. offset - offset(.rodata)
= b8          - a8
= 10
```

This can be verified by showing the content of the `.rodata` section using:

```
$ readelf -x .rodata ./foo.o
```

The output is:

```
Hex dump of section '.rodata':
  0x00000000 666f6f2e 61646200 0000a040 00004843 foo.adb....@..HC
  0x00000010 0000c842                            ...B
```

which indeed shows (again) that the expected value 100.0 is found at
`offset(.rodata) + 10`.

### Relocation @ 58 (Type R_X86_64_PC32)

To get more familiar with this type of relocation, let's do it again, but now
for the relocation at `58`. The relocation overview shows that this is indeed a
`R_X86_64_PC32` type relocation, so we can compute the relative offset using

```
S  Symbol's Value : 00                 
A  Addend         : offset(.data) + 00
P  Offset         : 58           
```

which gives:

```
S + A - P = 00 + (a0 + 00) - 58
          = 48
```

The *absolute* offset equals (`rip` will be pointing to the next instruction!):

```
rip + (S+A-P) = 5c + 48
              = a4
```

and the offset within the `.data` section is found to be:

```
  abs. offset - offset(.data)
= a4          - a0
= 04
```

The hexdump of the `.data` section confirms that this is indeed correct. The
static variable is initialized with value 100.0. The command:

```
$ readelf -x .data ./foo.o
```

gives:

```
Hex dump of section '.data':
  0x00000000 00000000 0000c842                   .......B
```

As a final detail: observe that as the global variable is initialized in the
`.data` section, so the code line

```ada
Value : My_Float := Initial_Value;
```

does not require any (initialization) code. This can be confirmed by looking at
the disassembly.

## 5. External References to Subprograms

Reviewing the relocation table once more, it can be seen that a subprogram
`__gnat_rcheck_CE_Range_Check` is referenced next to the static (read-only)
variables:

```
Relocation section '.rela.text' at offset 0x580 contains 8 entries:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000000008  0000000300000002 R_X86_64_PC32          0000000000000000 .data + 0
0000000000000010  0000000600000002 R_X86_64_PC32          0000000000000000 .rodata + 4
0000000000000025  0000000600000002 R_X86_64_PC32          0000000000000000 .rodata + 8
0000000000000034  000000060000000a R_X86_64_32            0000000000000000 .rodata + 0
000000000000003e  0000001100000002 R_X86_64_PC32          0000000000000000 __gnat_rcheck_CE_Range_Check - 4
0000000000000046  0000000300000002 R_X86_64_PC32          0000000000000000 .data + 0
0000000000000052  0000000600000002 R_X86_64_PC32          0000000000000000 .rodata + c
0000000000000058  0000000300000002 R_X86_64_PC32          0000000000000000 .data + 0

...
```

Let's examine the disassembly step-by-step to see why its there. The disassembly
shows that after subprogram's prologue, the actual addition takes place:

```
procedure Increase is
 0: 55                    push   rbp
 1: 48 89 e5              mov    rbp,rsp
begin
  Value := Value + 5.0;
 4: f3 0f 10 0d 00 00 00  movss  xmm1,DWORD PTR [rip+0x0]        # c <foo__increase+0xc>
 b: 00
 c: f3 0f 10 05 00 00 00  movss  xmm0,DWORD PTR [rip+0x0]        # 14 <foo__increase+0x14>
13: 00
14: f3 0f 58 c1           addss  xmm0,xmm1
```

The operands are loaded from the `.data` and `.rodata` sections using `movss`
(move single-precision floating-point scalar). The sum is computed using `addss`
(add single-precision floating-point scalars) and stored into `xmm0`. Next the
result is then first compared to the lower bound of the `My_Float` type of
variable `Value` using `ucommss` (unordered comparison of single-precision
floating-point scalars):

```
18: 66 0f ef c9           pxor   xmm1,xmm1
1c: 0f 2e c1              ucomiss xmm0,xmm1
1f: 72 0d                 jb     2e <foo__increase+0x2e>
```

Register `xmm1` contains the lower bound of the `My_Float` type. The lower
bound, 0, is set using `pxor`. The result of the comparison is tested using `jb`
(jump if below). The "jump" will be made if the result is lower than 0, else the
upper bound is subsequently loaded from the read-only data section into register
`xmm1` using `movss`:

```
21: f3 0f 10 0d 00 00 00  movss  xmm1,DWORD PTR [rip+0x0]        # 29 <foo__increase+0x29>
28: 00
29: 0f 2e c8              ucomiss xmm1,xmm0
2c: 73 14                 jae    42 <foo__increase+0x42>
```

The summation result (still in `xmm0`) is then again compared using `ucomiss`
but now with respect to the upper bound. The result is tested using `jae` (jump
above or equal). Note that the "jump" will now be made if the value is actually
in the range of type `My_Float`. If either test fails, preparation for the
invocation of the function we're investigating will be done using some `mov`
instructions:

```
2e: be 09 00 00 00        mov    esi,0x9
33: bf 00 00 00 00        mov    edi,0x0
38: b8 00 00 00 00        mov    eax,0x0
3d: e8 00 00 00 00        call   42 <foo__increase+0x42>
```

From the System V ABI for AMD64 we can infer that the first and second actual
parameters of the function are set to the values `0` and `9` respectively
(parameters are transferred in right-to-left order via registers `edi` and `esi`
respectively). After that, the actual invocation (`call`) of the library
function `__gnat_rcheck_CE_Range_Check` takes place. If the summation result
*was* in range of type `My_Float`, then the static variable `Value` is updated
at using `movss`:

```
42: f3 0f 11 05 00 00 00  movss  DWORD PTR [rip+0x0],xmm0        # 4a <foo__increase+0x4a>
```

After that, the subprogram epilogue follows and the subprogram returns.

The function `__gnat_rcheck_CE_Range_Check` is part of the Ada runtime system
(RTS) and is called when a range check fails and a `Contraint_Error` must then
be raised. This and other runtime functions can be found in the runtime library
`libgnat.a` (see `adalib` directory of the Ada runtime) and use:

```
$ nm -A libgnat.a | grep '__gnat_rcheck_CE_Range_Check'
```

This command will list the symbols named `__gnat_rcheck_CE_Range_Check` in the
archive `libgnat`. The option `-A` shows the object file in which the found
symbol resides (note that an archive is a collection of object files). The
command outputs:

```
libgnat.a:a-except.o:0000000000000000 T __gnat_rcheck_CE_Range_Check
libgnat.a:a-except.o:0000000000000000 T __gnat_rcheck_CE_Range_Check_ext
libgnat.a:a-siteio.o:                 U __gnat_rcheck_CE_Range_Check
libgnat.a:a-ssitio.o:                 U __gnat_rcheck_CE_Range_Check
libgnat.a:s-auxdec.o:                 U __gnat_rcheck_CE_Range_Check
```

It shows that the function being referenced in our program (or compilation unit
to be more precise), is defined in the object file `a-except.o`. It also shows
that an extended version exists (for use with array bound checking; see runtime
source code) and that other functions within the runtime itself refer to the
function as well.

One may now download the sources of the Ada runtime and search for the file
`a-execpt.ads` to see the function's formal specification and implementation.

```ada
procedure Rcheck_CE_Range_Check                    -- 12
   (File : System.Address; Line : Integer);

-- ...

pragma Export (C, Rcheck_CE_Range_Check,
                "__gnat_rcheck_CE_Range_Check");

-- ...

procedure Rcheck_CE_Range_Check
  (File : System.Address; Line : Integer)
is
begin
   Raise_Constraint_Error_Msg (File, Line, 0, Rmsg_12'Address);
end Rcheck_CE_Range_Check;
```

Interestingly, this now allows us to interpret the values `0` and `9` that are
passed as parameters (see disassembly above). The first actual parameter, `0`,
is a relocatable and should point to a filename. The second parameter, `9`,
refers to the line number at which the exception occurs (line 9 in the source
code). The third parameter is constant and the fourth parameter refers to the
string explaining the problem (`range check failed`). The string is stored
within to the library).

Another interesting point to observe is that the `Export` pragma or aspect can
be used to overrule Ada's visibility rules at *link-time*. The `Export` pragma
or aspect allows a subprogram which is defined only in the body of a package to
be externally available for linking (indicated by the `T` and contrary to `t` in
`nm`'s output ). This is contrary to the rule which says that a subprogram must
be specified in the package spec to be externally visible at *compile-time*. Ada
sometimes allows this (and other forms of) subtle rule bending for the
programmer's convenience as long as he or she states its intention explicitly.
The compiler then assumes that the programmer is aware of the consequences.

## 6. A Second Look at Relocations

So we've seen the invocation of the external subprogram
`__gnat_rcheck_CE_Range_Check`. The invocation itself contains two relocations:
one for the first parameter (at offset `34`) and one for the actual call (at
offset `3e`). Let's have a closer look at both.

### Relocation @ 33 (Type R_X86_64_32)

Here, the relocation type *does not* use relative addressing. It uses absolute
addressing instead. The absolute offset for type `R_X86_64_32` can be found
using the formula:

```
abs. offset = S + A
```

with

```
S  Symbol's Value : 00                   
A  Addend         : offset(.rodata) + 00
```

The *absolute* offset now equals:

```
S + A = 00 + (a8 + 00)
      = a8
```

and the offset within the `.rodata` section equals:

```
a8 - offset(.rodata) = 00
```

Taking a look at the content of the `.rodata` section again shows that the
relocation is indeed associated with a string containing the filename of the
source code. The filename is shown when the `Constraint_Error` exception is
reported.

### Relocation @ 3e (Type R_X86_64_PC32)

The last example involves the relocation of the function address itself. The
external function is not yet available within the object file but the symbol
which represents the subprogram is. The relocation is of type `R_X86_64_PC32`.
Let's compute the relative offset.

```
S  Symbol's Value  : 00                                        
A  Addend          : offset(__gnat_rcheck_CE_Range_Check) - 04
P  Offset          : 3e                                        
```

which gives:

```
S + A - P = 00 + (offset(__gnat_rcheck_CE_Range_Check) - 04) - 3e
          =       offset(__gnat_rcheck_CE_Range_Check) - 42
```

The *absolute* offset equals:

```
rip  + (S+A-P) = 42 + offset(__gnat_rcheck_CE_Range_Check) - 42
               =      offset(__gnat_rcheck_CE_Range_Check)
```

This shows that the call statement will set the instruction pointer correctly to
the entry point of the external function once its offset if known. The extra
`-04` in the addend (see table) is required to compensate for the fact that
`rip` points to the *next* instruction when it is read.

## 7. Conclusion

This was only a brief example of how one can use the `readelf` and `objdump`
tools. Feeling comfortable with these tools may come in handy when debugging or
understanding the anatomy of software at low-level. As can be imagined, a lot
can be found in all the nifty-gritty details and one can spend a vast amount of
time following various trails leading to all kind of insights; even for a small
and rather simple program as shown in this example.

## Appendix

Much of the same information can be obtained using either `readelf` or
`objdump` (although the information from `readelf` is sometimes more
extensive). The table below gives an overview of the arguments used by each
program to obtain some particular information.

|                    | readelf | objdump |
| :----------------- | :-----: | :-----: |
| Program header     | `-l`    | (n/a)   |
| File header        | `-h`    | `-f`    |
| Sections           | `-S`    | `-h`    |
| Relocation entries | `-r`    | `-r`    |
| Symbol table       | `-s`    | `-t`    |
| Hex dump           | `-x`    | `-j`    |
| Disassemble        | (n/a)   | `-d`    |
| Wide printing      | `-W`    | `-w`    |

Show file type:

    $ file <file>

Show shared object dependencies:

    $ ldd <file>

or, as a more secure alternative (see man page of `ldd`):

    $ objdump -pW <file> | grep 'NEEDED'

Display archive contents (`objdump -a <file.a>`):

    $ ar tv <file.a>
