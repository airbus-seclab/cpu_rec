# Description
`cpu_rec` is a tool that recognizes cpu instructions
in an arbitrary binary file.
It can be used as a standalone tool, or as a plugin for binwalk
(https://github.com/devttys0/binwalk).

# Installation instructions
## Standalone tool
1. Copy `cpu_rec.py` and `cpu_rec_corpus` in the same directory.
2. If you don't have the `lzma` module installed for your python (this
   tool works either with python3 or with python2 >= 2.4) then you
   should `unxz` the corpus files in `cpu_rec_corpus`.
3. If you want to enhance the corpus, you can add new data in the
   corpus directory. If you want to create your own corpus, please
   look at the method `build_default_corpus` in the source code.

## For use as a binwalk module
Same as above, but the installation directory must be the binwalk
module directory: `$HOME/.config/binwalk/modules`.

You'll need a recent version of binwalk, that includes the patch
provided by https://github.com/devttys0/binwalk/pull/241 .

# How to use the tool
## As a binwalk module
Add the flag `-%` when using binwalk.

Be patient. Waiting a few minutes for the result is to be expected.
On my laptop the tool takes 25 seconds and 1 Gb of RAM
to create the signatures for 70 architectures, and then the analysis
of a binary takes one minute per Mb.
If you want the tool to be faster, you can remove some architectures,
if you know that your binary is not one of them (typically Cray or
MMIX are not found in a firmware).

## As a standalone tool
Just run the tool, with the binary file(s) to analyze as argument(s)
The tool will try to match an architecture for the whole file, and
then to detect the largest binary chunk that corresponds to a CPU
architecture; usually it is the right answer, but one should not
forget that this tool is heuristic and that some binary files contain
instructions for multiple architectures, therefore a more detailed
analysis may be needed.

If the result is not satisfying, prepending twice `-v` to the arguments
makes the tool very verbose; this is helpful when adding a new
architecture to the corpus or when there are doubts on the raw result
of the tool.

If https://github.com/LRGH/elfesteem is installed, then the
tool also extract the text section from ELF, PE, Mach-O or COFF
files, and outputs the architecture corresponding to this section;
the possibility of extracting the text section is also used when
building a corpus from full binary files.

Option `-d` followed by a directory dumps the corpus in that directory;
using this option one can reconstruct the default corpus.

## As a python module
The function `which_arch` takes a bytestring as input and outputs
the name of the architecture, or None.
Loading the training data is done during the first call of which_arch,
and calling which_arch with no argument does this precomputation only.

For example
```
>>> from cpu_rec import which_arch
>>> which_arch()
>>> which_arch(b'toto')
>>> which_arch(open('/bin/sh').read())
'X86-64'
```

## Create a corpus or extend the existing corpus
Each architecture is defined by a file in `cpu_rec_corpus`.
Only file names ending with `.corpus`, which can be compressed with `xz`.

The corpus file shall contain instructions for the target architecture.
As you can see in `build_default_corpus`, most of the default corpus has
been created by extracting the TEXT section of an executable.

If you want to add an new architecture (e.g. 78k as described below)
then you have to find a binary, and extract the executable section
(the command line to extract the 78k code from the Metz firmware is
`dd if=MB50AF1_NikonV12.bin of=Nec78k.corpus bs=1 skip=0x2ba count=0x7d5a`).

# Examples
Running the tool as a binwalk module typically results in:
```
shell_prompt> binwalk -% corpus/PE/PPC/NTDLL.DLL corpus/MSP430/goodfet32.hex

Target File:   .../corpus/PE/PPC/NTDLL.DLL
MD5 Checksum:  d006a2a87a3596c744c5573aece81d77

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             None (size=0x5800, entropy=0.620536)
22528         0x5800          PPCel (size=0x4c800, entropy=0.737337)
335872        0x52000         None (size=0x23800, entropy=0.731620)

Target File:   .../corpus/MSP430/goodfet32.hex
MD5 Checksum:  4b295284024e2b6a6257b720a7168b92

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             None (size=0x8000, entropy=0.473132)
32768         0x8000          MSP430 (size=0x5000, entropy=0.473457)
53248         0xD000          None (size=0x3000, entropy=0.489337)

Target File:   .../corpus/PE/ALPHA/NTDLL.DLL
MD5 Checksum:  9c76d1855b8fe4452fc67782aa0233f9

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             None (size=0xa000, entropy=0.785498)
40960         0xA000          Alpha (size=0x5b800, entropy=0.810394)
415744        0x65800         None (size=0x800, entropy=0.695699)
417792        0x66000         VAX (size=0x1000, entropy=0.683740)
421888        0x67000         None (size=0x28800, entropy=0.717975)

Target File:   .../corpus/Mach-O/OSXII
MD5 Checksum:  a4097b036f7ee45c147ab7c7d871d0c1

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             None (size=0x1800, entropy=0.156350)
6144          0x1800          PPCeb (size=0x1b800, entropy=0.772708)
118784        0x1D000         None (size=0xd000, entropy=0.588620)
172032        0x2A000         X86 (size=0x2000, entropy=0.594146)
180224        0x2C000         None (size=0x800, entropy=0.758712)
182272        0x2C800         X86-64 (size=0x800, entropy=0.767427)
184320        0x2D000         X86 (size=0x18800, entropy=0.786143)
284672        0x45800         None (size=0xc000, entropy=0.612610)
```

Important: it is usually a good idea to start the analysis of an unknown
binary with some entropy analysis. `cpu_rec` assumes that it has been done,
but to protect the user against overlooking this aspect, it displays the
entropy.
If the entropy value is above 0.9, it is probably encrypted or compressed
data, and therefore the result of `cpu_rec` should be meaningless.

We can notice that during the analysis of `ALPHA/NTDLL.DLL`
small chunks are wrongly detected as non-Alpha architectures.
They should be ignored.
But some files can contain multiple architectures, e.g. `Mach-O/OSXII`
which is a Mach-O FAT file with ppc and i386 executables.

## More documentation

The tool has been presented at
[SSTIC 2017](https://www.sstic.org/2017/presentation/cpu_rec/),
with a full paper describing why this technique has been used for
the recognition of architectures. A video of the presentation
and the slides are available.

This presentation was made in French.
A [translation in English of the slides](doc/cpu_rec_slides_english.pdf) is available,
a [translation in English of the paper](doc/cpu_rec_sstic_english.md) is in progress.

# Known architectures in the default corpus
[`6502`](https://en.wikipedia.org/wiki/6502)
[`68HC08`](https://en.wikipedia.org/wiki/Freescale_68HC08)
[`68HC11`](https://en.wikipedia.org/wiki/Freescale_68HC11)
[`8051`](https://en.wikipedia.org/wiki/Intel_MCS-51)
[`Alpha`](https://en.wikipedia.org/wiki/DEC_Alpha)
[`ARcompact`](https://en.wikipedia.org/wiki/ARC_(processor))
[`ARM64` `ARMeb` `ARMel` `ARMhf`](https://en.wikipedia.org/wiki/ARM_architecture)
[`AVR`](https://en.wikipedia.org/wiki/Atmel_AVR)
[`AxisCris`](https://en.wikipedia.org/wiki/ETRAX_CRIS)
[`Blackfin`](https://en.wikipedia.org/wiki/Blackfin)
[`Cell-SPU`](https://en.wikipedia.org/wiki/Cell_(microprocessor))
[`CLIPPER`](https://en.wikipedia.org/wiki/Clipper_architecture)
[`CompactRISC`](https://en.wikipedia.org/wiki/CompactRISC)
[`Cray`](https://en.wikipedia.org/wiki/Cray)
[`CUDA`](https://en.wikipedia.org/wiki/CUDA)
[`Epiphany`](https://en.wikipedia.org/wiki/Adapteva)
[`FR-V`](https://en.wikipedia.org/wiki/FR-V_(microprocessor))
[`FR30`](http://www.fujitsu.com/downloads/MICRO/fma/pdfmcu/hm91101-cm71-10102-2e.pdf)
[`FT32`](https://en.wikipedia.org/wiki/FTDI)
[`H8-300` `H8S`](https://en.wikipedia.org/wiki/H8_Family)
[`HP-Focus`](https://en.wikipedia.org/wiki/HP_FOCUS)
[`HP-PA`](https://en.wikipedia.org/wiki/PA-RISC)
[`i860`](https://en.wikipedia.org/wiki/Intel_i860)
[`IA-64`](https://en.wikipedia.org/wiki/IA-64)
[`IQ2000`](http://www.ic72.com/pdf_file/v/165699.pdf)
[`M32C`](https://www.renesas.com/en-eu/products/microcontrollers-microprocessors/m16c.html)
[`M32R`](https://www.renesas.com/en-eu/products/microcontrollers-microprocessors/m32r.html)
[`M68k`](https://en.wikipedia.org/wiki/Motorola_68000_series)
[`M88k`](https://en.wikipedia.org/wiki/Motorola_88000)
[`MCore`](https://en.wikipedia.org/wiki/M%C2%B7CORE)
[`Mico32`](https://en.wikipedia.org/wiki/LatticeMico32)
[`MicroBlaze`](https://en.wikipedia.org/wiki/MicroBlaze)
[`MIPS16` `MIPSeb` `MIPSel`](https://en.wikipedia.org/wiki/MIPS_instruction_set)
[`MMIX`](https://en.wikipedia.org/wiki/MMIX)
[`MN10300`](https://en.wikipedia.org/wiki/MN103)
[`Moxie`](http://moxielogic.org/blog/)
[`MSP430`](https://en.wikipedia.org/wiki/TI_MSP430)
[`NDS32`](http://osdk.andestech.com/index.html)
[`NIOS-II`](https://en.wikipedia.org/wiki/Nios_II)
[`OCaml`](https://en.wikipedia.org/wiki/OCaml)
[`PDP-11`](https://en.wikipedia.org/wiki/PDP-11)
[`PIC10` `PIC16` `PIC18` `PIC24`](https://en.wikipedia.org/wiki/PIC_microcontroller)
[`PPCeb` `PPCel`](https://en.wikipedia.org/wiki/PowerPC)
[`RISC-V`](https://en.wikipedia.org/wiki/RISC-V)
[`RL78`](https://www.renesas.com/en-eu/products/microcontrollers-microprocessors/rl78.html)
[`ROMP`](https://en.wikipedia.org/wiki/ROMP)
[`RX`](https://www.renesas.com/en-eu/products/microcontrollers-microprocessors/rx.html)
[`S-390`](https://en.wikipedia.org/wiki/IBM_System/390_ES/9000_Enterprise_Systems_Architecture_ESA_family)
[`SPARC`](https://en.wikipedia.org/wiki/SPARC)
[`STM8`](https://en.wikipedia.org/wiki/STM8)
[`Stormy16`](https://sourceware.org/cgen/gen-doc/xstormy16.html)
[`SuperH`](https://en.wikipedia.org/wiki/SuperH)
[`TILEPro`](https://en.wikipedia.org/wiki/TILEPro64)
[`TLCS-90`](https://en.wikipedia.org/wiki/Toshiba_TLCS#90)
[`TMS320C2x` `TMS320C6x`](https://en.wikipedia.org/wiki/Texas_Instruments_TMS320)
[`TriMedia`](https://en.wikipedia.org/wiki/TriMedia_%28mediaprocessor%29)
[`V850`](https://en.wikipedia.org/wiki/V850)
[`VAX`](https://en.wikipedia.org/wiki/VAX)
[`Visium`](https://www.slideshare.net/AdaCore/controls-and-dataservices)
[`WASM`](https://en.wikipedia.org/wiki/WebAssembly)
[`WE32000`](https://en.wikipedia.org/wiki/Bellmac_32)
[`X86-64`](https://en.wikipedia.org/wiki/X86-64)
[`X86`](https://en.wikipedia.org/wiki/X86)
[`Xtensa`](https://en.wikipedia.org/wiki/Tensilica)
[`Z80`](https://en.wikipedia.org/wiki/Zilog_Z80)
[`#6502#cc65`](https://github.com/cc65/cc65)

Because of licencing issues, the following architectures are not in
the default corpus, but they can be manually added:
[`78k`](https://en.wikipedia.org/wiki/78K)
[`TriCore`](https://en.wikipedia.org/wiki/Infineon_TriCore)

# Licence
## The tool
The `cpu_rec.py` file is licenced under a Apache Licence, Version 2.0.

## The default corpus
The files in the default corpus have been built from various sources.
The corpus is a collection of various compressed files, each compressed
file is dedicated to the recognition of one architecture and is made by
the compression of the concatenation of one or many binary chunks, which
come from various origins and have various licences.
Therefore, the default corpus is a composite document, each sub-document
(the chunk) being redistributed under the appropriate licence.

The origin of each chunk is described in `cpu_rec.py`, in the function
`build_default_corpus`. The licences are:
- files `libgmp.so`, `libc.so`, `libm.so` come from Debian binary
distributions and are distributed under GPLv2 (and LGPLv3 for recent
versions of `libgmp`) and the source code is available from
http://archive.debian.org/.
- `busybox` binaries come from https://busybox.net/downloads/binaries/
and are distributed under GPLv2.
- `C-Kermit` binaries come from ftp://kermit.columbia.edu/kermit/bin/
and are distributed under GPLv2
(according to ftp://kermit.columbia.edu/kermit/archives/COPYING but
the status of each binary is not always clear).
- all files identified in `build_default_corpus` as part of the
`CROSS_COMPILED` subdirectory have been built by myself.
The corresponding source code are
`zlib` (from http://zlib.net/, distributed under the zlib licence)
or `libjpeg` (from http://www.ijg.org/, distributed under an unknown licence)
or some other code based on public sources
(e.g. https://anonscm.debian.org/cgit/pkg-games/bsdgames.git/tree/arithmetic/arithmetic.c modified to work with SDCC compilers).
- The `camlp4` binary is built from https://github.com/ocaml/camlp4
and distributed under LGPLv2.
- The binary for TMS320C2x comes from
https://github.com/slavaprokopiy/Mini-TMS320C28346/blob/master/For_user/C28346_Load_Program_to_Flash/Debug/C28346_Load_Program_to_Flash.out
where it is distributed under an unknown licence.
- The binary for RISC-V comes from https://riscv.org/software-tools/
distributed under GPLv2 and can downloaded at
https://github.com/radare/radare2-regressions/blob/master/bins/elf/analysis/guess-number-riscv64
- The binaries for PIC10 and PIC16 come from http://www.pic24.ru/doku.php/en/osa/ref/examples/intro
where they are distributed under an unknown licence.
- The binary for PIC18 comes from https://github.com/radare/radare2-regressions/blob/master/bins/pic18c/FreeRTOS-pic18c.hex
where it seems to be distributed under GPLv3 (or later).
- The binary for PIC24 comes from https://raw.githubusercontent.com/mikebdp2/Bus_Pirate/master/package_latest/BPv4/firmware/bpv4_fw7.0_opt0_18092016.hex
distributed under Creative Commons Zero.
- The binary for 6502 comes from https://raw.githubusercontent.com/RolfRolles/Atredis2018/master/MemoryDump/data-4000-efff.bin
and was distributed for the Atredis BlackHat 2018 challenge, under an unknown licence.
- The binary for H8S comes from https://github.com/airbus-seclab/cpu_rec/issues/4 and was distributed by Dell, under an unknown licence.
- The binary for TriMedia comes from https://github.com/crackinglandia/trimedia/blob/master/tm-linux/tmlinux-kernel-obj-latest.tar.bz2 where it is distributed under an unknown licence.
- The binary for CUDA comes from http://jcuda.org/samples/matrixInvert%200.0.1%20CUBIN%2032bit.zip where it is distributed under a MIT licence.
- The binary for WebAssembly comes from https://github.com/mdn/webassembly-examples/blob/master/wasm-sobel/change.wasm where it is distributed under a CC Zero licence.
- The reference for statistics of ASCII text comes from https://users.cs.duke.edu/~ola/ap/linuxwords with all LF replaced with NULL bytes.

## Other architectures that cannot be distributed in the default corpus
- A binary for Nec/Renesas 78k can be found at https://www.metz-mecatech.de/en/lighting/firmware-download-flash-units/mecablitz-50-af-1-digital.html where it is distributed under a restrictive licence. The file named `MB50AF1_NikonV12.mtz` is a nibble-swapped Intel-HEX firmware (cf. https://debugmo.de/2011/10/whats-inside-metz-50-af-1-n/) with 0x7d5a bytes of 78k code starting at offset 0x2ba.
- An example of binary for TriCore is the firmware of the ECU of Volkswagen cars. This firmware is distributed under a restrictive licence not allowing redistribution, at https://erwin.volkswagen.de/erwin/showHome.do where it can be downloaded at no cost after the creation of a free account.
