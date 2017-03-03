# Description
`cpu_rec` is a tool that recognizes cpu instructions
in an arbitrary binary file.
It can be used as a standalone tool, or as a plugin for binwalk
(https://github.com/devttys0/binwalk).

# Installation instructions
## Standalone tool
1. Copy `cpu_rec.py` in the directory of your choice.
2. Unpack the standard corpus archive `cpu_rec_corpus.tar` in the same
   directory; this will create a `cpu_rec_corpus` directory with each
   corpus file compressed with `xz`.
3. If you don't have the `lzma` module installed for your python (this
   tool works either with python3 or with recent python2) then you
   should `unxz` the corpus files.
4. If you want to enhance the corpus, you can add new data in the
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

## As a standalone tool
Just run the tool, with the binary file(s) to analyze as argument(s)
The tool will try to match an architecture for the whole file, and
then to detect the largest binary chunk that corresponds to a CPU
architecture; usually it is the right answer.

If the result is not satisfying, prepending twice `-v` to the arguments
makes the tool very verbose; this is helpful when adding a new
architecture to the corpus.

If https://bitbucket.org/LouisG/elfesteem is installed, then the
tool also extract the text section from ELF, PE, Mach-O or COFF
files, and outputs the architecture corresponding to this section;
the possibility of extracting the text section is also used when
building a corpus from full binary files.

Option `-d` followed by a directory dumps the corpus in that directory;
using this option one can reconstruct the standard corpus archive.

# Examples
Running the tool as a binwalk module typically results in:
```
shell_prompt> binwalk -% corpus/PE/PPC/NTDLL.DLL corpus/MSP430/goodfet32.hex

Target File:   .../corpus/PE/PPC/NTDLL.DLL
MD5 Checksum:  d006a2a87a3596c744c5573aece81d77

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             None (size=0x5800)
22528         0x5800          PPCel (size=0x4c800)
335872        0x52000         None (size=0x1000)
339968        0x53000         IA-64 (size=0x800)
342016        0x53800         None (size=0x21800)

Target File:   .../corpus/MSP430/goodfet32.hex
MD5 Checksum:  4b295284024e2b6a6257b720a7168b92

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             MSP430 (size=0x5200)
20992         0x5200          None (size=0xe00)
```

We can notice that during the analysis of `PPC/NTDLL.DLL`
a small chunk has been identified as `IA-64`.
This is an erroneous detection, due to the fact that
the IA-64 architecture has statistical properties similar
to data sections.

# Licence
## The tool
The `cpu_rec.py` file is licenced under a Apache Licence, Version 2.0.

## The default corpus
The files in the default corpus have been built from various sources.
The corpus is a `tar` archive of various compressed files, each compressed
file is dedicated to the recognition of one architecture.
Each compressed file is made by the compression of the concatenation
of one or many binary chunks, which come from various origins and have
various licences.
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
ditributed under GPLv2.
- The binaries for PIC10 and PIC16 come from http://www.pic24.ru/doku.php/en/osa/ref/examples/intro
where they are distributed under an unknown licence.
- The binary for PIC18 comes from https://github.com/radare/radare2-regressions/blob/master/bins/pic18c/FreeRTOS-pic18c.hex
where it seems to be distributed under GPLv3 (or later).
- The binary for PIC24 comes from https://raw.githubusercontent.com/mikebdp2/Bus_Pirate/master/package_latest/BPv4/firmware/bpv4_fw7.0_opt0_18092016.hex
distributed under Creative Commons Zero.
