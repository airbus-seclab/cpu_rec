# cpu_rec.py — scientific paper
Louis Granboulan, Airbus

# Why: automatic recognition of CPU
During the security analysis of a product that includes software, it is useful to be able to reverse-engineer some software, especially binary code (executables or libraries).
To be able to disassemble a binary, one needs to know which is the CPU target: what is the ISA (*Instruction Set Architecture*).

This need is common, and therefore Airbus Group Innovations proposed this problem at [REDOCS2016](http://confiance-numerique.clermont-universite.fr/redocs2016/) and provided a corpus of various binaries containing various architectures. The participants to REDOCS2016 (Sebanjila Kevin Bukasa, Benjamin Farinier, Omar Jaafor, and Nisrine Jafri) have experimented multiple techniques; I have implemented another technique, which results in an efficient tool.

Most files containing binary code are containers (PE, ELF, Mach-O, COFF) who indicate what is the target architecture et where are the executable instructions (*text* section), but many embedded software use non-standard file format where this information is not available.
To identify which is the architecture, many reverse-engineers use a disassembler (e.g. IDA Pro) and try every architecture known by the disassembler, and guess whether the resulting assembly code is meaningful, or not.
The tool `cpu_rec.py` avoids this lengthy process and outputs what is the architecture and where are the executable instructions. Because this tool is based on statistical methods, its output is not 100% reliable, and one needs to validate the result using a disassembler; but one needs only to use the disassembler once.

# How: statistical analysis with sliding windows
## Statistical analysis
### Statistical analysis is relevant to recognise which cpu is used
There exists a lot of families of cpus, with very different designs. But each cpu includes a decoder, qui inputs the instructions, analyse them and sends them to the appropriate computing unit. Whether it is a cpu with fixed-size instructions (typically 4 bytes for most RISC cpus) or a cpu with variable-size instructions (the Intel x86 family being the most common CISC cpu), the decoder starts by looking at the first byte to know which type of instruction it is.
This way of working implies that each architecture (ISA) has a statistical signature: depending on the value of the first byte of an instruction, the distribution of the next bytes is not a uniform distribution.
This statistical signature does not only depends on the architecture, it also depends on how the software is built, e.g. on the compiler, because some sequence of instructions may have higher probability (e.g. start or end of functions) and some instructions include numeric constants whose values depend on the software (e.g. distance of relative jumps or constants written in registers).

### Choosing a machine learning technique
Learning a statistical signature is typically done with *machine learning*. By using the [scikit-learn](http://scikit-learn.org/) library, one can test many techniques of statistical learning.

In the analysis, the binary code is seen as a sequence of bytes, and the straightforward approach is based in the [bag of words model](https://en.wikipedia.org/wiki/Bag-of-words_model) which has been developed to analyse texts in natural language, and can be extended to computer languages such as the cpu instructions.

The tutorial at http://scikit-learn.org/stable/tutorial/text_analytics/working_with_text_data.html is a nice introduction to text classification techniques.
Statistical learning works better when the corpus used to learn the statistical signature is large.
Experimentation with scikit-learn showed that for exotic architectures, the corpus that is available is too small, and no better method than Multinomial Naive Bayes of n-grams has been found.
More detail on this experimentation is available in appendix

Because the available corpus is of insufficient quality, a way to measure the confidence in the result of the classifier is needed. This will allow to detect when we are facing an unknown architecture, and it will allow to eliminate from the corpus some invalid data that introduces perturbations.
The problem is that Multinomial Naive Bayes is known to be a good classifier but cannot provide any measure of confidence.
Another technique is needed.

Applying Multinomial Naive Bayes to n-grams gave good results, therefore a natural candidate is the computation of a "distance" between the distribution of n-grams in the binary and the distribution of n-grams in every known architecture.
The Kullback-Leibler divergence (also named relative entropy, and shortened KLD in this document) is such a "distance" between distributions, and a "Kullback-Leibler classifier" can output the name of the known architecture which is the closest to the binary.
In practice, if the corpus is sufficiently uniform (meaning that the size of the corpus for each architecture does not vary much), the Kullback-Leibler classifier on n-grams distributions outputs the same results as the Multinomial Naive Bayes on n-grams, and provides a measure of confidence.

The computation of the KLD is not available in scikit-learn, therefore `cpu_rec.py` avoids any dependency to scikit-learn and includes its own implementaion of sparse data structures and computation of statistical signatures.
From a performance point of view, `cpu_rec.py` is faster than using MultinomialNB in scikit-learn, but is slower than an implementation in C. For example, on a standard MacBook, with a corpus containing 70 architectures, `cpu_rec.py` takes 25 seconds and 1Gb of RAM to create the signatures, `scikit-learn` takes 90 seconds and 1Gb, and `cpu_rec.c` takes 10 seconds and 8Gb (because it does not use sparse data structures).
After the corpus has been loaded, the analysis of a binary file takes 60 seconds per Mb of file.

Depending on the architectures, a meaningful statistical signature includes the distribution of n-grams for various values of n (2, 3, 4, ...) and possibly some other statistics.
But the corpus available for some architectures is too small, and for these architectures only the frequencies of bigrams and trigrams can be measured. Therefore `cpu_rec.py` does not compute other statistics.

More precisely, `cpu_rec.py` computes the KLD for bigrams and for trigrams between the binary and all known architectures. If the closest architecture for bigrams is not the same as the closest architectures for trigrams, then it is likely that `cpu_rec.py` cannot recognise the architecture. In that case, `cpu_rec.py` can display debug messages with all KLD values: this is very useful when adding a new architecture to the corpus, to check that this new architecture does not pertubate the recognition of other architectures.

### What can be recognised with this statistical analysis
In conclusion, `cpu_rec.py` uses its own definition of what an "architecture" is: an architecture is a statistical property of bigrams and trigrams in a binary.

In theory, the same cpu could be recognized as distinct architectures, for example if the choice of a compiler changes these statistical properties.
For example, the output of the 6502 compiler available at https://github.com/cc65/cc65 is very different from "normal" 6502 software.
But this is an exception: for example, the corpus for Intel x86 is based on software compiled with gcc, and it recognises efficiently software compiled with Visual Studio or Clang-LLVM.

Some similar cpus are different architectures (e.g. 64-bit code for x86 is different from 32-bit code, because of the heavy use of REX prefixes) and some other similar cpus are the same architecture (e.g. PowerPC or SPARC don't differ whether they are used with their 32-bit of 64-bit variants).
Morevover, intensive use of specific cpu instruction sets such as SSE/AltiVec/VIS/Thumb changes the statistical properties of the code. For example, Debian's ARM hard float binaries are different from regular ARM binaries.

## Sliding windows
For binaries that are not in a standard container (PE, ELF, Mach-O, COFF) there may be no information on where is the executable code.
Therefore `cpu_rec.py` needs to find where is the code and where is the rest (data, relocations, debug, ...)
It is common to have some data interleaved with code (e.g. switch tables); if these chunks of data are big enough, `cpu_rec.py` will detect them and consider that there are multiple sections of executable code.

To achieve this goal, the statistical analysis described above is not made on the whole binary: it is made on a sliding window. The size of this window should be small enough to contain only code (so that the statistics are not perturbated by non-code) and big enough to provide meaningful statistics.
Heuristically, a size of 0x1000 bytes is OK.
For small binary files, `cpu_rec.py` reduces the size of the window (with a minimum of 0x80 bytes) but its results are less reliable.

One more heuristic is used: one of the architectures know by the tool is OCaml bytecode.
The statistical signature of OCaml is close to the statistical signature of non executable sections in standard containers, but the KLD between OCaml bytecode is very small. Therefore, if the tool recognises some chunk as OCaml, it is output as OCaml only if the KLD is very small, else the tool considers that non architecture has been recgnised, because it is very likely that this is a non executable section.

# Raw material: the creation of the corpus
As mentioned above, a few hundreds kilobytes is needed to be able to learn the statistical signature of an architecture.

The first available binaries are the ones that can be freely donwloaded.
For example, Linux distributions or busybox binaries allow to learn the signature of the most common architectures (x86, ARM, MIPS, ...) and C-Kermit allows to learn the signature of many antique architectures (m88k, we32k, Cray, ...)

For some other architectures, e.g. V850, no free binary was found, but a gcc cross-compiler could generate binaries, from an open source code such as zlib or libjpeg.
Cross-compilation has been the most difficult for 8-bit microprocessors with small RAM and ROM, because it is not feasible to generate one binary of a few hundreds kilobytes. One needs to generate multiple small files.
In the default corpus of `cpu_rec.py`, sometimes a big file has been simulated by repeating a small file.

In the current version of the tool, the default corpus recognises 72 architectures:
68HC08, 68HC11, 8051, ARM64, ARMeb, ARMel, ARMhf, ARcompact, AVR, Alpha, AxisCris, Blackfin, CLIPPER, Cell-SPU, CompactRISC, Cray, Epiphany, FR-V, FR30, FT32, H8-300, HP-Focus, HP-PA, IA-64, IQ2000, M32C, M32R, M68k, M88k, MCore, MIPS16, MIPSeb, MIPSel, MMIX, MN10300, MSP430, Mico32, MicroBlaze, Moxie, NDS32, NIOS-II, OCaml, PDP-11, PIC10, PIC16, PIC18, PIC24, PPCeb, PPCel, RISC-V, RL78, ROMP, RX, S-390, SPARC, STM8, Stormy16, SuperH, TILEPro, TLCS-90, TMS320C2x, TMS320C6x, V850, VAX, Visium, WE32000, X86, X86-64, Xtensa, Z80, i860, and 6502.

More details on this corpus and on how to build a corpus can be found below, in an appendix.

# A binwalk module
Because using http://binwalk.org/ is the standard first step in the analysis of an unknown firmware, the `cpu_rec.py` tool can be used as a binwalk module.
binwalk is made of various standard modules, each module being extensible with user-defined plugins. Because none of the standard modules could manage the addition of a statistical analysis to recognise architectures, a modification of binwalk has been needed: https://github.com/devttys0/binwalk/pull/241 .

With a recent binwalk, one needs only to copy `cpu_rec.py` and `cpu_rec_corpus` in `$HOME/.config/binwalk/modules`, and to launch `binwalk` with option `-%`.
Because the default corpus is compressed with `xz`, either the `lzma` module need to be installed with python, or the corpus has to be uncompressed.

The output of the tool will be similar to:

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

If architecture detection fails, to output will be similar to:

```
shell_prompt> binwalk -% unknown/140

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             None (size=0xb400)
46080         0xB400          MMIX (size=0x80)
46208         0xB480          NDS32 (size=0x80)
46336         0xB500          None (size=0x14a80)
```

One can noticed that, when analysing `PPC/NTDLL.DLL`, a small chunk as been mentioned as being IA-64. The cause of this mistake is that the statistical signatures of IA-64 and of data sections are close. It is possible to add specific additional analysis for IA-64, like it has been done for OCaml, but the rare occurences of IA-64 don't justify to deviate from using a generic statistical method.

The tool can also be use standalone, without binwalk. Its output is slightly different: in addition to the analysis with a sliding window, there is also the analysis of the whole file, plus (if possible, using https://github.com/airbus-seclab/elfesteem which understands ELF, PE, Mach-O and COFF) an analysis of the executable section.
Adding once or twice the option `-v` outputs additional information such as other suggested architectures than the preferred one. Increasing verbosity is very useful when adding a new architecture to the corpus, to analyse the impact of this addition.

```
shell_prompt> cpu_rec.py corpus/PE/PPC/NTDLL.DLL corpus/MSP430/goodfet32.hex                                                                  
corpus/PE/PPC/NTDLL.DLL       full(0x75b10)None    text(0x58800)PPCel chunk(0x4c800;153)PPCel 
corpus/MSP430/goodfet32.hex   full(0x61ac) None                       chunk(0x5200;41)  MSP430    
```

Adding new architectures can be made by adding new files in `$HOME/.config/binwalk/modules/cpu_rec_corpus`  or by modifications of the method `read_corpus` in `cpu_rec.py`.

# Conclusion and perspectives

The `cpu_rec.py` tool implements a practical technique to recognise cpu architectures in an arbitrary binary file, and indicates approximately where executable code sections are located.
It is a new help for binary file analysis, and can be used as an extension of `binwalk`.

It does not aim at finding precisely where the cpu instructions are located, it is an help when the architecture is unknwon and unusual.

The tool being available under an Open Source Apache 2.0 licence, its corpus can be extended with new architectures. Any user of the tool can extend its own corpus, but it is recommended to share information on new architectures, so any one can benefit of it.

This tool is not the only one that was missing in the toolbox of someone needing to analyse binaries. Other tools, specialised for some architectures, can be expected:
* A tool that detects precisely at with byte(s) the excutable code starts. For example, the heuristics of IDA, used when there is no entry point nor function symbols, are not sufficiently reliable (they do linear disassembly until finding invalid instructions or patterns of prologues or ends of functions). One needs to enhance these heuristics with trial and errors.
* A tool that recovers the memory address where the executable sections are loaded; note that for PIE (Position Independent Executable) this is a meaningless question, but for many embedded software this information is useful.
* A tool dedicated to ARM. There are many variants of ARM code, and `cpu_rec.py` statistical analysis is not precise enough to detect the difference between them.

# Thanks

First thanks to Raphaël Rigo, who described the need of such a tool, and who collected the first corpus that I have used to experiment and find the best approach to answer this need.

Various other people made me understand that my initial idea (computing the distance between Markov chains) is not really a machine learning technique, they mentioned `scikit-learn` as the easiest way to begin experimentation with machine learning, and also mentioned the Kullback-Leibler Distance which is what I was looking for. In alphabetical order, they are:
Guillaume Charpiat, Vincent Feuillard, Pierre Senellart, and Mehdi Tibouchi.
Thanks also to the proof-readers of the original French version of this paper:
Philippe Biondi, Anaïs Gantet, and Raphaël Rigo.

# Other references

The oldest requests for a tool that automatically recognises the architecture that I have found is in [2011](https://debugmo.de/2011/10/whats-inside-metz-50-af-1-n/), but the need is certainly older.

Note that the idea of counting bigrams and trigrams was already published in [2013](https://reverseengineering.stackexchange.com/questions/2897/tool-or-data-for-analysis-of-binary-code-to-detect-cpu-architecture).

This idea also appeared in a research paper in [2015](https://arxiv.org/abs/1805.02146v1), which describes a complete strategy for architecture recognition, mainly based on the histogram of bytes.
They did not publish their reference corpus, and it is not clear how well they can deal with binaries not generated by the compiler used for training and how they behave when analysing a file where the executable section is a small part of the file.

A study in [2013](https://scholar.afit.edu/etd/904/) aims at recognizing code between ARM, M68k, PPC and AVR. Various techniques are evaluated: decision tree on 4-bytes values, or statistical analysis. The corpus is not public either.

The [ELISA](https://www.researchgate.net/publication/325641416_ELISA_ELiciting_ISA_of_Raw_Binaries_for_Fine-Grained_Code_and_Data_Separation) tool has also some similarities with `cpu_rec`, and aims at separating code and data, which of course is helpful to increase the reliability of the architecture recognition.

If you like exotic architectures that are not in the scope of `cpu_rec`, you may be interested by [the cLEMENCy Architecture](https://blog.legitbs.net/2017/07/the-clemency-architecture.html).


# Appendix: experimentations with statistical learning

During the development of `cpu_rec` I experimented the other methods described below, which were less efficient than the method retained for publication.

## Other machine learning techniques
Rather than using directly the Multinomial Naive Bayes technique, it is usually recommended to compensate the differences in corpus size by using for example a TF-IDF transform.
Experiments showed that the recognition capability of the tool is diminished a lot by using TF-IDF.
The technique I have used (manual repetition of training data for architectures with very small corpus) is sufficient to avoid the bad consequences of adding a new architecture with small corpus.

Other classifiers have been tested than Multinomial Naive Bayes, and none gave better results.
Nevertheless, it is very likely that in the hundreds of existing classification techniques, there are some that will perform better than what `cpu_rec` is doing.
But the very small size of corpus available for some exotic architectures is an explanation why common classification techniques don't perform well.

## Statistics modulo 4
32-bit RISC architectures have 4-octets long instructions, aligned on addresses that are multiple of 4. This property could be used.
But neither using 4-grams, nor computing statistics that depend on the position modulo 4, give better results than the current tool, mainly because it needs a sliding window larger than what we can afford in our context.

## Detecting RISC architectures
On idea to detect if the instructions have all the same length `n` is to compute the statistical distributions of values having the same address modulo `n`. If these distributions differ, then it is likely that the length of instructions divides `n`.

This approach is very efficient to detect 32-bit RISC architectures, if the *text* section has been isolated.
In practice, it would only be useful to detect an unknown 32-bit RISC architecture, and most of the work is still to be done.

## Looking for atypical patterns
Some 3-octet or 4-octet sequences, or some other specific patterns are unique to a given architecture.
Usual examples are sequences of instructions used at the beginning or the end of a function.
One way to find these sequences is by statistical analysis of the corpus.
Below are some sequences that allow to recognize some architectures with high confidence
(even if IA-64 patterns generate false positives in data section, because they have two null octets):
```
55 89 e5      X86     push %ebp; mov %esp,%ebp
55 57 56      X86     push %ebp; push %edi; push %esi
41 57 41 56   X86-64  push %r15; push %r14
41 55 41 54   X86-64  push %r13; push %r12
55 48 89 e5   X86-64  push %rbp; mov %rsp,%rbp
0e f0 a0 e1   ARMel   ret     (generated by gcc 4.x)
1e ff 2f e1   ARMel   bx lr   (generated by gcc 3.x)
6b c2 3f d9   HP-PA   stw %rp, -cur_rp(%sp)
4e 5e 4e 75   M68k    unlk a6; rts
ff bd 67      MIPSel  daddiu $sp, -X
ff bd 27      MIPSel  addiu $sp, -X
67 bd ff      MIPSeb  diaddu $sp, -X
67 bd 00      MIPSeb  diaddu $sp, +X
03 99 e0 21   MIPSeb  addu $gp, $t9
4e 80 00 20   PPCeb   blr
81 c3 e0 08   sparc   retl
60 00 80 00   IA-64   br.few b6
08 00 84 00   IA-64   br.ret.sptk.many b0
```

This approach gives faster results than using `cpu_rec` but it is not as generic.
For example, because `cpu_rec` uses the probabilities of trigrams, the pattern `55 89 e5` above is automatically taken into account as specific to X86, but if the compiler that was used never produced a `push %ebp; mov %esp,%ebp` then `cpu_rec` will use other elements and recognise the architecture anyway.
A concrete example is ARMel recognition, where the corpus used by `cpu_rec` was compiled by gcc 3.x only, but it is sufficient to regognize binaries compiled with gcc 4.x, which don't contain the instruction `bx lr`.


# Appendix: how cpu_rec corpus was built

The corpus is probably the most important element of `cpu_rec`, and collecting this corpus has been most of the work. Because of the difficulty to find samples of binaries from exotic architectures, the tool has been designed such that only short samples are necessary, a few hundreds of kilobytes only.

The method `build_default_corpus` in `cpu_rec.py` can build the corpus from the source files.
These source files are not provided with the tool, but the description below explains how they were chosen.

Any addition to the corpus is welcome!

## Various binaries found on the web
### Origin of the binaries
As mentioned in the introduction, a corpus of various binaries was provided by Airbus Group Innovations for REDOCS2016.
In this corpus, there were many ELF binaries. Some of them have been selected to train the tool for the most common architectures. They are the 'ELF' lines in `build_default_corpus`.
These files are some versions of `libgmp.so`, `libm.so`, or `libc.so` from Debian distributions for x86, x86_64, m68k, PowerPC, S/390, SPARC, Alpha, HP-PA, MIPS and some variants of ARM.
Note that the source code of these binaries is available at http://archive.debian.org/.
The method `add_training` used in `build_default_corpus` extract the `.text` section of the ELF library, using https://github.com/airbus-seclab/elfesteem
In this corpus, there were also `busybox` executables, which have been used for two architectures: ARM big endian and SH-4. Busybox binaries are available at https://busybox.net/downloads/binaries/

For less common architectures, ftp://kermit.columbia.edu/kermit/bin/ includes many binaries. This has been used to add to the corpus M88k, HP-Focus, Cray, Vax, PDP-11, ROMP, WE32k, CLIPPER, and i860.
Some of the C-Kermit binaries are in COFF format, and elfesteem can extract the .text section; some other binaries are in undocumented formats, and finding where is the executable code has been manually done by analyzing the output of `cpu_rec` in verbose mode. This results in the `section=slice(a,b)` argument of `add_training`.

For TMS320C2x, the REDOCS2016 contained a firmware in COFF format, which can be downloaded at https://github.com/slavaprokopiy/Mini-TMS320C28346/blob/master/For_user/C28346_Load_Program_to_Flash/Debug/C28346_Load_Program_to_Flash.out

### Why usually only one binary is sufficient
For almost all the architectures mentioned above, a unique binary has been used to generate the corpus.
This is not the way machine learning techniques are supposed to work, but in the context of `cpu_rec` we cannot make the assumption that more than one binary will be available for the corpus.
Using only one binary even when many binaries are available (e.g. x86) validates the efficiency of `cpu_rec` on exotic architectures.

As mentioned above, ARMel code generated with gcc 4.x is very different from ARMel code generated by gcc 3.x, e.g. returning from a function uses a differnet instruction. The corpus is trained with one libgmp compiled with gcc 3.x, yet the tool can easily recognize binaries compiled with gcc 4.x.
Another example is the CLIPPER architecture, where `cpu_rec` is trained on one binary from C-Kermit, and can detect that `boot.1` file from https://web-docs.gsi.de/~kraemer/COLLECTION/INTERGRAPH/starfish.osfn.org/Intergraph/index.html is containing CLIPPER instructions.

## Cross-compiled binaries for architectures known by gcc.gnu.org
The REDOC2016 corpus did not contain examples for all architectures known by gcc.
Small open-source projects have been cross-compiled, and the result is the 'CROSS_COMPILED' lines in `build_default_corpus`.

### Installing a cross-compilation environment
There are many architectures known to the gcc compiler at gcc.gnu.org, and for some of them building the cross-compiler has not been straightforward.
```
aarch64      OK
alpha      
arc          OK
arm      
avr          OK
bfin         OK
c6x          OK, bug of gcc when building libjpeg
cr16         OK, bug of gcc when building libjpeg
cris         OK
epiphany     OK
fr30         OK
frv          OK
ft32         OK
h8300        OK
i386      
ia64         OK
iq2000       OK
lm32         OK
m32c         OK
m32r         OK
m68k      
mcore        OK
microblaze   OK
mips         OK
mmix         OK, with TARGET=mmix (not mmix-elf)
mn10300      OK
moxie        OK
msp430       OK, but fails making valid executables
nds32be      OK
nds32le      OK, very similar to BE version
nios2        OK
nvptx        OK, but does not generate binaries, only "assembler"
pa      
pdp11        KO, cannot generate pdp11 assembly
rl78         OK
rs6000      
rx           OK
s390      
sh           OK, but fails in generating divisions
sparc      
spu          OK
tilegx       KO, tilepro/gen-mul-tables.cc is invalid
tilepro      OK, but many bugs
v850         OK
visium       OK
xstormy16    OK
xtensa       OK
```

My main computer was running MacOSX, but the same approach should work with Linux.
The first step is to install binutils and the compiler, with the following instructions:

```
export PREFIX=$BASEDIR/cross
export PATH="$PREFIX/bin:$PATH"
mkdir -p $BASEDIR/corpus $PREFIX
cd $BASEDIR
git clone git://sourceware.org/git/binutils-gdb.git
svn checkout svn://gcc.gnu.org/svn/gcc/trunk gcc

# the list of known architectures is in gcc/gcc/config
export TARGET=v850-elf

mkdir $BASEDIR/build-binutils-$TARGET
cd $BASEDIR/build-binutils-$TARGET
../binutils-gdb/configure --target=$TARGET --prefix="$PREFIX" \
    --with-sysroot --disable-nls --disable-werror
make
make install

mkdir $BASEDIR/build-gcc-$TARGET
cd $BASEDIR/build-gcc-$TARGET
../gcc/configure --target=$TARGET --prefix="$PREFIX" \
    --disable-nls --enable-languages=c --without-headers \
    --with-libiconv-prefix=/usr --with-gmp=/opt/local
make all-gcc
make all-target-libgcc
make install-gcc
make install-target-libgcc
```

Once binutils and gcc have been installed, it is not sufficient to compile a complete software (e.g. zlib) because no libc has been installed.

The standard approach for cross-compilation is to install additional elements, that depend on the target architecture. These can be libgloss of libnosys. https://github.com/32bitmicro/newlib-nano-1.0/ contains many interesting elements.
Sometimes the target architecture has no FPU, and therefore functions such as `__divsf3` need to be provided, either by a libm or a libc.

I did not follow the standard approach, I generated empty stubs. This allows to be able to cross-compile executables for architectures unknown of newlib, e.g. H8/300 or FTDI FT32.

### Cross-compiling zlib and libjpeg
These two software have been chosen because they mainly do computations, and therefore don't interact much with the operating system.
The command line to be used for cross-compiling depends on the software to compile, and only one binary for each software has been used in the corpus: minigzip for zlib, and jpegtran for libjpeg.

A typical cross-compilation, for V850, is:
```
TARGET=v850-elf

ZLIB=zlib-1.2.10
curl -O http://zlib.net/$ZLIB.tar.gz
tar xzf $ZLIB.tar.gz
cd $ZLIB
CROSS_PREFIX=$TARGET- uname=cross ./configure
make clean
make CC="$TARGET-gcc $CFLAGS"
cp minigzip .../minigzip-$TARGET

curl -O http://www.ijg.org/files/jpegsr6b.zip
unzip -x jpegsr6b.zip
cd jpeg-6b
perl -pi -e 's/\r$//' ./configure
CC="$TARGET-gcc $CFLAGS" ./configure
make clean
make AR="$TARGET-ar rc" AR2="$TARGET-ranlib"
cp jpegtran .../jpegtran-$TARGET
```

In some cases (c6x, cr16, epiphany, rl78, tilepro) the above procedure does not work, because the gcc compiler fails with `internal error` or `SEGV`.
These bugs can be avoided by modifying the source code of zlib or libjpeg to remove what triggers the bug.
In addition, when building executables for RL78 ou MSP430 (with option `-mlarge`) the result does not have a valid .text section. Object files have been used for the corpus, instead of the executable.

All these elements appear in the relevant `add_training` line in `build_default_corpus`.

## Other cross-compilers
There exist cross-compilers based on gcc but not available at gcc.gnu.org.
One example the the gcc+newlib toolchain available at https://riscv.org/software-tools/
One binary in this toolchain is the source of the corpus for RISC-V.

For many 8-bit architecture, there is not enough memory to be able to implement zlib or libjpeg.
Instead of zlib or libjpeg, small arbitrary C programs have been compiled: `tea` (the TEA cipher), `arithmetic` (simple arithmetic operations), `path` (path finding in graphs).
To have a better corpus, more should have been used.

The cross-compiler for MC68HC11 available with Ubuntu 12.04 has been used.

The compiler available ar http://sdcc.sourceforge.net/ can build binaries in HEX format, for many variants of 8051 (mcd51, ds390, ds400) and Z80 (z80, z180, r2k, r3ka), for STM8, and also ELF binaries for MC68HC08 (hc08, s08).
Note that when `-mtlcs90` is used, the result is not detected by `cpu_rec` as being Z80 code, which is surprising because the TLCS 90 is binary compatible with the Z80. Therefore our corpus considers that Z80 and TLCS-90 are different architectures. Note that TLCS 900 is not binary compatible with Z80, but is not known to SDCC.

For the 6502 architecture, there is a compiler at https://github.com/cc65/cc65, but the code generated from a C source is very regular and unlike any normal 6502 code. Therefore this is a specific architecture named `#6502#cc65`.

## When there is no cross-compiler
For example, there seem to be no open-source compiler that generates PIC code (SDCC has options `-mpic16` and `-mpic14` but they don't work).
We needed to find binaries for the many variants of PIC (mainly PIC10, PIC16, PIC18 and PIC24), by looking on the web for binaries with non restrictive distribution licences.

For some other architectures (e.g. 78k and TriCore) the only binaries found cannot be redistributed as part of `cpu_rec` corpus.

## About the quality of the corpus
### How the quality of the current corpus has been evaluated
It has to be discriminating: two different architectures shall correspond to two different statistical behaviours.
To satisfy this criterion, each architecture has been precisely studied before being added to the corpus.

For example, SPARC architecture was first trained on SPARC v7 binaries (old 32-bit variant) and then `cpu_rec` has been used on SPARC v9 binaries (64-bit, with extended instruction set). Most of the SPARC v9 binaries have been recognized as SPARC, therefore the first conclusion is that these two architectures are close.
Then the corpus has been trained on SPARC v9 binaries too. With this new corpus that aimed at make the difference between v7 and v9, `cpu_rec` failed at making the difference: v7 binaries were recognised as v7 or v9, and v9 binaries were recognized as v7 or v9.
The conclusion is that doing statistics on bigrams and trigrams is not sufficient to differentiate v7 and v9, and therefore `cpu_rec` has only one SPARC architecture, trained on both v7 and v9.
Another tool is needed to make the difference.

For a given architecture, the training data has to be large enough, such that counting bigrams and trigrams is sufficient to derive a signature specific of this architecture.
When adding to the corpus an architecture with a training data that is too small, then `cpu_rec` starts to output erroneous answers for other architectures. Sometimes, this adverse effect is avoided by repeating the training data (option `repeat` in `add_training`) because of the way the Kullback-Leibler is computed. Sometimes the training data is really too small and the architecture cannot be added.

### How to improve the quality of the corpus.
A first improvement is to have better training data for some existing architectures.
One way to know which architecture need to be improved is to look at the size of the xz-compressed corpus, because the smallest are the ones that contain the less information.
The priority order is: PIC10, 6502, CUDA, STM8, PIC16, PIC18, TMS320C2x, then Z80, WASM, 68HC08, TLCS-90, 68HC11 and 8051.

The other improvement is by adding new architectures.
Some examples of missing architectures, taken from various lists (https://en.wikipedia.org/wiki/Microprocessor, https://en.wikipedia.org/wiki/List_of_instruction_sets, https://en.wikipedia.org/wiki/Comparison_of_instruction_set_architectures, https://en.wikipedia.org/wiki/Digital_signal_processor, and https://github.com/larsbrinkhoff/awesome-cpus) are:
6800 (if different of PDP-11 and 68HCx),
6809 (if the new opcodes make it a different architecture from 6800),
8080 (including 8085),
AM29k (from AMD),
B5000 (from Burroughs),
CDC-* (Cray's first supercomputers),
CEVA-XC, CEVA-X, CEVA-Teaklite,
DSP56k (from Motorola),
Elbrus VLIW,
eSi-RISC,
F8 (from Fairchild),
F18A (from GreenArrays),
HD6301 (from Hitachi),
KDF9 (from English Electric),
i960,
MARC4 (from Eurosil/Temic/Atmel),
MCS-48 (from Intel),
Mico8,
MSC81xx (from Freescale),
OpenRISC,
PDP-1, PDP-7, PDP-8, PDP-10,
%PIC10 (incl. PIC12), PIC16,
PSC1000 (aka. Ignite, aka. ShBoom),
Propeller (aka. Parallax P8X32A)
RTX2000 (from Harris),
S1C6x (from Epson),
Saturn (from HP scientific calculators),
SHARC (from Analog Devices)
Signetics 2650,
SPC (Sunplus S+Core )
SystemZ (if different from S/390),
TMS320C1x, TMS320C3x, TMS320C5x,
Transputer (from Inmos),
xCore (from XMOS).
