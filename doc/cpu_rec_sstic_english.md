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


# Appendix: experimentations with statistical learning

__LATEX SOURCE IN FRENCH - TO BE TRANSLATED LATER__

Lors de la conception de \texttt{cpu\_rec.py}, j'ai expérimenté avec les quelques autres méthodes ci-dessous,
qui sont moins efficaces en pratique que la méthode retenue.

\paragraph{Autres techniques d'apprentissage.}
Au lieu d'utiliser directement la technique \emph{Multinomial Naive Bayes}, il est habituellement recommandé de compenser les différences de taille de corpus en utilisant par exemple une transformation TF-IDF. En pratique cela a beaucoup diminué la capacité de reconnaissance de l'outil, et la technique utilisée (répétition manuelle des entrées pour les architectures ayant un trop petit corpus) permet d'éviter la plupart des effets nocifs au moment de l'ajout d'une nouvelle architecture.

D'autres classifieurs ont été testés et n'ont pas donné de meilleurs résultats.
Néanmoins, il est probable que parmi les nombreux outils de classification existants, certains seront plus performant que celui utilisé par \texttt{cpu\_rec.py}.
Et si le corpus sur lequel apprendre les architectures exotiques était plus large, ces méthodes pourraient devenir intéressantes.

\paragraph{Statistiques modulo 4.}
Les architectures RISC 32-bits ont toutes leurs instructions de longueur 4 octets et alignées sur des adresses multiples de 4.
Mais l'utilisation de 4-grammes, ou bien le calcul de statistiques différentes selon l'adresse modulo 4, ne donnent pas de meilleurs résultats que l'outil actuel, en particulier parce que cela demande que la fenêtre glissante soit plus longue que ce qui est permis par les statistiques de bigrammes et trigrammes. 

\paragraph{Détection d'architecture RISC.}
Pour détecter si la longueur des instructions est $n$, on peut calculer la distribution des $n$ sous-ensembles contenant les octets dont l'adresse a une valeur fixée modulo $n$. Si les distributions de ces $n$ sous-ensembles sont suffisamment différentes, alors il est probable que la longueur des instructions soit un diviseur de $n$.

Cette approche marche assez bien pour détecter si une architecture est RISC 32-bits, pourvu qu'on sache isoler la section de texte.
Donc en pratique cette technique n'apporte pas grand chose, d'autant plus qu'elle ne permet pas de savoir plus précisément quelle est l'architecture.

\paragraph{Recherche de motifs atypiques.}
Certaines séquences de 3 ou 4 octets, ou certains motifs spécifiques, sont caractéristiques d'une architecture.
En général, ce sont des séquences de prologue ou de fin de fonction.
De telles séquences se trouvent par exemple au moyen d'une analyse statistique du corpus.
En voici quelques unes, qui permettent de reconnaître certaines architectures avec grande fiabilité
(même si les motifs IA-64 engendrent des faux positifs en particulier dans les sections de données, puisqu'ils ont deux octets nuls) :

\begin{center}
\begin{tabular}{|@{\tt}l|@{\tt}l|l|}
\hline
55 89 e5 & X86 & \verb|push %ebp; mov %esp,%ebp| \\
55 57 56 & X86 & \verb|push %ebp; push %edi; push %esi| \\
41 57 41 56 & X86-64 & \verb|push %r15; push %r14| \\
41 55 41 54 & X86-64 & \verb|push %r13; push %r12| \\
55 48 89 e5 & X86-64 & \verb|push %rbp; mov %rsp,%rbp| \\
0e f0 a0 e1 & ARMel & \verb|ret|    (typique de gcc 4.x) \\
1e ff 2f e1 & ARMel & \verb|bx lr|   (typique de gcc 3.x) \\
6b c2 3f d9 & HP-PA & \verb|stw %rp, -cur_rp(%sp)| \\
4e 5e 4e 75 & M68k & \verb|unlk a6; rts| \\
ff bd 67 & MIPSel & \verb|daddiu $sp, -X| \\
ff bd 27 & MIPSel & \verb|addiu $sp, -X| \\
67 bd ff & MIPSeb & \verb|diaddu $sp, -X| \\
67 bd 00& MIPSeb & \verb|diaddu $sp, +X| \\
03 99 e0 21& MIPSeb & \verb|addu $gp, $t9| \\
4e 80 00 20 & PPCeb & \verb|blr| \\
81 c3 e0 08 & sparc & \verb|retl| \\
60 00 80 00 & IA-64 & \verb|br.few b6| \\
08 00 84 00 & IA-64 & \verb|br.ret.sptk.many b0| \\
%X 00 bb 27 Y Z bd 23 & alpha & \verb|ldah $gp, X($27); lda $gp, YZ($gp)| \\
\hline
\end{tabular}
\end{center}

Cette approche permet d'avoir une réponse plus vite que \texttt{cpu\_rec.py}, mais elle est moins générale :
le calcul de distances entre distributions de trigrammes permet d'utiliser automatiquement le fait que sur x86 la séquence \texttt{55 89 e5} est bien plus probable que pour les autres architectures, mais si le compilateur utilisé ne produit pas les instructions \verb|push %ebp; mov %esp,%ebp|,
alors les autres motifs fréquents seront automatiquement pris en compte.

Ceci se voit par exemple pour la reconnaissance de l'ARMel (little-endian) pour laquelle le corpus de \texttt{cpu\_rec.py} est construit en utilisant uniquement un binaire compilé avec gcc 3.x, mais permet de reconnaître les binaires compilés avec gcc 4.x, bien que la plupart d'entre eux ne contienne aucune instruction \verb|bx lr|.



# Appendix: how cpu_rec corpus was built

__LATEX SOURCE IN FRENCH - TO BE TRANSLATED LATER__

Le corpus est un élément essentiel de \texttt{cpu\_rec.py} :
l'outil a été conçu pour pouvoir apprendre chance nouvelle architecture avec seulement
quelques centaines de Ko, mais l'intérêt de l'outil réside en sa capacité à reconnaître des
architectures inhabituelles.

C'est pour cela que la constitution du corpus est détaillée,
et que des extensions de ce corpus sont bienvenues.
\subsection{Binaires divers}
Pour diverses architectures, le corpus se base sur quelques un des fichiers
ELF fournis par Raphaël Rigo (un fichier par architecture, c'est suffisant) ;
l'apprentissage est fait sur la section de code exécutable\footnote
{La section de code exécutable s'appelle normalement
\texttt{.text} en COFF, PE et ELF,
et \texttt{\_\_TEXT,\_\_text} en Mach-O.
Ces noms sont des conventions, un exécutable valide pourrait utiliser d'autres noms.
Les binaires utilisés pour le corpus respectent cette convention.}.
Ce sont des versions de \texttt{libgmp.so}, \texttt{libm.so} ou \texttt{libc.so}
issues de diverses distributions Debian
(pour x86, x86\_64, m68k, PowerPC, S/390, SPARC, Alpha, HP-PA, MIPS et quelques variantes de ARM ;
le code source correspondant à ces binaires est sur \url{http://archive.debian.org/})
ou bien un busybox
(pour ARM big endian et SH-4,
binaires disponibles sur \url{https://busybox.net/downloads/binaries/}).

Pour d'autres architectures, de nombreux binaires sont
disponibles sur \url{ftp://kermit.columbia.edu/kermit/bin/} :
cela a permis d'enrichir le corpus avec
M88k, HP-Focus, Cray, Vax, PDP-11, ROMP, WE32k, CLIPPER, i860.
Certains de ces fichiers sont au format COFF, qui indique où est la section .text,
pour d'autres il a fallu utiliser l'outil \texttt{cpu\_rec.py} en mode verbeux pour
en déduire où est le code exécutable.
Le corpus utilise aussi un firmware pour TMS320C2x fourni par Raphaël Rigo,
au format COFF, issu de \url{https://github.com/slavaprokopiy/Mini-TMS320C28346/blob/master/For_user/C28346_Load_Program_to_Flash/Debug/C28346_Load_Program_to_Flash.out}.

Pour presque toutes ces architectures, un unique binaire a été utilisé pour faire partie du corpus.
Cela peut paraître audacieux de ne pas utiliser de nombreux binaires variés, quand ils sont disponibles,
mais en pratique cela n'est en général pas nécessaire, et cela permet de valider que l'approche statistique
utilisée par \texttt{cpu\_rec.py} sera valide même dans les cas où un seul binaire a pu être trouvé.
Un exemple est l'architecture CLIPPER, apprise à partir d'un unique binaire (celui de C-Kermit),
et détectée dans les fichiers \texttt{boot.1} de \url{https://web-docs.gsi.de/~kraemer/COLLECTION/INTERGRAPH/starfish.osfn.org/Intergraph/index.html}.
% aka. http://web.archive.org/web/20041109140051/http://starfish.osfn.org/Intergraph/floppies/
% Les fichiers "boot.1" files are identified as having CLIPPER instructions, the "root.n" files are of unknown content,
% probably compressed or encrypted data (high entropy in the whole file).


\subsection{Cross-compilateur pour les architectures connues de \protect\texttt{gcc.gnu.org}}
La première étape est d'installer les binutils et le compilateur.
Les instructions ci-dessous ont fonctionné sous MacOSX,
et devraient aussi fonctionner aussi sous Linux
(à quelques modifications de path près).

Les architectures connues du gcc de \texttt{gcc.gnu.org} sont :
\texttt{aarch64} % OK
\texttt{alpha}
\texttt{arc} % OK
\texttt{arm}
\texttt{avr} % OK
\texttt{bfin} % OK
\texttt{c6x} % OK, bug of gcc when building libjpeg
\texttt{cr16} % OK, bug of gcc when building libjpeg
\texttt{cris} % OK
\texttt{epiphany} % OK
\texttt{fr30} % OK
\texttt{frv} % OK
\texttt{ft32} % OK
\texttt{h8300} % OK
\texttt{i386}
\texttt{ia64} % OK
\texttt{iq2000} % OK
\texttt{lm32} % OK
\texttt{m32c} % OK
\texttt{m32r} % OK
\texttt{m68k}
\texttt{mcore} % OK
\texttt{microblaze} % OK
\texttt{mips} % OK
\texttt{mmix} % OK, with TARGET=mmix (not mmix-elf)
\texttt{mn10300} % OK
\texttt{moxie} % OK
\texttt{msp430} % OK, but fails making valid executables
\texttt{nds32be} % OK
\texttt{nds32le} % OK, very similar to BE version
\texttt{nios2} % OK
\texttt{nvptx} % OK, but does not generate binaries, only "assembler"
\texttt{pa}
\texttt{pdp11} % KO
\texttt{rl78} % OK
\texttt{rs6000}
\texttt{rx} % OK
\texttt{s390}
\texttt{sh} % OK, but fails in generating divisions
\texttt{sparc}
\texttt{spu} % OK
\texttt{tilegx} % KO
\texttt{tilepro} % OK, but many bugs
\texttt{v850} % OK
\texttt{visium} % OK
\texttt{xstormy16} % OK
\texttt{xtensa} % OK
mais la création d'un cross-compilateur avec la recette ci-dessous échoue
pour quelques-unes\footnote
{\texttt{mmix} : il faut utiliser \texttt{TARGET=mmix} et non pas \texttt{TARGET=mmix-elf} ;\\
\texttt{pdp11} : bug au moment de la création de l'assembleur ;\\
\texttt{tilegx} : bug pour la création de gcc (fichier \texttt{tilepro/gen-mul-tables.cc} invalide).}.

\begin{footnotesize}
\begin{verbatim}
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
\end{verbatim}
\end{footnotesize}



Les binutils et gcc ne suffisent pas pour compiler la zlib par exemple,
car il manque en particulier la libc. Seuls des programmes sans aucune
dépendance sont compilables.

L'approche habituelle est d'installer d'autres éléments,
selon l'architecture visée, par exemple la libgloss ou la libnosys
(\url{https://github.com/32bitmicro/newlib-nano-1.0/} est un bon point d'entrée).
Parfois l'absence de FPU demande qu'existent des fonctions
telles que \verb|__divsf3|, qui selon les architectures seront
dans la libm ou la libgcc.

Au lieu de suivre cette approche, j'ai créé des stubs vides,
ce qui a permis de directement gérer des architectures non connues
de la newlib, telles que H8/300 ou FTDI FT32.

\subsection{Cross-compilation de zlib et libjpeg}
Ce sont des bibliothèques plutôt calculatoires, donc avec peu d'adhérence au système
d'exploitation, ce qui en fait de bonnes candidates pour une création de corpus
d'instructions d'un CPU.

Les lignes de commande pour une cross-compilation dépendent un peu de la bibliothèque
à compiler. On utilise pour le corpus les exécutables produits : minigzip et jpegtran.
Par exemple pour V850 cela donne :

\begin{footnotesize}
\begin{verbatim}
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
\end{verbatim}
\end{footnotesize}

Dans plusieurs cas (c6x, cr16, epiphany, rl78, tilepro) en suivant la procédure ci-dessus, on tombe sur des bugs
du cross-compilateur gcc (\emph{internal error} ou \emph{SEGV} -- les bug reports restent à faire)
qui peuvent être contournés en modifiant le source de zlib ou libjpeg.
De plus, les exécutables cross-compilés pour RL78 ou MSP430 (avec \texttt{-mlarge})
ont une section .text inutilisable et le corpus ne peut se baser sur minigzip et jpegtran.
À la place, il se base sur les sections .text des fichiers objet engendrés.

\subsection{Autres cross-compilateurs}
Il existe quelques cross-compilateurs basés sur gcc mais disponibles ailleurs que sur \texttt{gcc.gnu.org},
par exemple la toolchain gcc/newlib disponible sur \url{https://riscv.org/software-tools/},
dont un binaire a rejoint le corpus pour l'architecture RISC-V.
% binaire compilé par on ne sait qui, pour résoudre le CTF risky de Hitcon'15

\medskip
Mais pour de nombreux microprocesseurs 8-bits, non seulement le gcc de \texttt{gcc.gnu.org} ne sait pas
faire de cross-compilation, mais comme ces microprocesseurs ont un espace mémoire limité,
on ne peut y faire tenir la zlib ou la libjpeg.
Il faut donc procéder autrement.
Au lieu de compiler une bibliothèque entière, on se limite à de petits programmes.
Pour construire le corpus, principalement trois ont été utilisés ; ça n'est pas suffisant
pour avoir une détection de CPU de bonne qualité, mais cela suffit à prouver la
validité de l'approche.

Pour le MC68HC11 il y a un cross-compilateur fourni avec Ubuntu 12.04, par exemple,
qui fabrique des binaires ELF.
Le compilateur disponible sur \url{http://sdcc.sourceforge.net/} fabrique des fichiers
au format HEX, pour plusieurs variantes de 8051 (mcd51, ds390, ds400),
de Z80 (z80, z180, r2k, r3ka\footnote
{La compilation avec \texttt{-mtlcs90} n'est pas détectée comme fabriquant du code Z80,
ce qui est surprenant car (contrairement au TLCS 900) le TLCS 90 est binairement
compatible avec le Z80.
Le corpus les considère donc comme deux architectures distinctes.}),
pour STM8,
et au format ELF pour des MC68HC08 (hc08, s08).

Pour le 6502, \url{https://github.com/cc65/cc65} permet de fabriquer du code,
mais celui-ci est trop caractéristique du compilateur, plutôt que du microprocesseur
(cela se voit en regardant la régularité de l'assembleur engendré,
et en pratique l'apprentissage sur ce code ne permet par exemple pas de reconnaître des ROM Apple II).
Le corpus par défaut ne permet donc pas de reconnaître le 6502 mais uniquement une variante
que je nomme \texttt{\#6502\#cc65}.

\subsection{En l'absence de cross-compilateur}
Il n'y a pas de compilateur libre permettant de fabriquer du code PIC\footnote
{SDCC a des options -mpic16 et -mpic14, mais elles ne sont pas fonctionnelles.},
Il faut donc trouver des binaires pour les nombreuses variantes de PIC
(principalement PIC10, PIC16, PIC18, PIC24).
Le corpus inclut un firmware pour PIC18
(issu de \url{https://github.com/radare/radare2-regressions/blob/master/bins/pic18c/FreeRTOS-pic18c.hex})
et un autre pour PIC24
(issu de \url{https://raw.githubusercontent.com/mikebdp2/Bus_Pirate/master/package_latest/BPv4/firmware/bpv4_fw7.0_opt0_18092016.hex})
et des petits firmwares pour PIC10 et PIC16
(issus de \url{http://www.pic24.ru/doku.php/en/osa/ref/examples/intro}).

\subsection{Qualité du corpus obtenu}
Le corpus d'apprentissage doit être discriminant :
deux labels différents doivent correspondre à deux comportements statistiques différents.
Pour satisfaire ce critère, les labels ont été définis progressivement.
Par exemple, lorsque l'architecture SPARC a été apprise sur des binaires SPARC v7,
l'outil a été utilisé pour analyser des binaires SPARC v9 (64-bits, et avec un jeu d'instructions
ayant des extensions) :
la plupart de ces binaires ont été reconnus comme SPARC, donc la conclusion est que
ces architectures sont proches ;
ensuite l'outil a été utilisé sur des binaires SPARC v7 et SPARC v9,
avec un apprentissage sur un corpus différenciant v7 et v9 :
les binaires v7 ont été reconnus comme v7 ou v9, et les binaires v9 ont été reconnus comme v7 ou v9,
donc la conclusion est que l'approche par bigrammes et trigrammes ne discrimine pas entre
ces deux architectures ;
le corpus ne contient donc qu'une architecture SPARC.


Pour une architecture donnée, le corpus doit être suffisant :
il faut suffisamment de données pour que le comptage des bigrammes et trigrammes
fasse émerger des caractéristiques de cette architecture.
Lorsqu'un corpus pour une architecture est insuffisant,
l'outil se met à fournir des réponses erronées pour les autres architectures :
le corpus insuffisant a une distribution trop peu marquée qui perturbe les calculs
de proximité.
Une solution (en l'absence de données supplémentaires) est de relire de façon répétée
les données au moment de l'apprentissage
(c'est une solution parce que le calcul de la distance de Kullback-Leibler,
afin d'éviter des divisions par 0, additionne une distribution uniforme à la
distribution observée dans le corpus ; répéter le corpus revient à diminuer
le poids de cette distribution uniforme).

\medskip
L'amélioration du corpus peut se faire dans deux directions :
\begin{itemize}
\item
Extension du corpus pour les architectures pour lesquelles celui-ci est insuffisant.
Si on calcule la taille (comprimée par xz) de chaque fichier du corpus,
les plus petits sont ceux pour lesquels le corpus contient le moins d'information.
On en déduit que les CPUs pour lesquels les données sont le plus incomplètes sont :
PIC10, STM8, PIC16, PIC18, TMS320C2x, puis Z80, 8051, 68HC08, 68HC11 et TLCS-90.
\item
Rajout de nouvelles architectures.
Voici une liste de quelques architectures qui ne sont pas présentes dans le corpus,
et pour lesquelles il faudrait vérifier si elles ne sont pas proches d'une architecture connue,
ou bien les rajouter dans le corpus\footnote
{Cette liste d'architectures existantes est issue principalement de
\url{https://en.wikipedia.org/wiki/Microprocessor},
\url{https://en.wikipedia.org/wiki/List_of_instruction_sets},
\url{https://en.wikipedia.org/wiki/Comparison_of_instruction_set_architectures},
\url{https://en.wikipedia.org/wiki/Digital_signal_processor}
et \url{https://github.com/larsbrinkhoff/awesome-cpus}.} :
6502, % aka. MCS-6500
6800 (si différent du PDP-11 et des 68HCx),
6809, % Motorola, nouveaux opcodes comparé au 6800
8080 (incl. 8085),
AM29k, % AMD
B5000, % Burroughs
CDC-*, % Cray's first supercomputers
CEVA-XC, CEVA-X, CEVA-Teaklite,
DSP56k, % Motorola
Elbrus VLIW,
eSi-RISC,
F8, % Fairchild
F18A, % GreenArrays
HD6301, % Hitachi
KDF9, % English Electric
i960,
MARC4, % Eurosil/Temic/Atmel
MCS-48, % Intel
Mico8,
MSC81xx, % Freescale
OpenRISC,
PDP-1, PDP-7, PDP-8, PDP-10,
%PIC10 (incl. PIC12), PIC16,
PSC1000, % aka. Ignite, aka. ShBoom
Propeller, % Parallax P8X32A
RTX2000, % Harris
S1C6x, % Epson
Saturn, % HP scientific calculators
SHARC, % e.g. Analog Devices
Signetics 2650,
SPC, % Sunplus S+Core 
SystemZ (si différent du S/390),
TMS320C1x, TMS320C3x, TMS320C5x,
Transputer, % Inmos
TriMedia, % NXP
xCore. % XMOS
\end{itemize}
