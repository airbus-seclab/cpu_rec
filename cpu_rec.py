#! /usr/bin/env python
# Tested with python >= 2.4

# cpu_rec.py is a tool that recognizes cpu instructions
# in an arbitrary binary file.
# It can be used as a standalone tool, or as a plugin for binwalk

# Copyright 2017-2019. Airbus -- Louis Granboulan
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



# Installation instructions:
#   1. Copy this file and the content of cpu_rec_corpus in the directory
#      of your choice.
#   2. If you don't have the lzma module installed for your python (this
#      tool works either with python3 or with recent python2) then you
#      should unxz the corpus files.
#   3. If you want to enhance the corpus, you can add new data in the
#      corpus directory. If you want to create your own corpus, please
#      look at the method 'read_corpus' below.

# Installation instructions, for use as a binwalk module:
#   Same as above, but the installation directory must be the binwalk
#   module directory: $HOME/.config/binwalk/modules .
#   You'll need a recent version of binwalk, that includes the patch
#   provided by https://github.com/devttys0/binwalk/pull/241 .

# How to use the tool as a binwalk module:
#   Add the flag -% when using binwalk.

# How to use the tool as a standalone tool:
#   Just run the tool, with the binary file(s) to analyze as argument(s)
#   The tool will try to match an architecture for the whole file, and
#   then to detect the largest binary chunk that corresponds to a CPU
#   architecture; usually it is the right answer.
#   If the result is not satisfying, prepending twice -v to the arguments
#   makes the tool very verbose; this is helpful when adding a new
#   architecture to the corpus.
#   If https://github.com/airbus-seclab/elfesteem is installed, then the
#   tool also extract the text section from ELF, PE, Mach-O or COFF
#   files, and outputs the architecture corresponding to this section;
#   the possibility of extracting the text section is also used when
#   building a corpus from full binary files.
#   Option -d followed by a directory dumps the corpus in that directory;
#   using this option one can reconstruct the default corpus.

# How to use the tool as a python module:
#   from cpu_rec import which_arch
#   Call which_arch with a bytestring as input; the answer is the name
#   of the architecture detected, or None.
#   Loading the training data is done during the first call of which_arch,
#   and calling which_arch with no argument does this precomputation only.



import sys, struct, os
import pickle
from time import time
import logging
log = logging.getLogger("cpu_rec")
if not len(log.handlers):
    # When used as a binwalk module, this file is loaded many, many times,
    # but only one handler should be defined.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
    log.addHandler(console_handler)
    log.setLevel(logging.WARN)

# NB: we get a string in python2 and bytes in python3
if sys.version_info[0] == 2:
    byte_ord = lambda i: ord(i)
else:
    byte_ord = lambda i: i

class TrainingData(object):
    def __init__(self):
        """ This class contains, for each item in the training corpus:
            architecture, file name, binary data """
        self.archs = []
        self.files = []
        self.data = []
    def dump(self, dumpdir=None):
        """ Dump the raw corpus, in a form that won't need elftesteem to be loaded """
        for arch, data in zip(self.archs, self.data):
            of = open(dumpdir+'/'+arch.replace('/','-')+'.corpus', 'ab')
            of.write(data)
            of.close()
    def add_training(self, arch, file=None, section='text', data=None, repeat=1):
        """ Add a new item in the training corpus:
            'arch': architecture name
            if 'data' is not None:
                'data': raw bytestream
            else:
                'file': file to read
                'section': part of the file to extract
                    None: keep the whole file
                    of type 'slice': start and end of part to extract
                    of type 'str': name of the section to extract
            'repeat': when the corpus is too small, we repeat it
        """
        if data is None:
            data = TrainingData.unpack_file(open(file, 'rb').read())
            if section is None:
                pass
            elif isinstance(section, slice):
                data = data[section]
            elif isinstance(section, str):
                data = TrainingData.extract_section(data, section=section)
            else:
                raise TypeError("Invalid type %s for section in add_training"%section.__class__.__name__)
        else:
            file = arch # no file name
        if repeat > 1: data = data*repeat
        self.archs.append(arch)
        self.files.append(file)
        self.data.append(data)
    @staticmethod
    def unpack_ihex(data):
        # https://en.wikipedia.org/wiki/Intel_HEX
        if sys.version_info[0] == 3: lines = data.decode('latin1').split('\n')
        else: lines = data.split('\n')
        sorted_lines = []
        base_address = 0
        for line in lines:
            if line.endswith('\r'): line = line[:-1]
            if len(line) == 0: continue
            if len(line) < 11: sorted_lines = []; break
            if line[0] != ':': sorted_lines = []; break
            if line[1:].strip('0123456789abcdefABCDEF') != '': sorted_lines = []; break
            count    = line[1:1+2]
            address  = line[3:3+4]
            type     = line[7:7+2]
            content  = line[9:-2]
            checksum = line[-2:]
            count    = int(count, 16)
            address  = int(address, 16)
            type     = int(type, 16)
            checksum = int(checksum, 16)
            if len(content) != 2*count: sorted_lines = []; break
            for i in range(count+4):
                checksum += int(line[2*i+1:2*i+3], 16)
            if checksum % 256 != 0: sorted_lines = []; break
            if type == 2:
                # Extended Segment Address
                base_address = 16*int(content, 16)
                continue
            if type == 4:
                # Extended Linear Address
                base_address = 65536*int(content, 16)
                continue
            if type != 0: continue
            sorted_lines.append((base_address+address,content))
        res = []
        large_chunk = False
        for address, content in sorted(sorted_lines, key=lambda _:_[0]):
            if len(res) < address:
                if address-len(res) > 0x1000000:
                    if not large_chunk:
                        log.warning("Intel HEX file has large chunk of zeroes, ignored")
                    large_chunk = True
                else:
                    res.extend([0 for i in range(address-len(res))])
            elif len(res) > address:
                log.warning("Intel HEX file decoding not valid")
            for i in range(len(content)//2):
                res.append(int(content[2*i:2*i+2], 16))
        if len(res):
            data = struct.pack("%dB"%len(res), *res)
        return data
    @staticmethod
    def unpack_chex(data):
        # ftp://kermit.columbia.edu/kermit/bin/cklxtr.cm
        # The decoding below is not fully valid, but sufficient for
        # our statistical analysis
        if sys.version_info[0] == 3: lines = data.decode('latin1').split('\n')
        else: lines = data.split('\n')
        res = []
        for line in lines:
            if line.endswith('\r'): line = line[:-1]
            if len(line) == 0: continue
            if line[0] == 'Z' and line[1:].strip('0123456789abcdefABCDEF') == '': continue
            if line.strip('0123456789abcdefABCDEF') != '': res = []; break
            if len(line) % 2 != 0: res = []; break
            for i in range(len(line)//2):
                res.append(int(line[2*i:2*i+2], 16))
        if len(res):
            data = struct.pack("%dB"%len(res), *res)
        return data
    @staticmethod
    def unpack_file(data):
        """ Sometimes, the file does not contain the raw data, but a compressed/encoded version """
        magic = ( 0xfd,0x37,0x7a,0x58,0x5a )
        if data.startswith(struct.pack("%dB"%len(magic),*magic)):
            # xz compressed data
            import lzma
            data = lzma.decompress(data)
        magic = ( 0x1f, 0x8b )
        if data.startswith(struct.pack("%dB"%len(magic),*magic)):
            # gzip compressed data
            import zlib
            data = zlib.decompress(data,16+zlib.MAX_WBITS)
        if data.startswith(struct.pack("B",58)):
            # Intel HEX
            data = TrainingData.unpack_ihex(data)
        magic = ( 0x0a,0x5a,0x30,0x31,0x0a ) # \nZ01\n
        if struct.pack("%dB"%len(magic),*magic) in data:
            # C-Kermit HEX
            data = TrainingData.unpack_chex(data)
        return data
    @staticmethod
    def extract_section(data, section=False):
        # Extract text sections from know containers
        # elfesteem has to be installed
        try:
            import elfesteem
        except ImportError:
            return data
        magic = ( 0x7f,0x45,0x4c,0x46 )
        if data.startswith(struct.pack("%dB"%len(magic),*magic)):
            from elfesteem import elf_init
            e = elf_init.ELF(data)
            res = struct.pack("")
            for sh in e.sh:
                if (section == 'text' and sh.sh.name.startswith('.text')) or sh.sh.name == section:
                    res += data[sh.sh.offset:sh.sh.offset+sh.sh.size]
            if len(res): return res
        magic = ( 0x4d,0x5a )
        if data.startswith(struct.pack("%dB"%len(magic),*magic)):
            if section == 'text': section = '.text'
            from elfesteem import pe_init
            e = pe_init.PE(data)
            for sh in e.SHList:
                if sh.name.strip('\0') == section:
                    return data[sh.offset:sh.offset+sh.rawsize]
        magic = (( 0xce,0xfa,0xed,0xfe ), ( 0xcf,0xfa,0xed,0xfe ))
        if data.startswith(tuple([struct.pack("4B",*_) for _ in magic])):
            if section == 'text': section = '__TEXT'
            from elfesteem import macho_init
            e = macho_init.MACHO(data, parseSymbols=False)
            for s in e.sect.sect:
                if s.sh.segname == section:
                    return data[s.sh.offset:s.sh.offset+s.sh.size]
        try:
            from elfesteem import pe_init, pe
            e = pe_init.Coff(data)
            if section == 'text': section = '.text'
            for sh in e.SHList:
                if sh.name.strip('\0') == section:
                    return data[sh.offset:sh.offset+sh.rawsize]
        except ValueError:
            pass
        return data
    def read_corpus(self):
        """ Gets the raw training dataset """
        basedir = os.path.dirname(os.path.realpath(__file__))
        if basedir != '': basedir += '/'
        # If the default training set has been installed along cpu_rec.py,
        # we use it.
        default_corpus = basedir+'cpu_rec_corpus'
        if os.access(default_corpus, os.R_OK):
            files = os.listdir(default_corpus)
            for file in files:
                if file.endswith('.corpus.xz') and file[:-3] in files:
                    log.warning("Both compressed and uncompressed versions of %s: only the uncompressed one is used", file[:-10])
                    continue
                for suffix in ('.corpus', '.corpus.xz'):
                    if file.endswith(suffix):
                        self.add_training(file[:-len(suffix)], file = default_corpus+'/'+file, section=None)
            log.info("Default set of size %d is read; %s different CPUs known", len(self.archs), len(set([_ for _ in self.archs if not _.startswith('_')])))
            return
        # If we have access to the binary files used to construct the
        # default corpus, we use them.
        source_corpus = basedir+'cpu_rec_source_corpus/'
        if os.access(source_corpus, os.R_OK):
            self.build_default_corpus(source_corpus)
            return
        log.error('No corpus available')
        sys.exit(1)
    def build_default_corpus(self, basedir):
        # Below, the list of files used to create this default training set
        # and the instructions to load them.
        # The following piece of code is informative only, to explain how
        # one can make/enrich the corpus.
        for key, pattern in (
                # Use struct.pack to be compatible with python2 and python3
                ('_zero', struct.pack("16B",*[0x00]*16)*32*1024),
                ('_ones', struct.pack("16B",*[0xff]*16)*32*1024),
                ('_mask1', struct.pack("16B",*[0xff,0xff,0xff,0x00]*4)*32*1024),
                ):
            self.add_training(key, data = pattern)
        self.add_training('_words',        file = basedir+'words')
        self.add_training('_words_ucs2',   file = basedir+'words_ucs2')
        # A few selected files from Trou's corpus for REDOCS, or cross-compiled
        # as explained in the paper for SSTIC'2017.
        self.add_training('X86',           file = basedir+'ELF/i386/libgmp.so.10.2.0.xz')
        self.add_training('X86-64',        file = basedir+'ELF/amd64/libgmp.so.10.2.0.xz')
        self.add_training('ARMeb',         file = basedir+'__TODO/busybox.net/busybox-armv4eb')
        self.add_training('ARMel',         file = basedir+'ELF/armel/libgmp.so.10.2.0.xz')
        self.add_training('ARM64',         file = basedir+'ELF/arm64/libgmp.so.10.2.0.xz') # el
        self.add_training('ARMhf',         file = basedir+'ELF/armhf/libgmp.so.10.2.0.xz') # el
        self.add_training('M68k',          file = basedir+'ELF/m68k/libc-2.3.2.so.xz')
        self.add_training('PPCeb',         file = basedir+'ELF/powerpc/libgmp.so.10.2.0.xz') # Big Endian (32 or 64-bit)
        self.add_training('PPCel',         file = basedir+'ELF/ppc64el/libgmp.so.10.2.0.xz') # Little Endian (32 or 64-bit)
        self.add_training('S-390',         file = basedir+'ELF/s390x/libgmp.so.10.2.0.xz') # S/390
        self.add_training('SPARC',         file = basedir+'ELF/sparc/libc-2.1.3.so.xz')
        self.add_training('SPARC',         file = basedir+'ELF/sparc64/libm-2.7.so.xz')
        self.add_training('Alpha',         file = basedir+'ELF/alpha/libc-2.7.so.xz')
        self.add_training('HP-PA',         file = basedir+'ELF/hppa/libc-2.3.2.so.xz')
        self.add_training('RISC-V',        file = basedir+'__TODO/elf/guess-number-riscv64')
        self.add_training('ARcompact',     file = basedir+'CROSS_COMPILED/minigzip-arc-elf.xz')
        self.add_training('ARcompact',     file = basedir+'CROSS_COMPILED/jpegtran-arc-elf.xz')
        self.add_training('AVR',           file = basedir+'CROSS_COMPILED/minigzip-avr-elf.xz')
        self.add_training('AVR',           file = basedir+'CROSS_COMPILED/jpegtran-avr-elf.xz')
        self.add_training('Blackfin',      file = basedir+'CROSS_COMPILED/minigzip-bfin-elf.xz')
        self.add_training('Blackfin',      file = basedir+'CROSS_COMPILED/jpegtran-bfin-elf.xz')
        self.add_training('TMS320C2x',     file = basedir+'TMS320/C28346_Load_Program_to_Flash.out', repeat=5)
        self.add_training('TMS320C6x',     file = basedir+'CROSS_COMPILED/minigzip-c6x-elf.xz')
        #       _training('TMS320C6x',     file = basedir+'CROSS_COMPILED/jpegtran-c6x-elf.xz') # does not build; bug of gcc for jccolor.o
        self.add_training('CompactRISC',   file = basedir+'CROSS_COMPILED/minigzip-cr16-elf.xz')
        #       _training('CompactRISC',   file = basedir+'CROSS_COMPILED/jpegtran-cr16-elf.xz') # does not build; bug of gcc for jdmarker.o
        self.add_training('AxisCris',      file = basedir+'CROSS_COMPILED/minigzip-cris-elf.xz')
        self.add_training('AxisCris',      file = basedir+'CROSS_COMPILED/jpegtran-cris-elf.xz')
        self.add_training('Epiphany',      file = basedir+'CROSS_COMPILED/minigzip-epiphany-elf.xz')
        #       _training('Epiphany',      file = basedir+'CROSS_COMPILED/jpegtran-epiphany-elf.xz') # does not build; bug of gcc for jidctred.o
        self.add_training('FR30',          file = basedir+'CROSS_COMPILED/minigzip-fr30-elf.xz') # Fujitsu FR30
        self.add_training('FR30',          file = basedir+'CROSS_COMPILED/jpegtran-fr30-elf.xz')
        self.add_training('FR-V',          file = basedir+'CROSS_COMPILED/minigzip-frv-elf.xz')
        self.add_training('FR-V',          file = basedir+'CROSS_COMPILED/jpegtran-frv-elf.xz')
        self.add_training('FT32',          file = basedir+'CROSS_COMPILED/minigzip-ft32-elf.xz') # FTDI FT32
        self.add_training('FT32',          file = basedir+'CROSS_COMPILED/jpegtran-ft32-elf.xz')
        self.add_training('H8-300',        file = basedir+'CROSS_COMPILED/minigzip-h8300-elf.xz') # H8/300
        self.add_training('H8-300',        file = basedir+'CROSS_COMPILED/jpegtran-h8300-elf.xz') # H8/300
        self.add_training('IA-64',         file = basedir+'CROSS_COMPILED/minigzip-ia64-elf.xz')
        self.add_training('IA-64',         file = basedir+'CROSS_COMPILED/jpegtran-ia64-elf.xz')
        self.add_training('IQ2000',        file = basedir+'CROSS_COMPILED/minigzip-iq2000-elf.xz') # Vitesse IQ2000
        self.add_training('IQ2000',        file = basedir+'CROSS_COMPILED/jpegtran-iq2000-elf.xz')
        self.add_training('Mico32',        file = basedir+'CROSS_COMPILED/minigzip-lm32-elf.xz') # LatticeMico32
        self.add_training('Mico32',        file = basedir+'CROSS_COMPILED/jpegtran-lm32-elf.xz')
        self.add_training('M32C',          file = basedir+'CROSS_COMPILED/minigzip-m32c-elf.xz')
        self.add_training('M32C',          file = basedir+'CROSS_COMPILED/jpegtran-m32c-elf.xz')
        self.add_training('M32R',          file = basedir+'CROSS_COMPILED/minigzip-m32r-elf.xz')
        self.add_training('M32R',          file = basedir+'CROSS_COMPILED/jpegtran-m32r-elf.xz')
        self.add_training('MCore',         file = basedir+'CROSS_COMPILED/minigzip-mcore-elf.xz') # aka. Motorola RCE
        self.add_training('MCore',         file = basedir+'CROSS_COMPILED/jpegtran-mcore-elf.xz')
        self.add_training('MicroBlaze',    file = basedir+'CROSS_COMPILED/minigzip-microblaze-elf.xz')
        self.add_training('MicroBlaze',    file = basedir+'CROSS_COMPILED/jpegtran-microblaze-elf.xz')
        self.add_training('MIPSel',        file = basedir+'ELF/mipsel/libgmp.so.10.2.0.xz')
        self.add_training('MIPSeb',        file = basedir+'ELF/mips/libgmp.so.10.2.0.xz')
        self.add_training('MIPSeb',        file = basedir+'CROSS_COMPILED/minigzip-mips1-elf.xz')
        self.add_training('MIPSeb',        file = basedir+'CROSS_COMPILED/jpegtran-mips1-elf.xz')
        self.add_training('MIPSeb',        file = basedir+'CROSS_COMPILED/minigzip-mips2-elf.xz')
        self.add_training('MIPSeb',        file = basedir+'CROSS_COMPILED/jpegtran-mips2-elf.xz')
        self.add_training('MIPS16',        file = basedir+'CROSS_COMPILED/minigzip-mips16-elf.xz')
        self.add_training('MIPS16',        file = basedir+'CROSS_COMPILED/jpegtran-mips16-elf.xz')
        self.add_training('MMIX',          file = basedir+'CROSS_COMPILED/minigzip-mmix-elf.xz', repeat=2)
        self.add_training('MMIX',          file = basedir+'CROSS_COMPILED/jpegtran-mmix-elf.xz', repeat=2)
        self.add_training('MN10300',       file = basedir+'CROSS_COMPILED/minigzip-mn10300-elf.xz') # Matsushita MN10300
        self.add_training('MN10300',       file = basedir+'CROSS_COMPILED/jpegtran-mn10300-elf.xz')
        self.add_training('Moxie',         file = basedir+'CROSS_COMPILED/minigzip-moxie-elf.xz')
        self.add_training('Moxie',         file = basedir+'CROSS_COMPILED/jpegtran-moxie-elf.xz')
        self.add_training('MSP430',        file = basedir+'CROSS_COMPILED/minigzip-msp430-elf.xz')
        self.add_training('MSP430',        file = basedir+'CROSS_COMPILED/cjpeg-msp430-elf.xz')
        self.add_training('MSP430',        file = basedir+'CROSS_COMPILED/libz-msp430-elf.o.xz') # Could only make object files for MSP430
        self.add_training('MSP430',        file = basedir+'CROSS_COMPILED/libjpeg-msp430.o.text.xz')
        self.add_training('NDS32',         file = basedir+'CROSS_COMPILED/minigzip-nds32le-elf.xz') # same statistics for nsd32le and nds32be
        self.add_training('NDS32',         file = basedir+'CROSS_COMPILED/jpegtran-nds32le-elf.xz')
        self.add_training('NIOS-II',       file = basedir+'CROSS_COMPILED/minigzip-nios2-elf.xz')
        self.add_training('NIOS-II',       file = basedir+'CROSS_COMPILED/jpegtran-nios2-elf.xz')
        self.add_training('RL78',          file = basedir+'CROSS_COMPILED/libz-rl78-elf.o.xz') # Could only make object files for RL78; need to patch deflate.c, to avoid SEGV of gcc
        self.add_training('RL78',          file = basedir+'CROSS_COMPILED/libjpeg-rl78.o.text.xz') # need to patch jdmainct.c, to avoid internal error of gcc
        self.add_training('RX',            file = basedir+'CROSS_COMPILED/minigzip-rx-elf.xz', section='P')
        self.add_training('RX',            file = basedir+'CROSS_COMPILED/jpegtran-rx-elf.xz', section='P')
        self.add_training('SuperH',        file = basedir+'__TODO/busybox.net/busybox-sh4')
        self.add_training('SuperH',        file = basedir+'CROSS_COMPILED/minigzip-sh-elf.xz') # need to delete divisions from source code, because gcc fails in creating __udivsi3
        self.add_training('SuperH',        file = basedir+'CROSS_COMPILED/jpegtran-sh-elf.xz') # need to delete divisions from source code, because gcc fails in creating __udivsi3
        self.add_training('Cell-SPU',      file = basedir+'CROSS_COMPILED/minigzip-spu-elf.xz')
        self.add_training('Cell-SPU',      file = basedir+'CROSS_COMPILED/jpegtran-spu-elf.xz')
        self.add_training('TILEPro',       file = basedir+'CROSS_COMPILED/minigzip-tilepro-elf.xz') # need to patch trees.c, to avoid internal error of gcc
        #       _training('TILEPro',       file = basedir+'CROSS_COMPILED/jpegtran-tilepro-elf.xz') # need to patch jchuff.c, jcphuff.c, jcdctmgr.c and others, to avoid internal error of gcc
        self.add_training('V850',          file = basedir+'CROSS_COMPILED/minigzip-v850-elf.xz')
        self.add_training('V850',          file = basedir+'CROSS_COMPILED/jpegtran-v850-elf.xz')
        self.add_training('Visium',        file = basedir+'CROSS_COMPILED/minigzip-visium-elf.xz')
        self.add_training('Visium',        file = basedir+'CROSS_COMPILED/jpegtran-visium-elf.xz')
        self.add_training('Stormy16',      file = basedir+'CROSS_COMPILED/minigzip-xstormy16-elf.xz')
        self.add_training('Stormy16',      file = basedir+'CROSS_COMPILED/jpegtran-xstormy16-elf.xz')
        self.add_training('Xtensa',        file = basedir+'CROSS_COMPILED/minigzip-xtensa-elf.xz')
        self.add_training('Xtensa',        file = basedir+'CROSS_COMPILED/jpegtran-xtensa-elf.xz')
        # Nice exotic architectures found in C-Kermit binaries.
        self.add_training('M88k',          file = basedir+'c-kermit/cku190.dgux540c-88k.xz')
        self.add_training('HP-Focus',      file = basedir+'c-kermit/cku192.hpux500wintcp-s550-5.21.xz', section=slice(0x0,0x66000))  # Educated guess for .text section
        self.add_training('Cray',          file = basedir+'c-kermit/cku189.unicos7y.xz',                section=slice(0x0,0x118000)) # Educated guess for .text section
        self.add_training('VAX',           file = basedir+'c-kermit/cku192.bellv10-vax.xz',             section=slice(0x0,0x4f800))  # Educated guess for .text section
        self.add_training('PDP-11',        file = basedir+'c-kermit/cku192.bsd211.xz',                  section=slice(0x0,0x1f000))  # Educated guess for .text section
        self.add_training('ROMP',          file = basedir+'c-kermit/cku192.rtaixc-2.2.1-rtpc.xz',       section=slice(0x0,0x6e000))  # Educated guess for .text section
        self.add_training('WE32000',       file = basedir+'c-kermit/cku192.att3bx.xz',                  section=slice(0xd0,0xd0+0x51944))  # .text section defined in COFF
        self.add_training('CLIPPER',       file = basedir+'c-kermit/cku196.clix-3.1.xz',                section=slice(0xe0,0xe0+0x108de0)) # .text section defined in COFF
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x4800,0x8800))    # .text section seems to be scattered across the file
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0xb800,0x18800))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x1a800,0x21800))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x23800,0x29000))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x2a800,0x3a000))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x3e800,0x47800))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x4b800,0x52000))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x54800,0x59800))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x60000,0x6c000))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0x74800,0x84000))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0xb4800,0xc7800))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0xcf000,0xe4800))
        self.add_training('i860',          file = basedir+'c-kermit/ckl196-i860-vos1333.hex.xz',        section=slice(0xeb000,0xfb000))
        # 8-bit CPUs, cannot cross-compile usual open source software, because
        # of size and of pointer size; we compile something else, but the
        # result is small, barely sufficient.
        self.add_training('8051',          file = basedir+'CROSS_COMPILED/tu-a15-mcs51.hex')
        self.add_training('8051',          file = basedir+'CROSS_COMPILED/tu-n9-mcs51.hex')
        self.add_training('8051',          file = basedir+'CROSS_COMPILED/tu-tea-mcs51.hex')
        self.add_training('8051',          file = basedir+'CROSS_COMPILED/tu-arithmetic-mcs51.hex')
        self.add_training('8051',          file = basedir+'CROSS_COMPILED/tu-tea-ds390.hex') # DS80C390 and DS80C400 are derived from 8051
        self.add_training('8051',          file = basedir+'CROSS_COMPILED/tu-arithmetic-ds390.hex')
        self.add_training('STM8',          file = basedir+'CROSS_COMPILED/tu-tea-stm8.hex', repeat=5)
        self.add_training('STM8',          file = basedir+'CROSS_COMPILED/tu-arithmetic-stm8.hex', repeat=5)
        self.add_training('68HC08',        file = basedir+'CROSS_COMPILED/tu-tea-hc08-elf', section='CSEG', repeat=2)
        self.add_training('68HC08',        file = basedir+'CROSS_COMPILED/tu-path-hc08-elf', section='CSEG', repeat=2)
        self.add_training('68HC08',        file = basedir+'CROSS_COMPILED/tu-arithmetic-hc08-elf', section='CSEG', repeat=2)
        self.add_training('68HC11',        file = basedir+'CROSS_COMPILED/tu-path-m68hc11-elf')
        self.add_training('68HC11',        file = basedir+'CROSS_COMPILED/tu-arithmetic-m68hc11-elf')
        self.add_training('Z80',           file = basedir+'CROSS_COMPILED/tu-tea-z80.hex', repeat=2)
        self.add_training('Z80',           file = basedir+'CROSS_COMPILED/tu-path-z80.hex', repeat=2)
        self.add_training('Z80',           file = basedir+'CROSS_COMPILED/tu-arithmetic-z80.hex', repeat=2)
        self.add_training('TLCS-90',       file = basedir+'CROSS_COMPILED/tu-tea-tlcs90.hex', repeat=2)
        self.add_training('TLCS-90',       file = basedir+'CROSS_COMPILED/tu-path-tlcs90.hex', repeat=2)
        self.add_training('TLCS-90',       file = basedir+'CROSS_COMPILED/tu-arithmetic-tlcs90.hex', repeat=2)
        # PIC10 and PIC16 from http://www.pic24.ru/doku.php/en/osa/ref/examples/intro
        self.add_training('PIC10',         file = basedir+'PIC10/3leds_pic10f222.hex', repeat=10)
        self.add_training('PIC16',         file = basedir+'PIC16/quartet.hex', repeat=10)
        # PIC18 from https://github.com/radare/radare2-regressions/blob/master/bins/pic18c/FreeRTOS-pic18c.hex
        self.add_training('PIC18',         file = basedir+'PIC18/FreeRTOS-pic18c.hex', repeat=5)
        # PIC24 from https://raw.githubusercontent.com/mikebdp2/Bus_Pirate/master/package_latest/BPv4/firmware/bpv4_fw7.0_opt0_18092016.hex
        self.add_training('PIC24',         file = basedir+'PIC24/bpv4_fw7.0_opt0_18092016.hex', section=slice(0x8830,0x1d2e0))
        # 6502 binary compiled with https://github.com/cc65/cc65
        # This appears to be more compiler-dependent than CPU-dependent, the
        # statistics are very different from an AppleII ROM, for example.
        self.add_training('#6502#cc65',     file = basedir+'CROSS_COMPILED/tu-tea-cc65', repeat=5)
        self.add_training('#6502#cc65',     file = basedir+'CROSS_COMPILED/tu-path-cc65', repeat=5)
        self.add_training('#6502#cc65',     file = basedir+'CROSS_COMPILED/tu-arithmetic-cc65', repeat=5)
        # Other 6502 binary, downloaded from https://raw.githubusercontent.com/RolfRolles/Atredis2018/master/MemoryDump/data-4000-efff.bin
        # This is not a lot of data, but seems sufficient
        self.add_training('6502',  file = basedir+'6502/data-4000-efff.bin', section=slice(0x4000,0x4542), repeat=5)
        # CUDA from http://jcuda.org/samples/matrixInvert%200.0.1%20CUBIN%2032bit.zip
        # Not a lot of data either
        self.add_training('CUDA',       file = basedir+'CUDA/kernels32/GPUeliminateRest_kernel.cubin',  section=slice(0x477,0x477+0xaa0), repeat=5)
        # WebAssembly from https://github.com/mdn/webassembly-examples/blob/master/wasm-sobel/change.wasm
        self.add_training('WASM',       file = basedir+'WASM/change.wasm')
        # H8S-2117A from https://github.com/airbus-seclab/cpu_rec/issues/4
        self.add_training('H8S',   file = basedir+'H8S/bridge7757.mot.bin',  section=slice(0x210c,0x1671e))
        # TriMedia from https://github.com/crackinglandia/trimedia/blob/master/tm-linux/tmlinux-kernel-obj-latest.tar.bz2
        self.add_training('TriMedia',   file = basedir+'trimedia/linux-obj/fs/built-in.o',  section=slice(0x400,0x400+0x73acf)) # .text section
        # Nec/Renesas 78k is used in Metz flash units, cf. https://debugmo.de/2011/10/whats-inside-metz-50-af-1-n/
        self.add_training('78k',        file = basedir+'Metz/MB50AF1_NikonV12.bin',  section=slice(0x2ba,0x2ba+0x7d5a))
        # TriCore is used in Volkswagen's ECU, cf. https://debugmo.de/2015/12/dieselgate/
        self.add_training('TriCore',    file = basedir+'Volkswagen/FL_03L906018HK_3533.bin',  section=slice(0xa094c,0x1ea48c))
        # OCaml bytecode, having non-standard statistical properties.
        self.add_training('OCaml',         file = basedir+'OCaml/camlp4',  section=slice(0x1a, 0xec856))
        log.info("Training set of size %d is read; %s different CPUs known", len(self.archs), len(set([_ for _ in self.archs if not _.startswith('_')])))
        log.debug("CPUs known: %s", ', '.join(sorted(list(set([_ for _ in self.archs if not _.startswith('_')])))))

import math
class MarkovCrossEntropy(object):
    """
    Markov chain, similarity by cross-entropy computation
    """
    def count_generic(self, data, freq, base_count):
        v = 0
        for idx in range(len(data)):
            v = (data[idx]+0x100*v)%self.tbl_size
            if idx >= self.length-1:
                if not v in freq: freq[v] = base_count
                freq[v] += 1
    def count_bigrams_mod4(self, data, freq, base_count):
        # Each four bytes
        for idx in range(len(data)//4):
            v = data[4*idx+1]+0x100*data[4*idx]
            if not v in freq: freq[v] = base_count
            freq[v] += 1
    def count_bigrams(self, data, freq, base_count):
        # Faster than count_generic
        prv = None
        for c in data:
            c = byte_ord(c)
            if prv is not None:
                v = c+0x100*prv
                if not v in freq: freq[v] = base_count
                freq[v] += 1
            prv = c
    def count_trigrams(self, data, freq, base_count):
        prv = None
        pprv = None
        for c in data:
            c = byte_ord(c)
            if pprv is not None:
                v = c+0x100*prv+0x10000*pprv
                if not v in freq: freq[v] = base_count
                freq[v] += 1
            pprv = prv
            prv = c
    def count_quadrigrams(self, data, freq, base_count):
        prv = None
        pprv = None
        ppprv = None
        for c in data:
            c = byte_ord(c)
            if ppprv is not None:
                v = c+0x100*prv+0x10000*pprv+0x1000000*ppprv
                if not v in freq: freq[v] = base_count
                freq[v] += 1
            ppprv = pprv
            pprv = prv
            prv = c
    def __init__(self, training, length=2, modulo=None, FreqVariant='A'):
        self.length = length
        self.tbl_size = 0x100**length
        if   length == 2 and modulo is None:
            self.count = self.count_bigrams
        elif length == 2 and modulo == 4:
            self.count = self.count_bigrams_mod4
        elif length == 3:
            self.count = self.count_trigrams
        elif length == 4:
            self.count = self.count_quadrigrams
        else:
            self.count = self.count_generic
        t0 = time()
        #   Frequencies in Q should never be 0 because any n-gram may appear in P
        #   and we will need to divide by the frequency in Q to compute the KL divergence
        #   Variant A: each counter starts with a small non-zero value, e.g. 0.01
        #   Variant B: when the counter is zero, the frequency will be 1/256**(n+1)
        #   Sometimes variant B is better, but usually variant A gives better results
        #   With a sufficiently large corpus, they are equivalent...
        if   FreqVariant == 'A': base_count = 0.01
        elif FreqVariant == 'B': base_count = 0
        # Don't use defaultdict: it takes more memory and is slower
        self.counts = {}
        self.Q = {}
        self.base_freq = {}
        for i, data in enumerate(training.data):
            arch = training.archs[i]
            if not arch in self.counts:
                self.counts[arch] = {}
            self.count(data, self.counts[arch], base_count)
            log.debug("%10d bytes long %10d %s %10s %s",
                len(data),
                len(self.counts[arch]),
                ['','','bigrams','trigrams','quadrigrams'][length],
                arch,
                training.files[i])
            # replace counts by frequencies
            Qtotal = base_count * (self.tbl_size-len(self.counts[arch]))
            for v in self.counts[arch].values():
                assert v != 0
                Qtotal += v
            self.Q[arch] = {}
            if   FreqVariant == 'A': self.base_freq[arch] = 0.01/Qtotal
            elif FreqVariant == 'B': self.base_freq[arch] = 1./0x100/self.tbl_size
            for idx, v in self.counts[arch].items():
                self.Q[arch][idx] = 1.0*v/Qtotal
        if modulo is None: modulo = ''
        else:              modulo = 'mod%d'%modulo
        log.info("... %s[%d-grams%s;%s] done in %fs", self.__class__.__name__, length, modulo, FreqVariant, time()-t0)
    def count_freq(self, data):
        P = {}
        self.count(data, P, 0)
        # replace counts by frequencies
        Ptotal = 0
        for v in P.values():
            Ptotal += v
        for idx, v in P.items():
            P[idx] = 1.0*v/Ptotal
        return P
    def compute_KL(self, P, Q, base_freq):
        KLD = 0.0
        for idx, v in P.items():
            if v != 0:
                KLD += v * math.log(v/Q.get(idx, base_freq))
        return KLD
    def predict(self, data):
        P = self.count_freq(data)
        # compute the Kullback-Leibler divergence D(P||Q) for observed P
        # and all pre-computed Q (for each architecture)
        KL = {}
        for arch, Q in self.Q.items():
            KL[arch] = self.compute_KL(P, Q, self.base_freq[arch])
        del P
        return sorted([(arch,KL[arch]) for arch in KL],key=lambda _:_[1])
    def dump(self, arch):
        fmt = '%%#0%dx: %%d,\n' % (2+2*self.length)
        res = ''
        values = sorted(self.counts[arch].items(), key=lambda x:-x[1])
        for idx, v in values:
            res += fmt % (idx,v)
        return res

class FileAnalysis(object):
    def dump(self, dumpdir=None):
        for arch in self.archs:
            of = open(dumpdir+'/'+arch.replace('/','-')+'.stat', 'w')
            of.write('stats = {\n')
            of.write('"M2": {\n%s},\n' % self.m2.dump(arch))
            of.write('"M3": {\n%s},\n' % self.m3.dump(arch))
            of.write('}\n')
            of.close()
    def __init__(self, t):
        self.archs = set(t.archs)
        self.m2 = MarkovCrossEntropy(t)
        self.m3 = MarkovCrossEntropy(t, length=3)
    def heuristic(self, r2, r3, d):
        # The following heuristics should probably be replaced by the result of
        # supervised machine learning.
        if r2[0][0] != r3[0][0]:
            # bigrams and trigrams disagree, we refuse to output a guess
            return None
        res = r2[0][0]
        if res.startswith('_'):
            # Recognized as not machine code
            return None
        # Special rules, to avoid false recognition for specific architectures
        if res == 'OCaml' and r2[0][1] > 1:
            # OCaml bytecode has non-standard statistics for a CPU;
            # when the CPU is not recognised, or in data sections, very often it is seen as OCaml
            return None
        elif res == 'IA-64' and r2[0][1] > 3:
            # Same for IA-64
            return None
        elif res == 'PIC24':
            # PIC24 code has a 24-bit instruction set. In our corpus it is encoded in 32-bit words,
            # therefore every four byte is 0x00.
            zero = [True, True, True, True]
            for idx in range(len(d)//4):
                zero = [ zero[i] and byte_ord(d[4*idx+i]) == 0 for i in range(4) ]
                if not True in zero:
                    return None
        return res
    def deduce(self, d):
        r2 = self.m2.predict(d)
        r3 = self.m3.predict(d)
        return self.heuristic(r2, r3, d), r2, r3
    def window(self, d, sz):
        res = [[None,0]]
        # For each chunk, we remember some other possible architectures,
        # this will be used if 'merge' is called
        other = []
        for i in range(len(d)//sz):
            r, r2, r3 = self.deduce(d[sz*i:sz*(i+2)])
            other.append([a for a,_ in r2[:2]]+[a for a,_ in r3[:2]])
            log.debug("      %#10x   %-10s %s", sz*i, r, r2[:4])
            log.debug("      %10s   %-10s %s", '', '', r3[:4])
            if r == res[-1][0]:
                res[-1][1] += 1
            else:
                res.append([r,1])
        return res, other
    def best_guess(self, res):
        cpu, cnt = None, 0
        for cp, cn in res:
            if cn > cnt and cp is not None: cpu, cnt = cp, cn
        return (cpu, cnt)
    def sliding_window(self, d):
        cpu, sz, cnt = None, 0x800, 1
        if len(d) < 0x20000: sz = 0x400
        if len(d) < 0x8000: sz = 0x200
        if len(d) < 0x1000: sz = 0x100
        if len(d) < 0x400: sz = 0x40
        while sz >= 0x40 and (cpu is None or cnt <= 1):
            # Computing time is roughly independent of the window size
            # If the window is too small, then the statistics within the
            # window are not representative enough to allow architecture
            # recognition
            t0 = time()
            res, other = self.window(d, sz)
            log.info("%s", res)
            cpu, cnt = self.best_guess(res)
            sz //= 2
            log.info("... window size %#x done in %fs", sz*4, time()-t0)
        return res, cpu, sz, cnt, other
    def merge(self, res, cpu, other):
        # Eliminate small chunks between larger chunks with identical cpu guesses
        def probably_outlier(cn, pos, prv, nxt):
            if prv[0] != nxt[0] or prv[1] == 0:
                # Not identical cpu guesses
                return False
            if cn > (prv[1]+nxt[1]):
                # The current chunk is bigger than the surrounding ones
                return False
            if other[pos-cn].count(prv[0]) == 2:
                # If the cpu guess for the surrounding chunks was in the first
                # two choices for this chunk, then we merge
                return True
            if cpu in other[pos-cn]:
                # Main cpu guess, we keep it
                return False
            if 10*cn < (prv[1]+nxt[1]):
                # Surrounding chunks are large, and the cpu guess for this
                # chunk is not the same as the best guess for the file
                # Probably a mistake!
                return True
            return False
        r = []
        pos = 0
        for idx, (cp, cn) in enumerate(res):
            pos += cn
            if len(r) and r[-1][0] == cp:
                r[-1][1] += cn
                continue
            if len(r) and idx < len(res)-1 and probably_outlier(cn, pos, r[-1], res[idx+1]):
                r[-1][1] += cn
                continue
            r.append([cp,cn])
        return r

def which_arch(d = None, training = {}):
    if not 'p' in training:
        t = TrainingData()
        t.read_corpus()
        training['p'] = FileAnalysis(t)
    if d is None:
        return None
    res, r2, r3 = training['p'].deduce(d)
    return res


if __name__ == "__main__":
    fast, dump = False, False
    argv = sys.argv[1:]
    if len(argv) and argv[0] == '-d':
        dump = True
        assert len(argv) == 2
        dumpdir = argv[1]
        if not os.path.isdir(dumpdir):
            log.error("Directory %r should be created before running the tool", dumpdir)
            sys.exit(1)
    if len(argv) and argv[0] == '-f':
        fast = True
        argv = argv[1:]
    if len(argv) and argv[0] == '-v':
        log.setLevel(logging.INFO)
        argv = argv[1:]
        if len(argv) and argv[0] == '-v':
            log.setLevel(logging.DEBUG)
            argv = argv[1:]
    if dump:
        # Always recompute data for dump
        t = TrainingData()
        t.read_corpus()
        p = FileAnalysis(t)
        t.dump(dumpdir=dumpdir)
        p.dump(dumpdir=dumpdir)
        sys.exit(0)
    # The pickled data might depend on the version of python, it is not
    # ditributed with cpu_rec and shall be erased in case of python
    # update or in case of addition of a new architecture in the corpus.
    # NB: there is a race condition, if "stats.pick" is created by
    # another program between os.path.isfile and open, it is overwritten.
    pickled_data = os.path.join(os.path.dirname(__file__), "stats.pick")
    if os.path.isfile(pickled_data):
        log.info("Loading training data from pickled file")
        t, p = pickle.load(open(pickled_data, "rb"))
    else:
        log.info("Pickled training data not found, loading from corpus")
        t = TrainingData()
        t.read_corpus()
        p = FileAnalysis(t)
        log.info("Saving pickled training data")
        try:
            f = open(pickled_data, "wb")
            pickle.dump((t, p), f)
            f.close()
        except OSError:
            log.warning("Could not save cached training data")
        except TypeError:
            # Using Cpython 2, fails with "can't pickle instancemethod objects"
            # But works with pypy-2.7, for example
            log.warning("Can't pickle with this version of python")
            os.unlink(pickled_data)
    for f in argv:
        sys.stdout.write('%-80s'%f)
        sys.stdout.flush()
        # Full file
        d = TrainingData.unpack_file(open(f, 'rb').read())
        res, r2, r3 = p.deduce(d)
        sys.stdout.write('%-15s%-10s' % ('full(%#x)' % len(d), res))
        sys.stdout.flush()
        log.debug("FULL")
        log.debug("                   %s", r2[:4])
        log.debug("                   %s", r3[:4])
        # Text section, if possible
        d_txt = TrainingData.extract_section(d, section='text')
        if len(d) != len(d_txt):
            res, r2, r3 = p.deduce(d_txt)
            sys.stdout.write('%-15s%-10s' % ('text(%#x)' % len(d_txt), res))
        else:
            sys.stdout.write('%-15s%-10s' % ('', ''))
        sys.stdout.flush()
        log.debug("TEXT")
        log.debug("                   %s", r2[:4])
        log.debug("                   %s", r3[:4])
        if not fast:
            _, cpu, sz, cnt, _ = p.sliding_window(d)
            sys.stdout.write('%-20s%-10s' % ('chunk(%#x;%s)'%(2*sz*cnt,cnt), cpu))
        sys.stdout.write('\n')
        sys.stdout.flush()
    sys.exit(0)

#######################################################
# Module for binwalk
try:
    import binwalk.core.module

    class CPUStatisticalDiscovery(binwalk.core.module.Module):
        TITLE = "Statistical CPU guessing"
        PRIORITY = 3
        CLI = [
                    binwalk.core.module.Option(short='%',
                       long='markov',
                       kwargs={'enabled' : True},
                       description='Identify the CPU opcodes in a file using statistical analysis')
              ]
        KWARGS = [
                    binwalk.core.module.Kwarg(name='enabled', default=False)
                 ]

        def run(self):
            for fp in iter(self.next_file, None):
                self.header()
                self.scan_file(fp)
                self.footer()
            return True

        def init(self):
            t = TrainingData()
            t.read_corpus()
            self.p = FileAnalysis(t)

        def scan_file(self, fp):
            raw = super(fp.__class__, fp).read()
            data = TrainingData.unpack_file(raw)
            res, cpu, sz, _, other = self.p.sliding_window(data)
            res = self.p.merge(res, cpu, other)
            pos = 0
            for cpu, cnt in res:
                if cnt == 0: continue
                cnt *= 2*sz
                self.result(offset=pos,file=fp,description="%s (size=%#x, entropy=%f)"%(cpu,cnt,
                    self.shannon(raw[pos:pos+cnt])))
                pos += cnt

        def shannon(self, data):
            '''
            Performs a Shannon entropy analysis on a given block of data.
            This code is very similar to the function 'shannon' from binwalk.modules.entropy, but it has been modified to work with python3 and 'data' of type 'bytes'.
            '''
            if not data:
                return 0
            entropy = 0
            length = len(data)
            seen = dict(((x, 0) for x in range(0, 256)))
            for byte in data:
                seen[byte_ord(byte)] += 1
            for x in range(0, 256):
                p_x = float(seen[x]) / length
                if p_x > 0:
                    entropy -= p_x * math.log(p_x, 2)
            return (entropy / 8)

except ImportError:
    pass
