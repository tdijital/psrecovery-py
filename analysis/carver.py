import struct
from common.logger import Logger
from .ufs import Endianness, SuperBlock, endianness

import disklib


class FileSignature:
    def __init__(self, stream, offset):
        self.stream = stream
        self._offset = offset
        self.initialization()

    def seek(self, offset, whence=0):
        if whence != 1:
            offset += self._offset
        self.stream.seek(offset, whence)
    
    def u8be(self):
        return struct.unpack(">B", self.stream.read(1))[0]

    def u16be(self):
        return struct.unpack(">H", self.stream.read(2))[0]

    def u32be(self):
        return struct.unpack(">L", self.stream.read(4))[0]

    def u64be(self):
        return struct.unpack(">Q", self.stream.read(8))[0]

    def floatbe(self):
        return struct.unpack(">f", self.stream.read(4))[0]

    def doublebe(self):
        return struct.unpack(">d", self.stream.read(8))[0]

    def u8le(self):
        return struct.unpack("<B", self.stream.read(1))[0]

    def u16le(self):
        return struct.unpack("<H", self.stream.read(2))[0]

    def u32le(self):
        return struct.unpack("<L", self.stream.read(4))[0]

    def u64le(self):
        return struct.unpack("<Q", self.stream.read(8))[0]

    def floatle(self):
        return struct.unpack("<f", self.stream.read(4))[0]

    def doublele(self):
        return struct.unpack("<d", self.stream.read(8))[0]
    
    def initialization(self):
        self.extension = ''

    def test(self):
        raise NotImplementedError("FileCarver tester not implemented!")

    def parse(self):
        raise NotImplementedError("FileCarver parser not implemented!")


class SelfSignature(FileSignature):
    def initialization(self):
        self.extension='.self'
        
    def test(self):
        magic = self.stream.read(4)
        return magic == b"SCE\0"


class ElfSignature(FileSignature):
    def initialization(self):
        self.extension='.elf'

    def test(self):
        magic = self.stream.read(4)
        return magic == b"\x7FELF"


class PUPSignature(FileSignature):
    def initialization(self):
        self.extension='.pup'
    
    def test(self):
        magic = self.stream.read(8)
        return magic == b"SCEUF\0\0"


class SFOSignature(FileSignature):
    def initialization(self):
        self.extension='.sfo'

    def test(self):
        magic = self.stream.read(4)
        return magic == b"\0PSF"


class TRPSignature(FileSignature):
    SIZEOF_HEADER = 0x40
    def initialization(self):
        self.extension='.trp'
    
    def test(self):
        magic = self.u32be()
        return magic == 0xDCA24D00


class PNGSignature(FileSignature):
    def initialization(self):
        self.extension='.png'

    def test(self):
        magic = self.stream.read(8)
        if magic == b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A':
            return True
        return False


class BMPSignature(FileSignature):
    def initialization(self):
        self.extension='.bmp'

    def test(self):
        magic = self.stream.read(2)
        size = self.u32le()
        if magic == b'BM' and size < 16000000 : # anything over 16MB probably means this is a false positive
            return True
        return False


class HKXSignature(FileSignature):
    def initialization(self):
        self.extension='.hkx'
    
    def test(self):
        magic = self.stream.read(8)
        return magic == b'\x57\xE0\xE0\x57\x10\xC0\xC0\x10'


class BIKSignature(FileSignature):
    def initialization(self):
        self.extension='.bik'
    
    def test(self):
        magic = self.stream.read(3)
        return magic == b'BIK'


class NPDSignature(FileSignature):
    def initialization(self):
        self.extension='.npd'
    
    def test(self):
        magic = self.stream.read(4)
        if magic == b'NPD\0':
            self.seek(0x90)
            npdtype = self.u8be()
            if (npdtype & 0xf) == 0x0:
                self.extension = ".edat"
            elif (npdtype & 0xf) == 0x1:
                self.extension = ".sdat"
            else:
                self.extension = ".npd"


class PCKSignature(FileSignature):
    def initialization(self):
        self.extension='.pck'
    
    def test(self):
        magic = self.stream.read(4)
        return magic == b'AKPK'


class UnrealArchiveSignature(FileSignature):
    def initialization(self):
        self.extension='.xxx'
    
    def test(self):
        magic = self.stream.read(4)
        return magic == b'\x9E\x2A\x83\xC1'


class UnrealTOCSignature(FileSignature):
    def test(self):
        magic = self.stream.read(64)
        if b'..\\Binaries' in magic or b'Coalesced' in magic:
            return True
        return False


all_filesigs = [a_filesig for a_filesig in FileSignature.__subclasses__()]

class FileCarver():
    def __init__(self, disk, partition_name):
        partition = disk.getPartitionByName(partition_name)
        self._stream = partition.getDataProvider()
        self.identified_file_sigs = []
    
    def scan(self, stream, start=0, end=0, interval=0x800):
        if end == 0:
            self.stream.seek(0, 2)
            end = self.stream.tell()
            self.stream.seek(0, 0)

        for offset in range(start, end, interval):
            for carver in self.carvers:
                tester = carver(self.stream, offset)
                self.stream.seek(offset)
                if tester.test():
                    self.stream.seek(offset)
                    Logger.log("Parsing {}...".format(tester.__class__.__name__)),
                    tester.parse()
                    self.identified_file_sigs.append(tester)
                    Logger.log(str(tester))

class InodeIdentifier():
    def __init__(self, stream):
        self._stream = stream
        self._superblock = SuperBlock(self._stream)
        self._max_block_index = self._stream.getLength() / self._superblock.fsize

    def identify_unk_inode_filetype(self, inode):
        for file_sig in all_filesigs:
            offset = inode.db[0] * self._superblock.fsize
            if offset > self._max_block_index:      # This shouldn't happen. No inodes should get past the scan that have invalid db bindex
                continue
            self._stream.seek(offset)
            tester = file_sig(self._stream, offset)
            if tester.test():
                return tester
        return None