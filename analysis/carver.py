import struct
import zlib
import analysis
from analysis.node import Node, NodeType
from common.logger import Logger
from .ufs import Endianness, SuperBlock, endianness

import disklib


class FileCarver:
    def __init__(self, stream, offset):
        self.stream = stream
        self.offset = offset
        self.size = None
        self.name = None
        self.stream.seek(self.offset)
        self.initialization()

    def seek(self, offset, whence=0):
        if whence != 1:
            offset += self.offset
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
        pass

    def test(self):
        pass

    def parse(self):
        pass


class JPEGCarver(FileCarver):
    def initialization(self):
        self.extension='.jpeg'
        
    def test(self):
        magic = self.stream.read(3)
        if magic == 0xFFD8FF:
            magic2 = self.stream.read(1)
            if magic2 == 0xDB:
                return True
            if magic2 == 0xE0:
                return True
            if magic2 == 0xEE:
                return True
            if magic2 == 0xE1:
                return True
        return False


class ARCCarver(FileCarver):
    def initialization(self):
        self.extension='.arc'
        
    def test(self):
        magic = self.stream.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.stream.read(4)
            if magic2 == b"\0CRA":
                return True
        return False


class PAMCarver(FileCarver):
    def initialization(self):
        self.extension='.pam'
        
    def test(self):
        magic = self.stream.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.stream.read(3)
            if magic2 == b"PAM":
                return True
        return False


class AT3Carver(FileCarver):
    def initialization(self):
        self.extension='.at3'
        
    def test(self):
        magic = self.stream.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.stream.read(4)
            if magic2 == b"RIFF":
                return True
        return False


class TEXCarver(FileCarver):
    def initialization(self):
        self.extension='.tex'
        
    def test(self):
        magic = self.stream.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.stream.read(4)
            if magic2 == b"\0XET":
                return True
        return False


class SQTRCarver(FileCarver):
    def initialization(self):
        self.extension='.sqtr'
        
    def test(self):
        magic = self.stream.read(4)
        if magic == b"\0SFH":
            self.seek(0x10)
            magic2 = self.stream.read(4)
            if magic2 == b"RQTS":
                return True
        return False

class AVICarver(FileCarver):
    def initialization(self):
        self.extension='.avi'
        
    def test(self):
        magic = self.stream.read(4)
        if magic == b"RIFF":
            self.seek(8)
            magic2 = self.stream.read(4)
            if magic2 == b"AVI\x20":
                return True
        return False


class WaveCarver(FileCarver):
    def initialization(self):
        self.extension='.wav'
        
    def test(self):
        magic = self.stream.read(4)
        if magic == b"RIFF":
            self.seek(8)
            magic2 = self.stream.read(4)
            if magic2 == b"WAVE":
                return True
        return False


class MPEGCarver(FileCarver):
    def initialization(self):
        self.extension='.zlib'
        
    def test(self):
        magic = self.stream.read(4)
        return magic == 0x4C5A4950


class LZipCarver(FileCarver):
    def initialization(self):
        self.extension='.lz'
        
    def test(self):
        magic = self.stream.read(4)
        return magic == 0x4C5A4950


class ZipCarver(FileCarver):
    def initialization(self):
        self.extension='.zip'

    def test(self):
        magic = self.stream.read(3)
        return magic == 0x504B03


class TarGZCarver(FileCarver):
    def initialization(self):
        self.extension='.tar'
        
    def test(self):
        magic = self.stream.read(2)
        magic1 = 0x1F9D
        magic2 = 0x1FA0
        magic3 = 0x1F8B
        if magic3 == magic:
            self.extension = '.gz'
        return magic == magic1 or magic == magic2 or magic == magic3


class PKGCarver(FileCarver):
    def initialization(self):
        self.extension='.pkg'
    
    def test(self):
        magic = self.stream.read(4)
        return magic == b"\x7FPKG"


class SelfCarver(FileCarver):
    def initialization(self):
        self.extension='.self'
        
    def test(self):
        magic = self.stream.read(4)
        return magic == b"SCE\0"

    def parse(self):
        self.seek(0x10)
        self.size = self.u64be() + self.u64be()
        self.extension = ".self"


class ElfCarver(FileCarver):
    def initialization(self):
        self.extension='.elf'

    def test(self):
        magic = self.stream.read(4)
        return magic == b"\x7FELF"


class PUPCarver(FileCarver):
    def initialization(self):
        self.extension='.pup'
    
    def test(self):
        magic = self.stream.read(8)
        return magic == b"SCEUF\0\0"


class SFOCarver(FileCarver):
    def initialization(self):
        self.extension='.sfo'

    def test(self):
        magic = self.stream.read(4)
        return magic == b"\0PSF"
    
    def parse(self):
        self.seek(8)
        key_table_start = self.u32le()
        data_table_start = self.u32le()
        num_ents = self.u32le()

        last_data_offset = 0
        last_data_size = 0
        for x in range(num_ents):
            self.seek(4, 1)
            data_size = self.u32le()
            self.seek(4, 1)
            data_offset = self.u32le()
            if data_offset > last_data_offset:
                last_data_size = data_size
                last_data_offset = data_offset
        self.size = data_table_start + last_data_offset + last_data_size


class TRPCarver(FileCarver):
    SIZEOF_HEADER = 0x40
    def initialization(self):
        self.extension='.trp'
    
    def test(self):
        magic = self.u32be()
        return magic == 0xDCA24D00

    def parse(self):
        self.seek(8)
        self.size = self.u64be() + TRPCarver.SIZEOF_HEADER


class PNGCarver(FileCarver):
    def initialization(self):
        self.extension='.png'

    def test(self):
        magic = self.stream.read(8)
        if magic == b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A':
            return True
        return False

    def parse(self):
        self.extension = ".png"
        self.seek(8)
        while True:
            length = self.u32be()
            ctype = self.read(4)
            cdata = self.read(length)
            ccrc = self.u32be()
            crc = zlib.crc32(ctype + cdata) & 0xffffffff
            if crc != ccrc:
                print("ERROR: Invalid CRC!"),
                break
            if ctype == "IEND":
                break
        self.size = self.tell()


class BMPCarver(FileCarver):
    def initialization(self):
        self.extension='.bmp'

    def test(self):
        magic = self.stream.read(2)
        size = self.u32le()
        if magic == b'BM' and size < 16000000 : # anything over 16MB probably means this is a false positive
            return True
        return False


class HKXCarver(FileCarver):
    def initialization(self):
        self.extension='.hkx'
    
    def test(self):
        magic = self.stream.read(8)
        return magic == b'\x57\xE0\xE0\x57\x10\xC0\xC0\x10'

    def parse(self):
        self.seek(0xB4)
        offset = self.u32be()
        self.seek(0xCC)
        size = self.u32be()
        self.size = offset + size


class BIKCarver(FileCarver):
    def initialization(self):
        self.extension='.bik'
    
    def test(self):
        magic = self.stream.read(3)
        return magic == b'BIK'

    def parse(self):
        self.seek(4)
        self.size = self.u32le() + 8


class NPDCarver(FileCarver):
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

    def parse(self):
        self.seek(0x98)
        self.size = self.u64be()


class PCKCarver(FileCarver):
    def initialization(self):
        self.extension='.pck'
    
    def test(self):
        magic = self.stream.read(4)
        return magic == b'AKPK'


class UnrealArchiveCarver(FileCarver):
    def initialization(self):
        self.extension='.xxx'
    
    def test(self):
        magic = self.stream.read(4)
        return magic == b'\x9E\x2A\x83\xC1'


class UnrealTOCCarver(FileCarver):
    def initialization(self):
        self.extension='.toc.txt' # not really
    def test(self):
        magic = self.stream.read(64)
        if b'..\\Binaries' in magic or b'Coalesced' in magic:
            return True
        return False

class RagePackageCarver(FileCarver):
    def initialization(self):
        self.extension='.rpf'
    def test(self):
        magic = self.stream.read(3)
        return magic == b'\x52\x50\x46'


all_filecarvers = [a_filecarver for a_filecarver in FileCarver.__subclasses__()]


class FileCarver():
    def __init__(self, stream):
        #self._superblock = SuperBlock(self._stream)
        self.identified_file_sigs = []
    
    def scan(self, stream, start=0, end=0, interval=None):
        Logger.log("Beginning FileCarver scan...")

        if end == 0:
            stream.seek(0, 2)
            end = stream.tell()
            stream.seek(0, 0)
        
        if interval == None:
            #interval = self._superblock.fsize
            interval = 0x800

        global all_filecarvers
        for offset in range(start, end, interval):
            for carver in all_filecarvers:
                tester = carver(stream, offset)
                stream.seek(offset)
                if tester.test():
                    stream.seek(offset)
                    Logger.log(f"Found {tester.__class__.__name__}... at offset 0x{offset:X}")
                    self.identified_file_sigs.append(tester)
            if (offset & 0xfffffff) == 0:
                percent = round((offset/end)*100,2)
                Logger.log(f"Percent Complete: {percent}%")
        
        self.parse_identified_file_sigs()

    def parse_identified_file_sigs(self):
        Logger.log("Parsing found files...")
        global all_filecarvers
        for carver in self.identified_file_sigs:
            Logger.log(f"Parsing {carver.__class__.__name__}...")
            carver.parse()    

    def get_nodes(self):
        nodes = []
        for file_carver in self.identified_file_sigs:
            node = Node(NodeType.FILE)
            node.set_name(file_carver.name)
            node.set_file_ext(file_carver.extension)
            node.set_file_offset(file_carver.offset)
            node.set_size(file_carver.size)
            nodes.append(node)
        return nodes


class InodeIdentifier():
    def __init__(self, stream):
        self._stream = stream
        self._superblock = SuperBlock(self._stream)
        self._max_block_index = self._stream.getLength() / self._superblock.fsize

    def identify_unk_inode_filetype(self, inode):
        for file_sig in all_filecarvers:
            # if inode.db[0] > self._max_block_index:      # This shouldn't happen. No inodes should get past the scan that have invalid db bindex
            #     continue
            offset = inode.db[0] * self._superblock.fsize
            self._stream.seek(offset)
            tester = file_sig(self._stream, offset)
            if tester.test():
                return tester
        return None