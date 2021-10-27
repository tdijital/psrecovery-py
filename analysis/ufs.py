import ctypes
import struct

from common.logger import Logger

class Endianness:
    BIG = 'big'
    LITTLE = 'little'

endianness = Endianness.BIG

# TODO: Have this be a ctype struct and include the entire super block
class SuperBlock():
    def __init__(self, stream):
        # Load some fields we need from the ufs2 super block
        stream.seek(0x10000)
        # fsiblkno
        stream.seek(0x10000 + 0x10)
        self.iblkno = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_dblkno
        stream.seek(0x10000 + 0x14)
        self.dblkno = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_ncg
        stream.seek(0x10000 + 0x2C)
        self.ncg = int.from_bytes(stream.read(4), byteorder=endianness, signed=False)
        # fsbsize
        stream.seek(0x10000 + 0x30)
        self.bsize = int.from_bytes(stream.read(4), byteorder=endianness)
        # fsfsize
        stream.seek(0x10000 + 0x34)
        self.fsize = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_frag
        stream.seek(0x10000 + 0x38)
        self.frag = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_bshift
        stream.seek(0x10000 + 0x50)
        self.bshift = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_fshift
        stream.seek(0x10000 + 0x54)
        self.fshift = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_fragshift
        stream.seek(0x10000 + 0x60)
        self.fragshift = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_fsbtodb
        stream.seek(0x10000 + 0x64)
        self.fsbtodb = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_nindir
        stream.seek(0x10000 + 0x74)
        self.nindir = int.from_bytes(stream.read(4), byteorder=endianness)
        # fs_inopb
        stream.seek(0x10000 + 0x78)
        self.inopb = int.from_bytes(stream.read(4), byteorder=endianness, signed=False)
        # fsipg
        stream.seek(0x10000 + 0xB8)
        self.ipg = int.from_bytes(stream.read(4), byteorder=endianness)
        # fsfpg
        stream.seek(0x10000 + 0xBC)
        self.fpg = int.from_bytes(stream.read(4), byteorder=endianness)

    def log_info(self):
        Logger.log(\
            f"ipg: {self.ipg:X}\nfpg: {self.fpg:X}\niblkno: {self.iblkno:X}\
            \ninopb: {self.inopb:X} \nfsize: {self.fsize:X} \nbsize: {self.bsize:X}\
            \nfsbtodb: {self.fsbtodb:X} \nbshift: {self.bshift:X}\nnindir: {self.nindir:X}")


def ino_to_offset(superblock, ino):
    cyl_index = (ino // superblock.ipg)
    cyl_offset = (cyl_index * (superblock.fpg * superblock.fsize))
    inode_table_offset = superblock.iblkno * superblock.fsize
    inode_offset = (ino - (superblock.ipg * cyl_index)) * 0x100
    return cyl_offset + inode_table_offset + inode_offset

"""
struct    direct {
    u_int32_t d_ino;        /* inode number of entry */
    u_int16_t d_reclen;        /* length of this record */
    u_int8_t  d_type;         /* file type, see below */
    u_int8_t  d_namlen;        /* length of string in d_name */
    char      d_name[MAXNAMLEN + 1];/* name with length <= MAXNAMLEN */
};
"""
def get_direct_class():
    class Direct(ctypes.BigEndianStructure if endianness is Endianness.BIG else ctypes.LittleEndianStructure):
        _fields_ = [
            ("ino", ctypes.c_uint32),       # 0x00
            ("reclen", ctypes.c_uint16),    # 0x04
            ("type", ctypes.c_uint8),       # 0x06
            ("namlen", ctypes.c_uint8)      # 0x07
        ]

        def set_name(self, name):
            self._name = name

        def get_name(self):
            return self._name

        def set_offset(self, offset):
            self._offset = offset

        def get_offset(self):
            if not hasattr(self, "_offset"):
                self._offset = 0
                Logger.log(f"Warning: direct {self.get_name()} has no offset set.")
            return self._offset
    return Direct

def get_inode_class():
    class Inode(ctypes.BigEndianStructure if endianness is Endianness.BIG else ctypes.LittleEndianStructure):
        _fields_ = [
            ("mode", ctypes.c_uint16),
            ("nlink", ctypes.c_uint16),
            ("uid", ctypes.c_uint32),
            ("gid", ctypes.c_uint32),
            ("blksize", ctypes.c_uint32),

            ("size", ctypes.c_uint64),
            ("blocks", ctypes.c_uint64),

            ("atime", ctypes.c_uint64),
            ("mtime", ctypes.c_uint64),

            ("ctime", ctypes.c_uint64),
            ("birthtime", ctypes.c_uint64),

            ("mtimensec", ctypes.c_uint32),
            ("atimensec", ctypes.c_uint32),
            ("ctimensec", ctypes.c_uint32),
            ("birthnsec", ctypes.c_uint32),

            ("gen", ctypes.c_uint32),
            ("kernflags", ctypes.c_uint32),
            ("flags", ctypes.c_uint32),
            ("extsize", ctypes.c_uint32),

            ("extb", ctypes.c_uint64 * 2),

            ("db", ctypes.c_uint64 * 12),
            ("ib", ctypes.c_uint64 * 3),
            ("modrev", ctypes.c_uint64),
            ("freelink", ctypes.c_uint32),
            ("spare", ctypes.c_uint32 * 3)
        ]

        def set_offset(self, offset):
            self._offset = offset
        def get_offset(self):
            return self._offset
    return Inode

def inode_is_directory(inode):
    #  We can also check the following:
    #   - 0100000 is set for files (IFREG)
    return inode.mode & 0x4000

class InodeReader():
    def __init__(self, stream):
        self._stream = stream
        self._superblock = SuperBlock(stream)
        self._max_bindex = self._stream.getLength() / self._superblock.fsize

    def get_block_indexes(self, inode):
        indexes = []
        for index in inode.db:
            if index == 0 or  self._max_bindex < index:
                break
            indexes.append(index)
        
        # Read indirect blocks
        if inode.ib[0] > 0:
            btable_index = inode.ib[0]
            indexes += self.read_block_indexes_at_index(btable_index)
        if inode.ib[1] > 0:
            ib_table_index = inode.ib[1]
            btable = self.read_block_indexes_at_index(ib_table_index)
            for btable_index in btable:
                indexes += self.read_block_indexes_at_index(btable_index)
        if inode.ib[2] > 0:
            ib_table_index = inode.ib[2]
            ib_table = self.read_block_indexes_at_index(ib_table_index)
            for ib_ib_table_index in ib_table:
                btable = self.read_block_indexes_at_index(ib_ib_table_index)
                for btable_index in btable:
                    indexes += self.read_block_indexes_at_index(btable_index)
        
        return indexes

    def read_block_indexes_at_offset(self, block_table_offset):
        self.read_block_indexes_at_index(block_table_offset/self._superblock.fsize)

    def read_block_indexes_at_index(self, blocktable_index):
        if self._max_bindex < blocktable_index:
            return
        block_table_offset = blocktable_index * self._superblock.fsize
        self._stream.seek(block_table_offset)
        blocks_indexes = []
        blockcount = 0
        while blockcount < self._superblock.nindir:
            if endianness is Endianness.LITTLE:
                block_index = struct.unpack("<Q", self._stream.read(8))[0]
            else:
                block_index = struct.unpack(">Q", self._stream.read(8))[0]
            if self._max_bindex < block_index:
                break
            if block_index == 0:
                break
            # Logger.log(f"Read block [{blockcount}] index: {block_index:X} at offset 0x{block_table_offset + (blockcount*0x8):X}")
            blocks_indexes.append(block_index)
            blockcount += 1
        return blocks_indexes

    def fill_missing_block_indexes(self, block_indexes, required_blocks):
        missing_index_count = required_blocks - len(block_indexes)
        last_valid_index = block_indexes[-1]
        for i in missing_index_count:
            block_indexes.append(last_valid_index + i)