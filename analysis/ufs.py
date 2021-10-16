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

        Logger.log(\
            f"ipg: {self.ipg:X}\nfpg: {self.fpg:X}\niblkno: {self.iblkno:X}\
            \ninopb: {self.inopb:X} \nfsize: {self.fsize:X} \nbsize: {self.bsize:X}\
            \nfsbtodb: {self.fsbtodb:X} \nbshift: {self.bshift:X}\nnindir: {self.nindir:X}")


def ino_to_offset(sb, ino):
    cyl_index = (ino // sb.ipg)
    cyl_offset = (cyl_index * (sb.fpg * sb.fsize))
    inode_table_offset = sb.iblkno * sb.fsize
    inode_offset = (ino - (sb.ipg * cyl_index)) * 0x100
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
        def get_block_indexes(self, stream, super_block):
            
            #Logger.log( f"Retrieving block indexes of inode at offset: 0x{self.get_offset():X} ...\
            #            \nInode Details -----------------------------------------------------\
            #            \nblksize: {self.blksize} size: {self.size} blocks: {self.blocks}")
            max_bindex = stream.getLength() / super_block.fsize

            def read_block_indexes(blocktable_index, indirection=0, stream=stream, super_block=super_block):
                sb:SuperBlock = super_block
                if max_bindex < blocktable_index:
                    Logger.log(f"Warning block table index is out of bounds: {blocktable_index:X}")
                    return
                block_table_offset = blocktable_index * sb.fsize
                stream.seek(block_table_offset)
                blocks_indexes = []
                blockcount = 0
                while blockcount < sb.nindir:
                    if endianness is Endianness.LITTLE:
                        block_index = struct.unpack("<Q", stream.read(8))[0]
                    else:
                        block_index = struct.unpack(">Q", stream.read(8))[0]
                    if max_bindex < block_index:
                        Logger.log(f"Warning block index is out of bounds: {block_index:X}")
                        break
                    if block_index == 0:
                        break
                    Logger.log(f"Read block [{blockcount}] index: {block_index:X} at offset 0x{block_table_offset + (blockcount*0x8):X}")
                    blocks_indexes.append(block_index)
                    blockcount += 1
                return blocks_indexes
            
            indexes = []
            count = 0
            for index in self.db:
                if index == 0:
                    break
                if max_bindex < index:
                    Logger.log(f"Warning db index is out of bounds: {index:X}")
                    index = 0
                Logger.log(f"read db[{count}] block index: {index:X} at offset 0x{self._offset + 0x70 + (count*0x8):X}")
                indexes.append(index)
                count += 1
            
            # Read indirect blocks
            if self.ib[0] > 0:
                btable_index = self.ib[0]
                indexes += read_block_indexes(btable_index, 1)
            if self.ib[1] > 0:
                ib_table_index = self.ib[1]
                btable = read_block_indexes(ib_table_index, 1)
                for btable_index in btable:
                    indexes += read_block_indexes(btable_index, 2)
            if self.ib[2] > 0:
                ib_table_index = self.ib[2]
                ib_table = read_block_indexes(ib_table_index, 1)
                for ib_ib_table_index in ib_table:
                    btable = read_block_indexes(ib_ib_table_index, 2)
                    for btable_index in btable:
                        indexes += read_block_indexes(btable_index, 3)
            
            return indexes
    return Inode