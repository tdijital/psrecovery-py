import sys
import io
import os
import ctypes
from tkinter.constants import END, INSERT, LEFT, RIGHT, TOP
import disklib
import json
import time
import struct


"""
struct    direct {
    u_int32_t d_ino;        /* inode number of entry */
    u_int16_t d_reclen;        /* length of this record */
    u_int8_t  d_type;         /* file type, see below */
    u_int8_t  d_namlen;        /* length of string in d_name */
    char      d_name[MAXNAMLEN + 1];/* name with length <= MAXNAMLEN */
};
"""
class Direct(ctypes.BigEndianStructure):
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
        return self._offset

class Inode(ctypes.BigEndianStructure):
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
    def get_block_indexes(self, stream, fsize):
        
        max_bindex = stream.getLength() / fsize

        def read_block_indexes(blocktable_index, stream=stream, fsize=fsize):
            if max_bindex < blocktable_index:
                Logger.log(f"Warning block table index is out of bounds: {blocktable_index}")
                blocktable_index = 0
            blocks = []
            stream.seek(blocktable_index * fsize)
            blockcount = 0
            while blockcount <= 2048:
                blockcount += 1
                block_index = struct.unpack(">Q", stream.read(8))[0]
                if block_index == 0:
                    break
                blocks.append(block_index)
            return blocks
        
        blocks = []
        for block in self.db:
            if block == 0:
                break
            if max_bindex < block:
                Logger.log(f"Warning db index is out of bounds: {block}")
                block = 0
            blocks.append(block)
        
        # Read indirect blocks
        if self.ib[0] > 0:
            btable_index = self.ib[0]
            blocks += read_block_indexes(btable_index)
        if self.ib[1] > 0:
            ib_table_index = self.ib[1]
            ib_table = read_block_indexes(ib_table_index)
            for btable_index in ib_table:
                blocks += read_block_indexes(btable_index)
        if self.ib[2] > 0:
            ib_ib_table_index = self.ib[2]
            ib_ib_table = read_block_indexes(ib_ib_table_index)
            for ib_table in ib_ib_table:
                ib_indexes = read_block_indexes(ib_table)
                for btable_index in ib_indexes:
                    blocks += read_block_indexes(btable_index)
        
        return blocks


class NodeType:
    FILE = 0
    DIRECTORY = 1
    THIS = 2
    PARENT = 3


class Node:
    def __init__(self, typ):
        self._name = None
        self._size = None
        self._creation_time = None
        self._last_access_time = None
        self._last_modified_time = None
        self._flags = None
        self._direct = None
        self._direct_offset = None
        self._directory_offset = None
        self._inode = None
        self._inode_offset = None
        self._children = []
        self._parents = []
        self._type = typ
        self._filesignature = None
        self._active = False

    def set_active(self, active):
        self._active = active
    def get_active(self):
        return self._active
    def set_name(self, name):
        self._name = name
    def get_name(self):
        return self._name
    def set_creation_time(self, time):
        self._creation_time = time
    def set_last_access_time(self, time):
        self._last_access_time = time
    def set_last_modified_time(self, time):
        self._last_modified_time = time
    def get_creation_time(self):
        return self._creation_time
    def get_last_access_time(self):
        return self._last_access_time
    def get_last_modified_time(self):
        return self._last_modified_time
    def set_size(self, size):
        self._size = size
    def get_size(self):
        return self._size
    def get_type(self):
        return self._type
    def set_direct(self, direct):
        self._direct = direct
    def get_direct(self):
        return self._direct
    def set_direct_offset(self, offset):
        self._direct_offset = offset
    def get_direct_offset(self):
        return self._direct_offset
    def set_directory_offset(self, offset):
        self._directory_offset = offset
    def get_directory_offset(self):
        return self._directory_offset
    def set_inode(self, inode):
        self._inode = inode
    def get_inode(self):
        return self._inode
    def set_inode_offset(self, offset):
        self._inode_offset = offset
    def get_inode_offset(self):
        return self._inode_offset
    def get_inode_index(self):
        return self._direct.ino
    def get_children(self):
        return self._children
    def add_child(self, child):
        self._children.append(child)
    def get_parents(self):
        return self._parents
    def add_parent(self, parent):
        self._parents.append(parent)
    def __repr__(self):
        return self.get_name()


class Directory:
    def __init__(self, offset):
        self._offset = offset
        self._directs = {}
    def add_direct(self, direct):
        self._directs[direct.get_name()] = direct
    def get_direct(self, name):
        return self._directs[name]
    def get_directs(self):
        return self._directs.values()
    def get_offset(self):
        return self._offset


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


#class RIFFSignature(FileSignature):
#    def initialization(self):
#        self.extension='.rif' # this isn't right
#
#    def test(self):
#        magic = self.read(4)
#        return magic == b"RIFF"


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


class Scanner2:
    def __init__(self, disk, sector_size):
        self._stream = None  # The stream we will ultimately be reading from
        self._sector_size = sector_size
        # Values we will need to compute offsets
        self._iblkno = None # Offset of inode block table into cylinder group
        self._dblkno = None
        self._fsize = None  # Size of a fragment block
        self._bsize = None
        self._ipg = None    # Number of inodes in an inode table
        self._fpg = None    # Number of fragments per group
        self._ncg = None    # Number of cylinder groups in file system
        self._ninodes = None
        self._active_inodes = None
        self._active_directs = None
        self._initialize(disk)

    def _initialize(self, disk):
        partition = disk.getPartitionByName('dev_hdd0')
        self._stream = partition.getDataProvider()
        print(self._stream.getLength())

        # Load some fields we need from the ufs2 super block
        self._stream.seek(0x10000)
        # fs_iblkno
        self._stream.seek(0x10000 + 0x10)
        self._iblkno = int.from_bytes(self._stream.read(4), byteorder='big')
        # fs_dblkno
        self._stream.seek(0x10000 + 0x14)
        self._dblkno = int.from_bytes(self._stream.read(4), byteorder='big')
        # fs_ncg
        self._stream.seek(0x10000 + 0x2C)
        self._ncg = int.from_bytes(self._stream.read(4), byteorder='big')
        # fs_bsize
        self._stream.seek(0x10000 + 0x30)
        self._bsize = int.from_bytes(self._stream.read(4), byteorder='big')
        # fs_fsize
        self._stream.seek(0x10000 + 0x34)
        self._fsize = int.from_bytes(self._stream.read(4), byteorder='big')
        # fs_ipg
        self._stream.seek(0x10000 + 0xB8)
        self._ipg = int.from_bytes(self._stream.read(4), byteorder='big')
        # fs_fpg
        self._stream.seek(0x10000 + 0xBC)
        self._fpg = int.from_bytes(self._stream.read(4), byteorder='big')

        vfs = partition.getVfs()
        vfs.mount()
        if not vfs.isMounted():
            raise Exception("Vfs failed to mount!")
        root = vfs.getRoot()

        self._active_inodes = self._get_all_offsets(root, 'inode')
        self._active_directs = self._get_all_offsets(root, 'dirent')

        self._ninodes = (self._ipg * self._ncg)
        self.max_block_index = self._stream.getLength() / self._fsize
    def _get_all_offsets(self, root, key):
        """Get all tables from a directory"""
        tables = set()
        tables.update(root.getOffsets(key))
        for node in root.getChildren():
            tables.update(node.getOffsets(key))
            if isinstance(node, disklib.VfsDirectory):
                tables.update(self._get_all_offsets(node, key))
        return tables

    def _is_valid_block_table(self, indexes):
        for x in range(2+12+3):
            index = int.from_bytes(indexes[(x*8):(x*8)+8], byteorder='big')
            if -1 <= index > self.max_block_index:
                return False
        return True

    def _read_inode_at_offset(self, offset):
        self._stream.seek(offset)
        data = self._stream.read(0x100)
        # Fast basic checks
        indexes = data[0x70:0xF8]
        if not any(indexes):
            return None
        if not self._is_valid_block_table(indexes):
            return None
        # Create the inode
        inode = Inode.from_buffer(bytearray(data))
        inode.set_offset(offset)
        # More checks
        if inode.mode == 0:
            return None
        if inode.nlink > 0x10:
            return None
        if inode.size > 1099511627776 or inode.size < 0:
            return None
        if(inode.atime < 32536799999 and inode.mtime < 32536799999 and inode.ctime < 32536799999):
            if(inode.atime > 0 and inode.mtime > 0 and inode.ctime > 0):
                return inode
            else:
                return None
        else:
            return None

    def scan(self, loadpath, deep_scan=False):
        # self._inodes = self._find_inodes()
        # self._directs = self._find_directs()
        # return self._directs
        # Make sure we have the correct structures
        # Mapping of address to Inode
        inodeMap = {}
        # Mapping of address to Direct
        directsList = []
        # Mapping of address to collection of Direct
        directoryMap = {}

        import os

        loaded_from_file = False

        if os.path.exists(loadpath + '\\inodes.txt') and os.path.exists(loadpath + '\\directories.txt'):
            # Load offsets from previous results that have been stored in the above two txt files
            # Inodes.txt has offsets to all inodes
            # Directs.txt has offsets to all directs
            # We just load each offset, then go to the offset in the disk and read the structures
            # into the inodes_found and directs_found variables
            print("Loading from files")
            inodes_list = []
            with open(loadpath + '\\inodes.txt', 'r') as fp:
                inodes_list = fp.readlines()
            directories = []
            with open(loadpath + '\\directories.txt', 'r') as fp:
                directories = fp.readlines()
            # directs_list = []
            # with open('directs.txt', 'r') as fp:
            #     directs_list = fp.readlines()

            # Not really
            max_file_length = self._stream.getLength()

            for line in inodes_list:
                offset = int(line.strip())
                if offset in self._active_inodes:
                    continue
                self._stream.seek(offset)
                data = self._stream.read(0x100)
                inode = Inode.from_buffer(bytearray(data))
                if inode.mode == 0:
                    continue
                if inode.nlink > 0x10:
                    continue
                if inode.size > max_file_length:
                    continue
                #print(oct(inode.mode))
                inode.set_offset(offset)
                inodeMap[offset] = inode

            for line in directories:
                offset = int(line.strip())
                self._stream.seek(offset)
                directory = self._extract_directs(offset)
                directsList.extend(directory.get_directs())
                directoryMap[offset] = directory

            loaded_from_file = True
        else:
            # There are no saved results, let's start a new scan
            print(f"No previous scan found in {loadpath}")
            print("Scanning drive")
            assert(ctypes.sizeof(Direct) == 0x8)
            assert(ctypes.sizeof(Inode) == 0x100)

            inode_block_offset = self._iblkno * self._fsize
            data_block_offset = self._dblkno * self._fsize
            cgsize = self._fpg * self._fsize
            data_block_length = (cgsize - data_block_offset) + 0x14000

            max_block_index = self._stream.getLength() / self._fsize

            def is_valid_block_table(indexes):
                for x in range(2+12+3):
                    index = int.from_bytes(indexes[(x*8):(x*8)+8], byteorder='big')
                    if -1 <= index > max_block_index:
                        return False
                return True

            # Start scan for deleted files
            if deep_scan is False :
                for cyl in range(self._ncg): #range(151, 345): #self._ncg):
                    cyl_offset = (self._fpg * self._fsize) * cyl
                    print(f"Scanning cylinder group: {cyl}: {cyl_offset:X}")

                    # Read in the inode table
                    inode_table_offset = cyl_offset + inode_block_offset
                    inode_table_size = self._ipg * 0x100
                    self._stream.seek(inode_table_offset, 0)
                    inode_table = self._stream.read(inode_table_size)

                    # Check for any deleted inodes
                    # We go through each inode in the inode table
                    for i in range(self._ipg):
                        data = inode_table[i * 0x100: i*0x100+0x100]
                        # Check if any of the ib, db, or extb fields have any data
                        indexes = data[0x70:0xF8]
                        # TODO: Definitely need to add more checks, we keep running into bad inodes
                        # Check if indexes is all zero
                        if not any(indexes):
                            continue
                        if not is_valid_block_table(indexes):
                            continue
                        # Get the offset of this inode
                        inode_offset = inode_table_offset + (i * 0x100)
                        # Check if this inode is a non-deleted inode
                        #if True:
                        if inode_offset not in self._active_inodes:
                            inode = self._read_inode_at_offset(inode_offset)
                            # Check if this is an inode
                            if inode:
                            # This inode was deleted, so add it to the list
                            inode_index = (cyl * self._ipg) + i
                            print(f"Inode found at index {inode_index}, offset: 0x{inode_offset:X}")
                            # TODO: Maybe move this up instead of doing slicing
                            inode = Inode.from_buffer(bytearray(data))
                            inode.set_offset(inode_offset)
                            inodeMap[inode_offset] = inode

                    # Get the offset of the data block
                    data_start = cyl_offset + data_block_offset
                    data_end = data_start + data_block_length

                    # Check the data block sections at a time for direct tables
                    offset = data_start
                    bytesLeft = data_block_length
                    while offset < data_end:
                        # print(hex(offset))
                        # Load a buffer into memory
                        self._stream.seek(offset, 0)
                        bufSize = min(bytesLeft, 0x100000)
                        buf = self._stream.read(bufSize)
                        # Check every 0x800 bytes in the buffer for a direct table
                        for block in range(0, bufSize, 0x800):
                            # First we'll check the first 0x18 bytes for the first two direct's
                            dirents = buf[block:block+0x18]
                            # These tests check the d_type, d_namlen, and d_name fields
                            test1 = dirents[6] == 0x4 and dirents[7] == 0x1 and dirents[8:9] == b'.'
                            if not test1:
                                continue
                            test2 = dirents[0x12] == 0x4 and dirents[0x13] == 0x2 and dirents[0x14:0x16] == b'..'
                            if test2:
                                print(f"Direct table found at: 0x{offset+block:X}")
                                # We found a direct table, so lets read out the entire table
                                directory = self._extract_directs(offset+block)
                                directsList.extend(directory.get_directs())
                                directoryMap[offset+block] = directory

                        bytesLeft -= bufSize
                        offset += bufSize
            else:
                drive_length = self._stream.getLength()
                for offset in range(0, drive_length, self._fsize):
                    self._stream.seek(offset)
                    # Check if directs
                    direct_check = self._stream.read(0x18)
                    test1 = direct_check[6] == 0x4 and direct_check[7] == 0x1 and direct_check[8:9] == b'.'
                    if test1:
                        test2 = direct_check[0x12] == 0x4 and direct_check[0x13] == 0x2 and direct_check[0x14:0x16] == b'..'
                        if test2:
                            print(f"Direct table found at: 0x{offset:X}")
                            # We found a direct table, so lets read out the entire table
                            directory = self._extract_directs(offset)
                            directsList.extend(directory.get_directs())
                            directoryMap[offset] = directory
                            continue
                    # Check if inode
                    inode = self._read_inode_at_offset(offset)
                    if inode:
                        inodeMap[offset] = inode
                        _offset = offset + 0x100
                        while _offset < offset + scan_interval:
                            inode = self._read_inode_at_offset(_offset)
                            if inode:
                                inodeMap[_offset] = inode
                                _offset += 0x100
                            else:
                                break
                                
                    if (offset & 0xfffffff) == 0:
                        print(f"Percent Complete: {round((offset/drive_length)*100,2)}%")
                                           
        print("Finished scanning. Now analyzing...")

        # Save the offsets to files so we don't have to go through the entire disk again
        if not os.path.exists(loadpath + "\\"):
            os.mkdir(loadpath + "\\")
        if not loaded_from_file:
            with open(loadpath + '\\inodes.txt', 'w') as fp:
                for inode in inodeMap:
                    fp.write(f"{inode}\n")
            with open(loadpath + '\\directs.txt', 'w') as fp:
                for direct in directsList:
                    fp.write(f"{direct}\n")
            with open(loadpath + '\\directories.txt', 'w') as fp:
                for directory in directoryMap:
                    fp.write(f"{directory}\n")

        def ino_to_offset(ino):
            cyl_index = (ino // self._ipg)
            cyl_offset = (cyl_index * (self._fpg * 0x1000))
            inode_table_offset = self._iblkno * 0x1000
            inode_offset = (ino - (self._ipg * cyl_index)) * 0x100
            return cyl_offset + inode_table_offset + inode_offset

        def inode_is_directory(inode):
            data_offset = inode.db[0] * self._fsize
            return inode.mode & 0x4000 or data_offset in directoryMap

        # Relationship matching
        #
        # Direct (d_ino) -> Inode (di_db[]) -> Direct[]
        # - Normal relationship
        #   - Should have complete information for files
        #
        # Inode -> Direct[]
        # - Missing Direct
        #   - The folder will have a missing name
        #   - Other attributes will be available
        #   - Will need to detect whether it is a file or directory
        #   - We can check if it is a directory by check the first 2 direct's
        # 
        # Direct[] (["."] d_ino) -> Direct (or Direct -> Direct[])
        # - Missing Inode
        #   - Match a directory with it's folder's name through the ".." entry
        #
        # Direct[] (".." d_ino)
        # - Missing parent direct
        #   - Group directories by their parent ino

        # List of recovered nodes
        nodes = []

        # Set of claimed inodes
        # This will be used to create nodes for any inodes that aren't claimed
        # by a Direct
        claimedInodes = set()

        # Set of claimed directories
        claimedDirectories = set()

        # Mapping of ino's to direct's
        # This will be used later on for Directory to Direct matching
        inoDirectMap = {}

        parentDirectoryMap = {}

        # Mapping of Direct to Node
        # This will be used to look up a Node by it's Direct
        directNodeMap = {}

        # Mapping of Inode to Node
        # This will be used to look up a Node by it's Inode
        #inodeNodeMap = {}  # Unused at the moment

        # Active Filesystem
        for direct_offset in self._active_directs:
            #  Create Direct
            self._stream.seek(direct_offset)
            buf = self._stream.read(self._bsize)
            direct = self.read_direct(buf,0)
            if not direct:
                continue
            # Create Inode
            inode_offset = ino_to_offset(direct.ino)
            self._stream.seek(inode_offset)
            inode_data = self._stream.read(0x100)
            inode = Inode.from_buffer(bytearray(inode_data))
            inode.set_offset(inode_offset)
            # Add the inode to the map
            self._scan_results.inodeMap[inode_offset] = inode

        # Create directories for active files on the filesystem
        for direct_offset in self._active_directs:
            self._stream.seek(direct_offset-0x18)
            buf = self._stream.read(self._fsize)
            direct = self.read_direct(buf,0)
            if not direct:
                continue
            name = direct.get_name()
            if name == '.':
                directory = self._extract_directs(direct_offset-0x18, False)
                self._scan_results.directsList.extend(directory.get_directs())
                self._scan_results.directoryMap[direct_offset-0x18] = directory
        
        t1 = time.time()
        # Populate the inoDirectMap
        for direct in directsList:
            name = direct.get_name()
            if name == '..' or name == '.':
                continue
            # TODO: Allow multiple entries
            ino = direct.ino
            if ino in inoDirectMap:
                print(f"Warning: Duplicate ino usage for direct {name} (ino={ino} , direct={direct.get_offset()})")
                continue
            inoDirectMap[ino] = direct
        t2 = time.time()
        print(f"Step 1: {t2 - t1}")

        t1 = time.time()
        # Create an initial list of Node's using Direct's
        for direct in directsList:
            node = None
            if direct.type == 0x4:
                node = Node(NodeType.DIRECTORY)
            else:
                node = Node(NodeType.FILE)
            if direct.get_offset() in self._active_directs:
                node.set_active(True)
            inode_offset = ino_to_offset(direct.ino)
            node.set_direct(direct)
            node.set_direct_offset(direct.get_offset())
            node.set_inode_offset(inode_offset)
            node.set_name(direct.get_name())
            inode = inodeMap.get(inode_offset)
            directNodeMap[direct.get_offset()] = node
            if inode:
                node.set_inode(inode)
                node.set_size(inode.size)
                node.set_creation_time(inode.ctime)
                node.set_last_access_time(inode.atime)
                node.set_last_modified_time(inode.mtime)
                claimedInodes.add(inode.get_offset())
            nodes.append(node)
        t2 = time.time()
        print(f"Step 2: {t2 - t1}")

        t1 = time.time()
        # Create Node's for any inode's that weren't claimed
        for inode in inodeMap.values():
            if inode.get_offset() in claimedInodes:
                continue
            node = None
            # TODO: This checks if there is a direct at the first block
            #  We can also check the following:
            #   - there is a recovered direct table
            #   - if the inode's IFDIR (0040000) is set in di_mode
            #   - 0100000 is set for files (IFREG)
            if inode_is_directory(inode):
                node = Node(NodeType.DIRECTORY)
            else:
                node = Node(NodeType.FILE)
            node.set_inode(inode)
            node.set_inode_offset(inode.get_offset())
            node.set_size(inode.size)
            node.set_creation_time(inode.ctime)
            node.set_last_access_time(inode.atime)
            node.set_last_modified_time(inode.mtime)
            claimedInodes.add(inode.get_offset())
            nodes.append(node)
        t2 = time.time()
        print(f"Step 3: {t2 - t1}")

        t1 = time.time()
        # Now create relationships between nodes
        # Creates normal relationships with or without the directory name (direct)
        for node in nodes:
            inode = node.get_inode()
            if not inode:
                continue
            offset = inode.db[0] * self._fsize
            directory = directoryMap.get(offset)
            if directory:
                if inode.db[1] != 0:
                    print(f"Warning: Node \"{node.get_name()}\" uses multiple blocks.")
                for direct in directory.get_directs():
                    child = directNodeMap.get(direct.get_offset())
                    node.add_child(child)
                    child.add_parent(node)
                claimedDirectories.add(directory.get_offset())
        t2 = time.time()
        print(f"Step 4: {t2 - t1}")

        t1 = time.time()
        # Connect child directories with parent directories
        # Matches direct -> direct[] using the "." (this folder) direct.
        for directory in directoryMap.values():
            if directory.get_offset() in claimedDirectories:
                continue
            upperDirect = directory.get_direct(".")
            parentDirect = inoDirectMap.get(upperDirect.ino)
            if not parentDirect:
                continue
            parentNode = directNodeMap.get(parentDirect.get_offset())
            if parentNode.get_type() == 1:
                for direct in directory.get_directs():
                    child = directNodeMap.get(direct.get_offset())
                    parentNode.add_child(child)
                    child.add_parent(parentNode)
                directory_offset = directory.get_offset()
                claimedDirectories.add(directory_offset)
        t2 = time.time()
        print(f"Step 5: {t2 - t1}")

        # for directory in directoryMap.values():
        #     offset = directory.get_offset()
        #     if offset in claimedDirectories:
        #         continue
        #     parentDirect = directory.get_direct("..")
        #     parentDirectoryMap[offset] = parentDirect.ino

        # tempnodes = {}
        # for offset in parentDirectoryMap:
        #     ino = parentDirectoryMap[offset]
        #     if ino == 2:s
        #         continue
        #     if ino not in tempnodes:
        #         tempnodes[ino] = Node(NodeType.DIRECTORY)
        #     node = tempnodes[ino]
        #     node.set_name(f"FolderInode{ino}")
        #     directory = directoryMap[offset]
        #     for direct in directory.get_directs():
        #         child = directNodeMap.get(direct.get_offset())
        #         node.add_child(child)
        #         child.add_parent(node)
        #     claimedDirectories.add(offset)

        # nodes.extend(tempnodes.values())

        t1 = time.time()
        # Create nodes for unclaimed directories
        for directory in directoryMap.values():
            offset = directory.get_offset()
            if offset in claimedDirectories:
                continue
            node = Node(NodeType.DIRECTORY)
            node.set_directory_offset(directory.get_offset())
            for direct in directory.get_directs():
                child = directNodeMap.get(direct.get_offset())
                node.add_child(child)
                child.add_parent(node)
            nodes.append(node)
        t2 = time.time()
        print(f"Step 6: {t2 - t1}")

        root_nodes = []
        for node in nodes:
            if len(node.get_parents()) == 0:
                root_nodes.append(node)

        print_directory(root_nodes)

        return root_nodes

    def _extract_directs(self, addr, ignore_active=True):
        result = Directory(addr)
        started = False

        # Initial buffer
        self._stream.seek(addr)
        buf = self._stream.read(self._bsize)

        offset = 0
        direct = self.read_next_direct(buf, offset)

        while True:

            name = direct.get_name()

            # Check if we've run into another directory
            if name == '.' or name == '..':
                if not started and name == '..':
                    started = True
                elif started and name == '.':
                    return result

            absolute_offset = (addr+offset)
            #if True:
            if absolute_offset not in self._active_directs and name != "." and name != ".." and ignore_active:
            if absolute_offset not in self._active_directs or not ignore_active:
                direct.set_name(name)
                direct.set_offset(addr+offset)
                result.add_direct(direct)

            # We hit the end of a block
            # Maybe continue reading?
            if offset >= 0x4000:
                print(f"Warning: Hit end of block when parsing direct table at 0x{addr:X}!")
                return result

            expected_length = (8 + direct.namlen)
            if expected_length % 4 == 0:
                expected_length += 4
            else:
                expected_length = ((expected_length + 0x3) & 0xFFFFFFFC)
            expected_end = offset + expected_length
            direct_end = offset + direct.reclen
            
            if (expected_end + 8) >= 0x4000:
                print(f"Warning: Hit end of block when parsing direct table at 0x{addr:X}!")
                return result

            # TODO: Check if both expected_end and direct_end are the same
            direct = self.read_next_direct(buf, expected_end)
            if not direct:
                if (direct_end + 8) >= 0x4000:
                    print(f"Warning: Hit end of block when parsing direct table at 0x{addr:X}!")
                    return result
                direct = self.read_next_direct(buf, direct_end)
                if not direct:
                    if (expected_end + 0x40) >= 0x4000:
                        direct = None
                    else:
                        direct = self.find_trailing_directs(buf, expected_end, 0x40)
                    if not direct:
                        return result
                offset = direct_end
            else:
                offset = expected_end

    # I don't know if this ever returns true
    def find_trailing_directs(self, buffer, start_offset, search_dist):
        for offset in range(start_offset, start_offset+search_dist):
            direct = self.read_next_direct(buffer, offset)
            if direct is not None:
                print(f"Found a trailing direct! {direct._name}")
                return direct
        return None

    def read_next_direct(self, buffer, offset):
        buf = bytearray(buffer[offset:offset+8])
        direct = Direct.from_buffer(buf)

        if direct.ino > self._ninodes:
            return None

        if direct.reclen % 4 != 0:
            return None

        if direct.reclen == 0 or direct.reclen > 0x200:
            return None

        if direct.namlen > 255 or direct.namlen == 0:
            return None

        if direct.type not in (0,1,2,3,4,6,8,10,12,14):
            return None

        name = ''
        try:
            name = buffer[offset+8:offset+8+direct.namlen].decode('ascii')
        except:
            return None

        direct.set_name(name)
        
        return direct


def print_directory(root, depth=0):
    for inode in root:
        # direct = node.get_name()
        if inode.get_name() == '.' or inode.get_name() == '..':
            continue
        typ = 'File' if inode.get_type() == 0 else 'Directory'
        inode_offset = hex(inode.get_inode_offset()) if inode.get_inode_offset() else 'None'
        direct_offset = hex(inode.get_direct_offset()) if inode.get_direct_offset() else 'None'
        inode_index = 'None'
        if inode.get_direct():
            inode_index = hex(inode.get_inode_index())
        print('    '*depth + str(inode.get_name()) + f' (Type:{typ}, HasInode:{inode.get_inode() != None}, InodeOffset:{inode_offset}, InodeIndex:{inode_index} , DirectOffset:{direct_offset})')
        if inode.get_type() == 1:
            print_directory(inode.get_children(), depth+1)

import tkinter as tk
import tkinter.ttk as ttk
from tkinter import simpledialog
from tkinter import filedialog
from tkinter import Entry, Label
import time
from PIL import Image, ImageTk

all_filesigs = [a_filesig for a_filesig in FileSignature.__subclasses__()]

class App(tk.Frame):
    def __init__(self, master, nodes, disk):
        
        self.item_right_click_on = None
        self._search_text = ""
        self.recovered_files = 0
        self.recovered_inodes = 0
        self.recovered_directs = 0
        
        # Disk
        self._partition = disk.getPartitionByName('dev_hdd0')
        self._stream = self._partition.getDataProvider()

        # fs_bsize
        self._stream.seek(0x10000 + 0x30)
        self._bsize = int.from_bytes(self._stream.read(4), byteorder='big')

        # fs_fsize
        self._stream.seek(0x10000 + 0x34)
        self._fsize = int.from_bytes(self._stream.read(4), byteorder='big')

        self.max_block_index = self._partition.getLength() / self._fsize

        self._master = master
        self._master.geometry("1200x800")
        self._nodes = nodes

        tk.Frame.__init__(self, master)

        self.pack(fill='both', expand=True)
        # mainframe = tk.Frame(self)
        # mainframe.pack(fill='both', expand=True)
        tree_columns = ('filesize', 'cdate', 'mdate', 'adate', 'doff', 'ioff', 'hino')
        self.tree = ttk.Treeview(self, columns=tree_columns)
        ysb = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        xsb = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscroll=ysb.set, xscroll=xsb.set)
        self.tree.heading('#0', text='Contents', anchor='w')
        self.tree.heading('filesize', text='File Size', anchor="w") #, command=lambda: self.sort_column(2, False))
        self.tree.heading('cdate', text='Date Created', anchor="w")
        self.tree.heading('mdate', text='Date Modified', anchor="w")
        self.tree.heading('adate', text='Date Accessed', anchor="w")
        #self.tree.heading('doff', text='Direct Offset')
        #self.tree.heading('ioff', text='Inode Offset')
        #self.tree.heading('hino', text='Has Inode')

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.folder_ico = ImageTk.PhotoImage(Image.open('assets/icon-folder.png'))
        self.folder_direct_ico = ImageTk.PhotoImage(Image.open('assets/icon-folder-direct.png'))
        self.folder_direct_ref_ico = ImageTk.PhotoImage(Image.open('assets/icon-folder-direct-ref.png'))
        self.folder_inode_ico = ImageTk.PhotoImage(Image.open('assets/icon-folder-inode.png'))
        self.folder_recovered_ico = ImageTk.PhotoImage(Image.open('assets/icon-folder-recovered.png'))
        self.file_ico = ImageTk.PhotoImage(Image.open('assets/icon-file.png'))
        self.file_direct_ico = ImageTk.PhotoImage(Image.open('assets/icon-file-direct.png'))
        self.file_inode_ico = ImageTk.PhotoImage(Image.open('assets/icon-file-inode.png'))
        self.file_warning_ico = ImageTk.PhotoImage(Image.open('assets/icon-file-warning.png'))
        self.file_recovered_ico = ImageTk.PhotoImage(Image.open('assets/icon-file-recovered.png'))
        

        # Make the content column wider than others
        self.tree.column("#0", minwidth=0, width=400)

        # self.pack()
        root_node = self.tree.insert('', tk.END, text='root', image=self.folder_direct_ref_ico)
        self.node_map = {}
        print("Processing directories...")
        self.process_directory(root_node, nodes)
        print(f"Fully Recovered: {self.recovered_files} files!")
        print(f"Inodes: {self.recovered_inodes} inodes!")
        print(f"Directs: {self.recovered_directs} directs!")
        print("Sorting directories...")
        self.sort_root_folders_to_top()
        # self.tree.grid(sticky='nesw')
        # self.tree.pack(side='left', fill='both', expand=True)

        self.tree.grid(row=0, column=0, sticky='nesw')
        ysb.grid(row=0, column=1, sticky='ns')
        xsb.grid(row=1, column=0, sticky='ew')
        # self.grid()
        master.bind('<Control-f>', self.find)
        master.bind('<F3>', self.find_next)
        master.bind('<Shift-F3>', lambda event:self.find_next(event, True)) # Previous
        self._nodes = self.get_all_nodes()

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label='Recover Selected',
                                      command=self.recover_selected_files)
        self.context_menu.add_command(label='Get Info',
                                      command=self.display_file_info)
        self.tree.bind("<ButtonRelease-3>", self.open_context_menu)
    
    def open_context_menu(self, event):
        item = self.tree.identify('row', event.x, event.y)
        self.item_right_click_on = item
        #self.tree.selection_set(item)
        #self.tree.focus(item)
        self.context_menu.tk_popup( event.x_root + 60, event.y_root + 10, 0)
    
    def identify_file(self, node):
        if node.get_direct() is None:
            inode:Inode = node.get_inode()
            file_offset = inode.db[0] * self._fsize
            idenfified = False
            if(file_offset > self.max_block_index):
                return
            for filesig in all_filesigs:
                self._stream.seek(file_offset)
                sig = filesig(self._stream, file_offset)
                if(sig.test()):
                    node._filesignature = sig
                    idenfified = True
                    break

    def display_file_info(self):
        info_window = tk.Toplevel()
        info_window.geometry("250x200")
        info_window.title(f"{self.tree.item(self.item_right_click_on)['text']} Info")

        def add_attribute_row_item(label, value, row):
            entryText = tk.StringVar()
            entryText.set(value)
            lbl = Label(info_window, text=f'{label:<20}')
            entry = Entry(info_window, textvariable=entryText, state='readonly')
            lbl.grid(row=row, column=0, padx=2)
            entry.grid(row=row, column=1)

        add_attribute_row_item( "Filename: ",
                                self.tree.item(self.item_right_click_on)['text'],
                                0)
        add_attribute_row_item( "Direct Offset: ",
                                self.node_map[self.item_right_click_on].get_direct_offset(),
                                1)
        add_attribute_row_item( "Inode Offset: ",
                                self.node_map[self.item_right_click_on].get_inode_offset(),
                                2)
        add_attribute_row_item( "Has Inode: ",
                                'True' if self.node_map[self.item_right_click_on].get_inode() else 'False',
                                3)
        
    def recover_selected_files(self):
        print("Recover files...")
        recover_items = []
        for item in self.tree.selection():
            recover_items.append(item)
            child_items = self.get_all_nodes(item)
            for item in child_items:
                recover_items.append(item)

        outpath = filedialog.askdirectory()

        for item in recover_items:
            node:Node = self.node_map[item]

            # Create any parent folders for the file
            path = outpath + "\\" + self.get_item_full_path(item)
            path = os.path.normpath(path)
            dirname = os.path.dirname(__file__)
            fullpath = os.path.join(dirname, path)
            if not os.path.exists(fullpath):
                os.makedirs(fullpath)
                self.set_ts(fullpath, node)
            
            # Read blocks
            if node.get_type() == NodeType.FILE:

                blocks = []
                file_bytes = bytearray()
                inode = node.get_inode()

                # If an inode exists read the inodes blocks
                if inode is not None:
                    # Read direct blocks
                    blocks = inode.get_block_indexes(self._stream, self._fsize)
                    
                    # Read data
                    remaining = node.get_size()
                    for block in blocks:
                        if block > self.max_block_index:
                            block = 0
                        self._stream.seek(block * self._fsize)
                        while remaining > 0:
                            read = min(remaining, self._bsize)
                            file_bytes += self._stream.read(read)
                            remaining -= read
                
                # Write the file     
                file_path = fullpath + "\\" + self.tree.item(item)['text']
                file_path = os.path.normpath(file_path)

                with open(file_path, 'wb') as f:
                    f.write(file_bytes)
                
                self.set_ts(file_path, node)
            
                print("Recovered: {}".format(file_path))

        

    def set_ts(self, path, node):
        if node.get_inode() is None:
            return
        atime = node.get_last_access_time()
        mtime = node.get_last_modified_time()

        os.utime(path, (atime, mtime))

    def get_item_full_path(self, item):
        path = ""
        current_parent = str(self.tree.parent(item))
        while True:
            if current_parent == "I001":
                return path
            path = self.tree.item(current_parent)['text'] + "\\" + path
            current_parent = str(self.tree.parent(current_parent))

    def get_all_nodes(self, node=None):
        nodes = []
        for child in self.tree.get_children(node):
            nodes.append(child)
            if self.tree.get_children(child):
                nodes.extend(self.get_all_nodes(child))
        return nodes

    def sort_column(self, column, reverse):
        items = self.tree.get_children('I001')
        l = [(self.tree.set(k, column), k) for k in items]
        l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        
        self.tree.heading(column, command=lambda: \
            self.sort_column(column, not reverse))

    def sort_root_folders_to_top(self):
        items = self.tree.get_children('I001')
        for item in items:
            if self.node_map[item].get_type() == NodeType.DIRECTORY:
                self.tree.move(item,'I001',0)

    def find_text(self, query, start=None, reversed=False):
        start_index = 0
        end_index = 0 if reversed else len(self._nodes)
        increment = -1 if reversed else 1
        offset = -1 if reversed else 1
        if start:
            for i, node in enumerate(self._nodes):
                if node == start:
                    start_index = i
        for i in range(start_index+offset, end_index, increment):
            text = self.tree.item(self._nodes[i])['text']
            if query in text.lower():
                return self._nodes[i]
        for i in range(end_index, start_index, increment):
            text = self.tree.item(self._nodes[i])['text']
            if query in text.lower():
                return self._nodes[i]
        return None
    
    def find_next(self, event, reversed=False):
        if self._search_text != '':
            focused = self.tree.focus()
            found = self.find_text(self._search_text, focused, reversed)
            if found:
                self.tree.see(found)
                self.tree.focus(found)
                self.tree.selection_set(found)

    def find(self, event):
        print("Find")
        query = simpledialog.askstring("Find File", "Enter file name:", initialvalue=self._search_text,
            parent=self)
        if query:
            self._search_text = query.lower()
            focused = self.tree.focus()
            found = self.find_text(self._search_text, focused)
            if found:
                self.tree.see(found)
                self.tree.focus(found)
                self.tree.selection_set(found)

    def check_if_inode_indexes_valid(self, node):
        def check_if_indexes_valid(indexes):
            for index in indexes:
                if index > self.max_block_index:
                    return False
            return True
        if node.get_type() == NodeType.FILE:
                # If an inode exists read the inodes blocks
                if node.get_inode() is not None:
                    print(f"Checking if inode is valid at offset: {node.get_inode_offset():X}")
                    # Check indirect blocks
                    for block in node.get_inode().db:
                        if block > self.max_block_index:
                            return False
                    
                    # Check indirect blocks
                    if node.get_inode().ib[0] > 0:
                        btable_index = node.get_inode().ib[0]
                        if btable_index > self.max_block_index:
                            return False
                        btable = self.read_block_indexes(btable_index)
                        if not check_if_indexes_valid(btable):
                            return False
           
                    if node.get_inode().ib[1] > 0:
                        ib_table_index = node.get_inode().ib[1]
                        if ib_table_index > self.max_block_index:
                            return False
                        ib_table = self.read_block_indexes(ib_table_index)
                        if not check_if_indexes_valid(ib_table):
                            return False
                        for btable_index in ib_table:
                            if not check_if_indexes_valid(self.read_block_indexes(btable_index)):
                                return False
                    
                    if node.get_inode().ib[2] > 0:
                        ib_ib_table_index = node.get_inode().ib[2]
                        if ib_ib_table_index > self.max_block_index:
                            return False
                        ib_ib_table = self.read_block_indexes(ib_ib_table_index)
                        if not check_if_indexes_valid(ib_ib_table):
                            return False
                        for ib_table in ib_ib_table:
                            if not check_if_indexes_valid(ib_table):
                                return False
                            for btable_index in ib_table:
                                if not check_if_indexes_valid(self.read_block_indexes(btable_index)):
                                    return False
        return True

    def process_directory(self, parent, nodes):
        for node in nodes:
            node:Node
            # Exclude meta data
            if node.get_name() == '.' or node.get_name() == '..':
                continue
            # Exclude directories at the root with no children
            if node.get_type() != NodeType.FILE and len(node.get_children()) <= 2 and str(parent) == "I001" and not node.get_active():
                continue
            # Data
            size = node.get_size()
            ctime = node.get_creation_time()
            atime = node.get_last_access_time()
            mtime = node.get_last_modified_time()
            direct_offset = hex(node.get_direct_offset()) if node.get_direct_offset() else 'None'
            inode_offset = hex(node.get_inode_offset()) if node.get_inode_offset() else 'None'
            has_inode = str(node.get_inode() is not None)
            # Icon
            if node.get_type() == NodeType.FILE:
                valid = self.check_if_inode_indexes_valid(node)
                if node.get_inode() and node.get_direct():
                    if node.get_active() is True:
                        icon = self.file_ico
                    else:
                    icon = self.file_recovered_ico
                    self.recovered_files += 1
                elif node.get_inode():
                    icon = self.file_inode_ico
                    self.recovered_inodes += 1
                elif node.get_direct():
                    icon = self.file_direct_ico
                    self.recovered_directs += 1
                if not valid:
                    icon = self.file_warning_ico
            else:
                if node.get_inode() and node.get_direct():
                    if node.get_active() is True:
                        icon = self.folder_ico
                    else:
                    icon = self.folder_recovered_ico
                    self.recovered_files += 1
                elif node.get_inode():
                    icon = self.folder_inode_ico
                    self.recovered_inodes += 1
                elif node.get_direct():
                    icon = self.folder_direct_ico
                    self.recovered_directs += 1
                else:
                    icon = self.folder_direct_ref_ico
            # Name
            name = node.get_name()
            if not node.get_direct() and not node.get_inode() and node.get_directory_offset():
                name = f"Folder{node.get_directory_offset():X}"
            elif not node.get_direct() and node.get_inode():
                self.identify_file(node)
                name = f"Inode{node.get_inode_offset():X}{node._filesignature.extension if node._filesignature is not None else ''}"
            # Tree Item
            item = self.tree.insert(parent, tk.END, text=name,
                values=(
                f'{self.format_bytes(size):<10} ({size} bytes)' if size else '',
                time.ctime(ctime) if ctime and ctime < 32536799999 else '',
                time.ctime(atime) if atime and atime < 32536799999 else '',
                time.ctime(mtime) if mtime and mtime < 32536799999 else '',
                #direct_offset,
                #inode_offset,
                #has_inode
                ),
                image=icon,
                tags = (str(node.get_inode_offset())))
            self.node_map[item] = node
            if node.get_type() == 1:
                self.process_directory(item, node.get_children())

    def format_bytes(self, filesize):
        for count in ['bytes','KB','MB','GB']:
            if filesize > -1024.0 and filesize < 1024.0:
                return "%3.2f%s" % (filesize, count)
            filesize /= 1024.0
        return "%3.2f%s" % (filesize, 'TB')

def main(path, keyfile=None, deep_scan=False):
    with open(path, 'rb') as fp:
        stream = disklib.FileDiskStream(path)
        config = disklib.DiskConfig()
        config.setStream(stream)
        
        if keyfile:
            keys = open(keyfile, 'rb').read()
            config.setKeys(keys)
        else:
            print("\nDecrypted drive support is broken currently... \nOpen an encrypted drive with a keyfile")

        disk = disklib.DiskFormatFactory.detect(config)
        
        scanner = Scanner2(disk, 0x200)
        
        load_path = os.path.normpath(f"{os.getcwd()}\\scans") + "\\" + os.path.basename(path).split(".")[0]
        load_path = load_path.lower()

        inodes = scanner.scan(load_path,deep_scan)


        root = tk.Tk()
        root.title("PS Recovery Prototype")
        app = App(root, inodes, disk)
        app.mainloop()

import argparse

if __name__ == "__main__":
    if len(sys.argv) == 1 or len(sys.argv) > 4:
        print(f"Usage: {sys.argv[0]}\n Encrypted Image: <image path> <keyfile path> \n Decrypted Image: <image path> \n Optional: --deep-scan")
        exit()

    deep_scan = False
    img_path = sys.argv[1]
    key_path = None

    if(len(sys.argv) == 3):
        if (sys.argv[2] == '--deep-scan'):
            deep_scan = True
        else:
            key_path = sys.argv[2]

    if(len(sys.argv) == 4):
        key_path = sys.argv[2]
        if (sys.argv[3] == '--deep-scan'):
            deep_scan = True
        
    main(img_path, key_path, deep_scan)
