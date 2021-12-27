import ctypes
import time
import os
from datetime import timedelta

import disklib

from common.logger import Logger
from .ufs import InodeReader, get_direct_class, get_inode_class, ino_to_offset, inode_is_directory, SuperBlock, endianness, Endianness
from analysis.node import Node, NodeType
import analysis.ufs

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
        Logger.log('    '*depth + str(inode.get_name()) + f' (Type:{typ}, HasInode:{inode.get_inode() != None}, InodeOffset:{inode_offset}, InodeIndex:{inode_index} , DirectOffset:{direct_offset})')
        if inode.get_type() == 1:
            print_directory(inode.get_children(), depth+1)

class Directory:
    def __init__(self, offset):
        self._offset = offset
        self._directs = {}
    def combine_directories(self, directory):
       self._directs.update( directory._directs )
    def add_direct(self, direct):
        self._directs[direct.get_name()] = direct
    def get_direct(self, name):
        if not name in self._directs.keys():
            return None
        return self._directs[name]
    def get_directs(self):
        return self._directs.values()
    def get_offset(self):
        return self._offset


class ScanResults:
    def __init__(self, superblock, partition_name, active_directs, active_inodes):
        # Mapping of address to Inode
        self.inode_map = {}
        # Mapping of address to Direct
        self.directs_map = {}
        # Mapping of address to collection of Direct
        self.directory_map = {}
        # Map an ino to map of directs that reference the inode
        self.ino_direct_map = {}
        # The super block of the hdd these results are from
        self.superblock:SuperBlock = superblock
        # Name of the partition this scan belongs to
        self.partition_name = partition_name
        # Directs in the active file system
        self.active_directs = active_directs
        # Inodes in the active file system
        self.active_inodes = active_inodes
    
    def add_directory(self, directory):
        self.directory_map[directory.get_offset()] = directory
        for direct in directory.get_directs():
            self.add_direct(direct)

    def add_inode(self, inode):
        self.inode_map[inode.get_offset()] = inode
        return True

    def add_direct(self, direct):
        if direct.get_name() == "." or direct.get_name() == "..":
            return False
        self.directs_map[direct.get_offset()] = direct
        self.ino_direct_map[direct.ino] = direct
        return True


class Scanner:
    def __init__(self, disk, partition_name):
        self._stream = None  # The stream we will ultimately be reading from
        self._superblock =  None
        self._partition_name = partition_name
        self.scan_results = None
        self._loaded_from_files = False
        self._initialize(disk, partition_name)

    def _initialize(self, disk, partition_name):
        partition = disk.getPartitionByName(partition_name)
        self._stream = partition.getDataProvider()
        self._inode_reader = InodeReader(self._stream)

        self._superblock = SuperBlock(self._stream)
        
        vfs = partition.getVfs()
        vfs.mount()
        if not vfs.isMounted():
            raise Exception("Vfs failed to mount!")
        root = vfs.getRoot()

        self._active_inodes = self._get_all_offsets(root, 'inode')
        self._active_directs = self._get_all_offsets(root, 'dirent')
        self._ninodes = (self._superblock.ipg * self._superblock.ncg)
        self.max_block_index = self._stream.getLength() / self._superblock.fsize
        self.inode_class = get_inode_class()
        self.direct_class = get_direct_class()

        self.scan_results = ScanResults(self._superblock, self._partition_name, self._active_directs, self._active_inodes)
    
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
            index = int.from_bytes(indexes[(x*8):(x*8)+8], byteorder=analysis.ufs.endianness)
            if index > self.max_block_index or index < 0:
                return False
        return True

    def _get_year_from_sec(self, sec):
        if sec > 32536799999 or sec <= 0:
            return 0
        return time.strptime(time.ctime(sec)).tm_year
    
    def _check_inode_has_valid_time(self, inode):
        min_year = 2000
        max_year = 2050
        if self._get_year_from_sec(inode.atime) > max_year or self._get_year_from_sec(inode.atime) < min_year:
            return False
        if self._get_year_from_sec(inode.mtime) > max_year or self._get_year_from_sec(inode.mtime) < min_year:
            return False
        if self._get_year_from_sec(inode.ctime) > max_year or self._get_year_from_sec(inode.ctime) < min_year:
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
        inode = self.inode_class.from_buffer(bytearray(data))
        inode.set_offset(offset)
        # More checks
        if inode.mode == 0:
            return None
        if inode.nlink > 0xF00:
            return None
        if inode.size > 1099511627776 or inode.size <= 0:
            return None
        if not self._check_inode_has_valid_time(inode):
            return None
        return inode

    def scan_active_filesystem(self):
        inodes = self._get_active_inodes()
        for inode in inodes:
            self.scan_results.add_inode(inode)
            if inode_is_directory(inode):
                directory = None
                for i in range(len(inode.db)):
                    if inode.db[i] == 0:
                        break
                    offset = inode.db[i] * self._superblock.fsize
                    if i == 0:
                        directory = self._read_directory(offset, True, False)
                    else:
                        directory2 = self._read_directory(offset, False, False)
                        directory.combine_directories(directory2)
                self.scan_results.add_directory(directory)

    def _get_active_inodes(self):
        inodes = []
        for offset in self._active_inodes:
            self._stream.seek(offset)
            data = self._stream.read(0x100)
            inode = self.inode_class.from_buffer(bytearray(data))
            inode.set_offset(offset)
            inodes.append(inode)
        return inodes
    
    def scan(self, loadpath, deep_scan=False):
        if os.path.exists(loadpath + '\\inodes.txt') and os.path.exists(loadpath + '\\directories.txt') and os.path.exists(loadpath + '\\directs.txt'):
            self._loaded_from_files = True
            self._load_from_files(loadpath)
        else:
            # There are no saved results, let's start a new scan
            Logger.log(f"No previous scan found in {loadpath}")
            Logger.log("Scanning drive")
            assert(ctypes.sizeof(self.direct_class) == 0x8)
            assert(ctypes.sizeof(self.inode_class) == 0x100)
            
            t1 = time.time()

            # Start scan for deleted files
            self._deep_scan() if deep_scan else self._fast_scan()
            
            self._find_missing_directs()
            self._find_missing_inodes()
                                           
            Logger.log("Finished scanning!")
            Logger.log(f"Total Scan Time: {timedelta(seconds=time.time()-t1)}")

            # Save the offsets to files so we don't have to go through the entire disk again
            self._save_scan_to_files(loadpath)

    
    def _deep_scan(self):
        drive_length = self._stream.getLength()
        for offset in range(0, drive_length, self._superblock.fsize):
            self._stream.seek(offset)
            # test for directories
            direct_check = self._stream.read(0x18)
            test1 = direct_check[6] == 0x4 and direct_check[7] == 0x1 and direct_check[8:9] == b'.'
            if test1:
                test2 = direct_check[0x12] == 0x4 and direct_check[0x13] == 0x2 and direct_check[0x14:0x16] == b'..'
                if test2:
                    # We found a direct table, so lets read out the entire table
                    directory = self._read_directory(offset)
                    self.scan_results.add_directory(directory)
                    continue
            # test for inodes
            for inode_offset in range(offset, offset + self._superblock.fsize, 0x100):
                # Check if inode
                inode = self._read_inode_at_offset(inode_offset)
                if inode:
                    if self.scan_results.add_inode(inode):
                        Logger.log(f"Deleted inode found at offset: 0x{inode_offset:X}")
                        
            if (offset & 0xfffffff) == 0:
                Logger.log(f"Percent Complete: {round((offset/drive_length)*100,2)}%")

    def _fast_scan(self):
        inode_block_offset = self._superblock.iblkno * self._superblock.fsize
        data_block_offset = self._superblock.dblkno * self._superblock.fsize
        cgsize = self._superblock.fpg * self._superblock.fsize
        data_block_length = (cgsize - data_block_offset) + 0x14000

        for cyl in range(self._superblock.ncg):
            cyl_offset = (self._superblock.fpg * self._superblock.fsize) * cyl
            Logger.log(f"Scanning cylinder group: {cyl}/{self._superblock.ncg}: 0x{cyl_offset:X}")
 
            # Read in the inode table
            inode_table_offset = cyl_offset + inode_block_offset

            # Check for any deleted inodes
            # We go through each inode in the inode table
            for i in range(self._superblock.ipg):
                inode_offset = inode_table_offset + (i * 0x100)
                # Check if this inode is a non-deleted inode
                #if True:
                if inode_offset not in self._active_inodes:
                    inode = self._read_inode_at_offset(inode_offset)
                    # Check if this is an inode
                    if inode:
                        # This inode was deleted, so add it to the list
                        inode_index = (cyl * self._superblock.ipg) + i
                        if self.scan_results.add_inode(inode):
                            Logger.log(f"Deleted inode found at index {inode_index}, offset: 0x{inode_offset:X}")
            # Get the offset of the data block
            data_start = cyl_offset + data_block_offset
            data_end = data_start + data_block_length

            # Check the data block sections one at a time for direct tables
            offset = data_start
            bytesLeft = data_block_length
            while offset < data_end:
                # Load a buffer into memory
                self._stream.seek(offset, 0)
                bufSize = min(bytesLeft, self._superblock.bsize)
                buf = self._stream.read(bufSize)
                for block in range(0, bufSize, self._superblock.fsize):
                    # First we'll check the first 0x18 bytes for the first two direct's
                    directs = buf[block:block+0x18]
                    # These tests check the d_type, d_namlen, and d_name fields
                    test1 = directs[6] == 0x4 and directs[7] == 0x1 and directs[8:9] == b'.'
                    if not test1:
                        continue
                    test2 = directs[0x12] == 0x4 and directs[0x13] == 0x2 and directs[0x14:0x16] == b'..'
                    if test2:
                        # We found a direct table, so lets read out the entire table
                        directory = self._read_directory(offset+block)
                        self.scan_results.add_directory(directory)

                bytesLeft -= bufSize
                offset += bufSize
    #
    # TODO: Split this into two functions 
    # 1) Add directs to directories that extend beyond a block 
    # 2) Find any missing referenced inodes
    #
    def _find_missing_directs(self):
        Logger.log("Looking for referenced directories scan may have missed...")
        for inode in self.scan_results.inode_map.values():
            if inode_is_directory(inode):
                block_indexes = self._inode_reader.get_block_indexes(inode)
                block_offset = block_indexes[0] * self._superblock.fsize
                parent_directory:Directory = self.scan_results.directory_map.get(block_offset)
                for index in block_indexes:
                    block_offset = index * self._superblock.fsize
                    if block_offset in self.scan_results.directory_map:
                        continue
                    directory = self._read_directory(block_offset, False)
                    if directory:
                        if parent_directory:
                            parent_directory.combine_directories(directory)
                        for direct in directory.get_directs():
                            if self.scan_results.add_direct(direct):
                                Logger.log(f"Deleted direct found at offset 0x{direct.get_offset():X}: {direct.get_name()}")

                    
    def _find_missing_inodes(self):
        Logger.log("Looking for referenced inodes scan may have missed...")
        for direct in self.scan_results.directs_map.values():
            inode_offset = ino_to_offset(self._superblock, direct.ino)
            if inode_offset in self.scan_results.inode_map:
                continue
            if inode_offset in self.scan_results.active_inodes:
                continue
            inode = self._read_inode_at_offset(inode_offset)
            if inode:
                if self.scan_results.add_inode(inode):
                    Logger.log(f"Deleted inode found at index unknown, offset: 0x{inode_offset:X}")


    def _load_from_files(self, loadpath):
        # Inodes.txt has offsets to all inodes
        # Directs.txt has offsets to all directs
        # We just load each offset, then go to the offset in the disk and read the structures
        # into the inodes_found and directs_found variables
        Logger.log(f"Loading from files at: {loadpath}")
        inodes_list = []
        with open(loadpath + '\\inodes.txt', 'r') as fp:
            inodes_list = fp.readlines()
        directories = []
        with open(loadpath + '\\directories.txt', 'r') as fp:
            directories = fp.readlines()
        directs = []
        with open(loadpath + '\\directs.txt', 'r') as fp:
            directs = fp.readlines()

        # Not really
        max_file_length = self._stream.getLength()

        for line in inodes_list:
            offset = int(line.strip())
            self._stream.seek(offset)
            data = self._stream.read(0x100)
            inode = self.inode_class.from_buffer(bytearray(data))
            inode.set_offset(offset)
            self.scan_results.add_inode(inode)

        for line in directories:
            offset = int(line.strip())
            self._stream.seek(offset)
            directory = self._read_directory(offset)
            self.scan_results.add_directory(directory)

        for line in directs:
            offset = int(line.strip())
            direct = self._read_direct(offset)
            self.scan_results.add_direct(direct)

        # This needs to be called right now to parent directs to directories that extend beyond a block
        self._find_missing_directs()

    def _save_scan_to_files(self, loadpath):
        if not os.path.exists(loadpath + "\\"):
            os.mkdir(loadpath + "\\")
        with open(loadpath + '\\inodes.txt', 'w') as fp:
            for inode in self.scan_results.inode_map:
                fp.write(f"{inode}\n")
        with open(loadpath + '\\directs.txt', 'w') as fp:
            for direct in self.scan_results.directs_map:
                fp.write(f"{direct}\n")
        with open(loadpath + '\\directories.txt', 'w') as fp:
            for directory in self.scan_results.directory_map:
                fp.write(f"{directory}\n")
        Logger.log(f"Saved scan files to: {loadpath}")

    def _read_directory(self, directory_offset, start_of_directory=True, skip_active=True):
        directory = Directory(directory_offset)
        started = not start_of_directory
        rel_direct_offset = 0
        direct = self._read_direct(directory_offset)

        if not direct:
            return None

        while True:
            name = direct.get_name()

            # Check if we've run into another directory
            if name == '.' or name == '..':
                if not started and name == '..':
                    started = True
                elif started and name == '.':
                    return directory

            absolute_offset = (directory_offset+rel_direct_offset)

            if not skip_active:
                directory.add_direct(direct)

            if absolute_offset not in self._active_directs:
                directory.add_direct(direct)
                if not self._loaded_from_files and name != "." and name != "..":
                    Logger.log(f"Deleted direct found at offset 0x{absolute_offset:X}: {name}")

            # We hit the end of a block
            if rel_direct_offset >= self._superblock.bsize:
                return directory

            expected_length = (8 + direct.namlen)
            if expected_length % 4 == 0:
                expected_length += 4
            else:
                expected_length = ((expected_length + 0x3) & 0xFFFFFFFC)
            expected_end = rel_direct_offset + expected_length
            direct_end = rel_direct_offset + direct.reclen

            if (expected_end + 8) >= self._superblock.bsize:
                return directory

            direct = self._read_direct(directory_offset+expected_end)
            if not direct:
                if (direct_end + 8) >= self._superblock.bsize:
                    return directory
                direct = self._read_direct(directory_offset+direct_end)
                if not direct:
                    return directory
                rel_direct_offset = direct_end
            else:
                rel_direct_offset = expected_end

    def _read_direct(self, offset):
        self._stream.seek(offset)
        buf = self._stream.read(8)
        direct = self.direct_class.from_buffer(bytearray(buf))

        if direct.ino > self._ninodes:
            return None

        if direct.reclen % 4 != 0:
            return None

        if direct.reclen == 0 or direct.reclen > 0x200:
            return None

        if direct.namlen > 255 or direct.namlen == 0:
            return None

        if direct.type not in (0,1,2,3,4,6,8,10,12,14,0x88): # 0x88 is a weird PS4 thing
            return None

        name = ''
        try:
            name = self._stream.read(direct.namlen).decode('utf-8', "ignore")
        except:
            return None

        direct.set_name(name)
        direct.set_offset(offset)
        
        return direct



class UFS2Linker:
    def __init__(self, disk, scan_results):
        self._scan_results:ScanResults = scan_results
        
        partition = disk.getPartitionByName(self._scan_results.partition_name)
        self._stream = partition.getDataProvider()
        self._inode_reader = InodeReader(self._stream)

        self._claimed_directories = {}
        self._claimed_inodes = {}
        self._claimed_directs = {}

        # For quick lookups
        self._direct_node_map = {}
        self._inode_node_map = {}
        self._directory_node_map = {}

        self._nodes = []

        Logger.log("UFS2Linker [Step 1/2] Creating nodes for all recovered files...")
        
        self._nodes += self._create_nodes_from_directs_linked_to_inodes()
        self._nodes += self._create_nodes_from_unclaimed_directs()
        self._nodes += self._create_nodes_from_unclaimed_inodes()
        self._nodes += self._create_nodes_from_parent_directs_missing_inode()

        Logger.log("UFS2Linker [Step 2/2] Discovering parent child relationships with recovered files...")

        self._link_nodes_with_inodes()
        self._link_nodes_with_directory_current_direct()
        

    def _create_node(self, direct, inode, inode_offset=None):
        _inode_offset = inode_offset
        _node = None
        
        if inode:
            _inode_offset = inode.get_offset()
            if direct:
                if direct.get_offset() not in self._scan_results.active_directs and _inode_offset in self._scan_results.active_inodes:
                    # don't associate the two if the direct is deleted but the inode is active
                    pass
                else:
                    # only associate the inode and direct if they are both deleted or both active
                    _node = self._add_inode_to_node(_node, inode)
            else:
                _node = self._add_inode_to_node(_node, inode)

        if direct:
            if not inode:
                # if there's no inode use the directs ino to determine what the _inode_offset should be
                _inode_offset = ino_to_offset(self._scan_results.superblock, direct.ino)
            _node = self._add_direct_to_node(_node, direct)
        
        if inode is None and direct is None and _inode_offset is not None:
            _node = Node(NodeType.DIRECTORY)
            _node.set_inode_offset(_inode_offset)
    
        # Mapping
        if inode:
            self._claimed_inodes[inode.get_offset()] = inode
        if direct:
            self._claimed_directs[direct.get_offset()] = direct
            self._direct_node_map[direct.get_offset()] = _node

        if _inode_offset:
            if self._inode_node_map.get(_inode_offset):
                self._inode_node_map.get(_inode_offset).append(_node)
            else:
                self._inode_node_map[_inode_offset] = [_node]

        return _node or None

    def _add_inode_to_node(self, node, inode):
        first_data_block_offset = inode.db[0] * self._scan_results.superblock.fsize
        if not node:
            if inode_is_directory(inode):
                node = Node(NodeType.DIRECTORY)
                node.set_directory_offset(first_data_block_offset)
                self._directory_node_map[first_data_block_offset] = node  
            else:
                node = Node(NodeType.FILE)
        if node.get_type() is not NodeType.DIRECTORY and inode_is_directory(inode):
            Logger.log(f"WTF?! The node {node.get_name()} is not a directory but the inode says it should be!")
        node.set_inode(inode)
        if inode.get_offset() in self._scan_results.active_inodes:
            node.set_active(True)
        return node

    def _add_direct_to_node(self, node, direct):
        if not node:
            if direct.type == 0x4 or direct.get_name() == '___LOCK' or '#' in direct.get_name():
                node = Node(NodeType.DIRECTORY)
            else:
                node = Node(NodeType.FILE)
        if direct.get_offset() in self._scan_results.active_directs:
            node.set_active(True)
        _inode_offset = ino_to_offset(self._scan_results.superblock, direct.ino)
        node.set_direct(direct)
        node.set_direct_offset(direct.get_offset())
        node.set_inode_offset(_inode_offset)
        node.set_name(direct.get_name())
        # This is the parent directory offset.. is useful?
        # node.set_directory_offset(self.align_to_start_of_frag(direct.get_offset()))
        if direct.get_offset() == None:
            Logger.log("WTF?!")
        return node

    #
    # Step 1 : Create all nodes
    #
    def _create_nodes_from_directs_linked_to_inodes(self):
        Logger.log("UFS2Linker [Step 1/2] |- Creating nodes from recovered directs that have their inodes also recovered")
        nodes = []
        for direct in self._scan_results.directs_map.values():
            name = direct.get_name()
            if name == '..' or name == '.':
                continue
            inode_offset = ino_to_offset(self._scan_results.superblock, direct.ino)
            inode = self._scan_results.inode_map.get(inode_offset)
            if inode:
                node = self._create_node(direct, inode)
                nodes.append( node )
                self._claimed_inodes[inode.get_offset()] = inode
                self._claimed_directs[direct.get_offset()] = direct
        return nodes

    def _create_nodes_from_unclaimed_inodes(self):
        Logger.log("UFS2Linker [Step 1/2] |- Creating nodes from inodes that have no direct")
        nodes = []
        for inode in self._scan_results.inode_map.values():
            if inode.get_offset() in self._claimed_inodes:
                continue
            nodes.append(self._create_node(None, inode))
        return nodes

    def _create_nodes_from_unclaimed_directs(self):
        Logger.log("UFS2Linker [Step 1/2] |- Creating nodes from directs that have no inode")
        nodes = []
        for direct in self._scan_results.directs_map.values():
            if direct.get_offset() in self._claimed_directs:
                continue
            if direct.get_name() == "." or direct.get_name() == "..":
                continue
            nodes.append( self._create_node(direct, None) )
        return nodes
    
    def _create_nodes_from_parent_directs_missing_inode(self):
        Logger.log("UFS2Linker [Step 1/2] |- Creating nodes from directories that have no nodes")
        nodes = []
        for directory in self._scan_results.directory_map.values():
            cur_dir_inode_offset = ino_to_offset(self._scan_results.superblock, directory.get_direct(".").ino)
            if cur_dir_inode_offset in self._inode_node_map.keys():
                possible_parent_nodes = self._inode_node_map[cur_dir_inode_offset]
                directory_exists_in_possible_parents = False
                for node in possible_parent_nodes:
                    if node.get_type() == NodeType.DIRECTORY:
                        directory_exists_in_possible_parents = True
                        break
                if directory_exists_in_possible_parents:
                    # A node has already been created for this directory
                    continue
            node = self._create_node(None, None, cur_dir_inode_offset)
            node.set_directory_offset(directory.get_offset())
            nodes.append(node)
        return nodes
    
    #
    # Step 2 : Link all nodes
    #
    def _link_nodes_with_inodes(self):
        Logger.log("UFS2Linker [Step 2/2] |- Link nodes that are linked via blocks in a directory inode")
        for node in self._nodes:
            node:Node
            if node.get_type() == NodeType.DIRECTORY:
                inode = node.get_inode()
                if inode:
                    block_indexes = self._inode_reader.get_block_indexes(inode)
                    # Directory is keyed to the block that the directory starts at, regardless of whether it spans multiple blocks.
                    if len(block_indexes) == 0:
                        Logger.log(f"WTF?! An inode with no block indexes was in the scan! inode at 0x{inode.get_offset():X}")
                        continue
                    directory_offset = block_indexes[0] * self._scan_results.superblock.fsize
                    directory:Directory = self._scan_results.directory_map.get(directory_offset)
                    if directory:
                        directs = directory.get_directs()
                        for direct in directs:
                            if direct.get_name() == "." or direct.get_name() == "..":
                                continue
                            child_node:Node = self._direct_node_map.get(direct.get_offset())
                            child_node.add_parent(node)
                            node.add_child(child_node)
                        # inodes are the only thing that can claim a directory
                        self._claimed_directories[directory.get_offset()] = directory
    
    def _link_nodes_with_directory_current_direct(self):
        Logger.log("UFS2Linker [Step 2/2] |- Link nodes in a directory to the directories parent")
        for directory in self._scan_results.directory_map.values():
            directory:Directory
            if directory.get_offset() in self._claimed_directories:
                continue
            directory_offset = directory.get_offset()
            current_directory_direct = directory.get_direct(".")
            current_directory_inode_offset = ino_to_offset(self._scan_results.superblock, current_directory_direct.ino)
            nodes = self._inode_node_map.get(current_directory_inode_offset)
            directs = directory.get_directs()
            for node in nodes:
                node:Node
                if node.get_type() == NodeType.FILE:
                    continue
                self._directory_node_map[directory_offset] = node
                for direct in directs:
                    if direct.get_name() == "." or direct.get_name() == "..":
                        continue
                    child_node:Node = self._direct_node_map.get(direct.get_offset())
                    node.add_child(child_node)
                    child_node.add_parent(node)

    def get_root_nodes(self):
        root_nodes = []
        for node in self._nodes:
            if len(node.get_parents()) == 0:
                if node.get_type() == NodeType.FILE:
                    root_nodes.append(node)
                elif len(node.get_children()) > 0:
                    root_nodes.append(node)
        return root_nodes