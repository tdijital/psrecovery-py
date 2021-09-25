import ctypes
import time

import disklib

from common.logger import Logger
from .ufs import get_direct_class, get_inode_class, ino_to_offset, SuperBlock, endianness, Endianness

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
        for node in self._children:
            if node.get_direct_offset() == child.get_direct_offset():
                Logger.log(f"[!] [Matching Direct]  Skipping add child {child.get_name()} because it already exists in {self._name}")
                return
            if node.get_inode_offset() == child.get_direct_offset():
                Logger.log(f"[!] [Matching Inode]   2 Skipping add child {child.get_name()} because it already exists in {self._name}")
                return
        self._children.append(child)
    def get_parents(self):
        return self._parents
    def add_parent(self, parent):
        for node in self.get_parents():
            if node.get_direct_offset() == parent.get_direct_offset():
                Logger.log(f"[!] [Matching Direct]  Skipping add parent {parent.get_name()} because {self._name} is already a child ")
                return
            if node.get_inode_offset() == parent.get_inode_offset():
                Logger.log(f"[!] [Matching Inode]   Skipping add parent {parent.get_name()} because {self._name} is already a child ")
                return
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
        if not name in self._directs.keys():
            return None
        return self._directs[name]
    def get_directs(self):
        return self._directs.values()
    def get_offset(self):
        return self._offset


class ScanResults:
    def __init__(self):
        # Mapping of address to Inode
        self.inodeMap = {}
        # Mapping of address to Direct
        self.directsList = []
        # Mapping of address to collection of Direct
        self.directoryMap = {}
        # Map an ino to map of directs that reference the inode
        self.inoDirectMap = {}
        # Nodes with directs
        self.nodes = []


class Scanner2:
    def __init__(self, disk, sector_size):
        self._stream = None  # The stream we will ultimately be reading from
        self._sector_size = sector_size
        self._sblk =  None
        self._initialize(disk)

    def _initialize(self, disk):

        if endianness is Endianness.BIG:
            # PS3
            partition = disk.getPartitionByName('dev_hdd0')
        elif endianness is Endianness.LITTLE:
            # PS4
            partition = disk.getPartitionByName('user')
        
        self._stream = partition.getDataProvider()
        Logger.log(f"Disk Size: {self._stream.getLength()} bytes")

        self._sblk = SuperBlock(self._stream)

        vfs = partition.getVfs()
        vfs.mount()
        if not vfs.isMounted():
            raise Exception("Vfs failed to mount!")
        root = vfs.getRoot()

        self._active_inodes = self._get_all_offsets(root, 'inode')
        self._active_directs = self._get_all_offsets(root, 'dirent')
        self._ninodes = (self._sblk.ipg * self._sblk.ncg)
        self.max_block_index = self._stream.getLength() / self._sblk.fsize
        self.inode_class = get_inode_class()
        self.direct_class = get_direct_class()
    
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
            index = int.from_bytes(indexes[(x*8):(x*8)+8], byteorder=endianness)
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
        inode = self.inode_class.from_buffer(bytearray(data))
        inode.set_offset(offset)
        # More checks
        if inode.mode == 0:
            return None
        if inode.nlink > 0xF00:
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

        self._scan_results = ScanResults()

        import os

        loaded_from_file = False

        if os.path.exists(loadpath + '\\inodes.txt') and os.path.exists(loadpath + '\\directories.txt'):
            # Load offsets from previous results that have been stored in the above two txt files
            # Inodes.txt has offsets to all inodes
            # Directs.txt has offsets to all directs
            # We just load each offset, then go to the offset in the disk and read the structures
            # into the inodes_found and directs_found variables
            Logger.log("Loading from files")
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
                inode = self.inode_class.from_buffer(bytearray(data))
                if inode.mode == 0:
                    continue
                if inode.nlink > 0x10:
                    continue
                if inode.size > max_file_length:
                    continue
                #Logger.log(oct(inode.mode))
                inode.set_offset(offset)
                self._scan_results.inodeMap[offset] = inode

            for line in directories:
                offset = int(line.strip())
                self._stream.seek(offset)
                directory = self._extract_directs(offset)
                self._scan_results.directsList.extend(directory.get_directs())
                self._scan_results.directoryMap[offset] = directory

            loaded_from_file = True
        else:
            # There are no saved results, let's start a new scan
            Logger.log(f"No previous scan found in {loadpath}")
            Logger.log("Scanning drive")
            assert(ctypes.sizeof(self.direct_class) == 0x8)
            assert(ctypes.sizeof(self.inode_class) == 0x100)

            inode_block_offset = self._sblk.iblkno * self._sblk.fsize
            data_block_offset = self._sblk.dblkno * self._sblk.fsize
            cgsize = self._sblk.fpg * self._sblk.fsize
            data_block_length = (cgsize - data_block_offset) + 0x14000

            # Start scan for deleted files
            if deep_scan is False :
                for cyl in range(self._sblk.ncg):
                    cyl_offset = (self._sblk.fpg * self._sblk.fsize) * cyl
                    Logger.log(f"Scanning cylinder group: {cyl}/{self._sblk.ncg}: 0x{cyl_offset:X}")

                    # Read in the inode table
                    inode_table_offset = cyl_offset + inode_block_offset

                    # Check for any deleted inodes
                    # We go through each inode in the inode table
                    for i in range(self._sblk.ipg):
                        inode_offset = inode_table_offset + (i * 0x100)
                        # Check if this inode is a non-deleted inode
                        #if True:
                        if inode_offset not in self._active_inodes:
                            inode = self._read_inode_at_offset(inode_offset)
                            # Check if this is an inode
                            if inode:
                                # This inode was deleted, so add it to the list
                                inode_index = (cyl * self._sblk.ipg) + i
                                Logger.log(f"Deleted inode found at index {inode_index}, offset: 0x{inode_offset:X}")
                                self._scan_results.inodeMap[inode_offset] = inode

                    # Get the offset of the data block
                    data_start = cyl_offset + data_block_offset
                    data_end = data_start + data_block_length

                    # Check the data block sections one at a time for direct tables
                    offset = data_start
                    bytesLeft = data_block_length
                    while offset < data_end:
                        # Logger.log(hex(offset))
                        # Load a buffer into memory
                        self._stream.seek(offset, 0)
                        bufSize = min(bytesLeft, self._sblk.bsize)
                        buf = self._stream.read(bufSize)
                        # Check every 0x800 bytes in the buffer for a direct table
                        for block in range(0, bufSize, self._sblk.fsize):
                            # First we'll check the first 0x18 bytes for the first two direct's
                            dirents = buf[block:block+0x18]
                            # These tests check the d_type, d_namlen, and d_name fields
                            test1 = dirents[6] == 0x4 and dirents[7] == 0x1 and dirents[8:9] == b'.'
                            if not test1:
                                continue
                            test2 = dirents[0x12] == 0x4 and dirents[0x13] == 0x2 and dirents[0x14:0x16] == b'..'
                            if test2:
                                # We found a direct table, so lets read out the entire table
                                directory = self._extract_directs(offset+block)
                                if directory:
                                    self._scan_results.directsList.extend(directory.get_directs())
                                    self._scan_results.directoryMap[offset+block] = directory

                        bytesLeft -= bufSize
                        offset += bufSize
            else:
                #
                #  Deep Scan
                #
                drive_length = self._stream.getLength()
                scan_interval = 0x100 # This will take forever but should never miss an inode or direct...
                for offset in range(0, drive_length, scan_interval):
                    self._stream.seek(offset)
                    direct_check = self._stream.read(0x18)
                    test1 = direct_check[6] == 0x4 and direct_check[7] == 0x1 and direct_check[8:9] == b'.'
                    if test1:
                        test2 = direct_check[0x12] == 0x4 and direct_check[0x13] == 0x2 and direct_check[0x14:0x16] == b'..'
                        if test2:
                            # We found a direct table, so lets read out the entire table
                            directory = self._extract_directs(offset)
                            self._scan_results.directsList.extend(directory.get_directs())
                            self._scan_results.directoryMap[offset] = directory
                            continue
                    # Check if inode
                    inode = self._read_inode_at_offset(offset)
                    if inode:
                        self._scan_results.inodeMap[offset] = inode
                        Logger.log(f"Deleted inode found at offset: 0x{offset:X}")
                        _offset = offset + 0x100
                        while _offset < offset + scan_interval:
                            inode = self._read_inode_at_offset(_offset)
                            if inode:
                                Logger.log(f"Deleted inode found at offset: 0x{_offset:X}")
                                self._scan_results.inodeMap[_offset] = inode
                                _offset += 0x100
                            else:
                                break
                                
                    if (offset & 0xfffffff) == 0:
                        Logger.log(f"Percent Complete: {round((offset/drive_length)*100,2)}%")
                                           
        Logger.log("Finished scanning. Now analyzing...")

        # Save the offsets to files so we don't have to go through the entire disk again
        if not os.path.exists(loadpath + "\\"):
            os.mkdir(loadpath + "\\")
        if not loaded_from_file:
            with open(loadpath + '\\inodes.txt', 'w') as fp:
                for inode in self._scan_results.inodeMap:
                    fp.write(f"{inode}\n")
            with open(loadpath + '\\directs.txt', 'w') as fp:
                for direct in self._scan_results.directsList:
                    fp.write(f"{direct}\n")
            with open(loadpath + '\\directories.txt', 'w') as fp:
                for directory in self._scan_results.directoryMap:
                    fp.write(f"{directory}\n")

        def inode_is_directory(inode):
            #  We can also check the following:
            #   - 0100000 is set for files (IFREG)
            data_offset = inode.db[0] * self._sblk.fsize
            return inode.mode & 0x4000 or data_offset in self._scan_results.directoryMap

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

        # Set of claimed inodes
        # This will be used to create nodes for any inodes that aren't claimed
        # by a Direct
        claimedInodes = set()

        # Set of claimed directories
        claimedDirectories = set()

        # Mapping of ino's to direct's
        # This will be used later on for Directory to Direct matching
        # {ino: [directs]}
        # inoDirectMap = {}

        # Mapping of Direct to Node
        # This will be used to look up a Node by it's Direct
        directNodeMap = {}

        # Mapping of Inode to Node
        # This will be used to look up a Node by it's Inode
        # inodeNodeMap = {}  # Unused at the moment

        # Mapping of direct ino to the Node
        inoNodeMap = {}

        #    
        # Active Filesystem
        #
        # Create directs and directories

        directMap = {}

        active_directories = {}

        def align_to_prev(offset, align):
            return ((offset - align) + align) & ~(align - 1)

        def add_directory(offset):
            directory = self._extract_directs(offset, True)
            if not directory:
                return None
            self._scan_results.directsList.extend(directory.get_directs())
            self._scan_results.directoryMap[offset] = directory
            return directory

        t1 = time.time()
        # Create active Directories
        for direct_offset in self._active_directs:
            # Check for start of directory aligned to start of fragment
            read_offset = align_to_prev(direct_offset, self._sblk.fsize)
            if read_offset in active_directories:
                continue
            self._stream.seek(read_offset)
            buf = self._stream.read(0x9)
            direct = self.read_direct(buf,0)
            if not direct:
                # Check for start of directory aligned to start of block
                read_offset = align_to_prev(direct_offset, self._sblk.bsize)
                if read_offset in active_directories:
                    continue
                self._stream.seek(read_offset)
                buf = self._stream.read(0x9)
                direct = self.read_direct(buf,0)
                if not direct:
                    Logger.log(f"WTF?? no directory found for the direct at 0x{direct_offset:X}")
                    continue
            name = direct.get_name()
            if name == '.':
                if read_offset in active_directories:
                    continue
                Logger.log(f"Found active directory at 0x{read_offset:X}")
                directory = add_directory(read_offset)
                active_directories[read_offset] = directory     
        # Create active Inodes + Directs
        for direct_offset in self._active_directs:
            self._stream.seek(direct_offset)
            buf = self._stream.read(0x300) # 255 is the max direct size
            direct = self.read_direct(buf,0)
            if not direct:
                 Logger.log(f"WTF?? direct in active_directs not found at 0x{direct_offset:X}")
                 continue       
            direct.set_offset(direct_offset)
            directMap[direct_offset] = direct
            # Create Inode
            inode_offset = ino_to_offset(self._sblk, direct.ino)
            inode = self._read_inode_at_offset(inode_offset)
            if not inode:
                Logger.log(f"WTF?? active direct: {direct._name} at 0x{direct_offset:X} is pointing to a non existent inode at 0x{inode_offset:X}")
                continue
            # Add the inode to the map
            self._scan_results.inodeMap[inode_offset] = inode
            self._scan_results.inoDirectMap[direct.ino] = [direct]

            if inode_offset not in self._active_inodes:
                Logger.log(f"WTF?? active direct: {direct._name} is pointing to a non active inode at 0x{inode_offset:X}")
        # Validate
        for direct1_offset in self._active_directs:
            if direct1_offset not in directMap:
                continue
            for directory in active_directories.values():
                found_directory = False
                directory_directs = directory.get_directs()
                for direct2 in directory_directs:
                    if direct1_offset == direct2.get_offset():
                        # Logger.log(f"Hell yah! Active directory found for direct: {directMap[direct1_offset].get_name()} at 0x{directMap[direct1_offset].get_offset():X}")
                        found_directory = True
                        break
                if found_directory:
                    break
            if not found_directory:
                Logger.log(f"WTF?? No active directory found for direct: {directMap[direct1_offset].get_name()} at 0x{directMap[direct1_offset].get_offset():X}")
        t2 = time.time()
        Logger.log(f"Step 0: {t2 - t1}")
        #
        # End Active Filesystem
        #
        
        # region | Step 1: Populate the inoDirectMap
        t1 = time.time()
        for direct in self._scan_results.directsList:
            if direct.get_offset() in self._active_directs:
                continue
            name = direct.get_name()
            if name == '..' or name == '.':
                continue
            ino = direct.ino
            if ino in self._scan_results.inoDirectMap:
                Logger.log(f"Log: Duplicate ino usage for direct {name} (ino={ino}, direct={direct.get_offset()})")
                self._scan_results.inoDirectMap[ino].append(direct)
            else:
                self._scan_results.inoDirectMap[ino] = [direct]
        t2 = time.time()
        Logger.log(f"Step 1: {t2 - t1}")
        # endregion
        # region | Step 2: Create an initial list of Node's using Direct's
        t1 = time.time()
        def create_nodes_from_directs(directs):
            for direct in directs:
                if direct._name == '..' or direct._name == '.':
                    continue
                node = None
                if direct.type == 0x4:
                    node = Node(NodeType.DIRECTORY)
                else:
                    node = Node(NodeType.FILE)
                if direct.get_offset() in self._active_directs:
                    node.set_active(True)
                inode_offset = ino_to_offset(self._sblk, direct.ino)
                node.set_direct(direct)
                node.set_direct_offset(direct.get_offset())
                node.set_inode_offset(inode_offset)
                node.set_name(direct.get_name())
                directNodeMap[direct.get_offset()] = node
                inode = self._scan_results.inodeMap.get(inode_offset)
                if not inode:
                    # This will check if there's an inode where the direct expected one
                    Logger.log(f"Warning: Direct {node._name} expected an inode at offset 0x{inode_offset:X} attempting to read one at offset...")
                    inode = self._read_inode_at_offset(inode_offset)
                    if inode:
                        Logger.log("Success! Inode discovered where the Direct expected!")
                        self._scan_results.inodeMap[inode_offset] = inode
                # Initaliaze the inode
                if inode:
                    node.set_inode(inode)
                    node.set_size(inode.size)
                    node.set_creation_time(inode.ctime)
                    node.set_last_access_time(inode.atime)
                    node.set_last_modified_time(inode.mtime)
                    claimedInodes.add(inode.get_offset())
                    if node.get_type() == NodeType.DIRECTORY:
                        directory_offset = inode.db[0] * self._sblk.fsize
                        node.set_directory_offset(directory_offset)
                    
                if direct.ino in inoNodeMap:
                    Logger.log(f"Warning: Another node {inoNodeMap.get(direct.ino).get_name()} already claims ino that {node.get_name()} is claiming")
                inoNodeMap[direct.ino] = node
                # Add the node to the results
                self._scan_results.nodes.append(node)
        create_nodes_from_directs(self._scan_results.directsList)
        t2 = time.time()
        Logger.log(f"Step 2: {t2 - t1}")
        # endregion
        # region | Step 3: Parent child relationships using inodes
        t1 = time.time()
        for node in self._scan_results.nodes:
            if node.get_name() == '..' or node.get_name() == '.':
                continue
            if node.get_type() is not NodeType.DIRECTORY:
                continue
            inode = node.get_inode()
            if not inode:
                continue
            if not inode_is_directory(inode):
                continue
            indexes = inode.get_block_indexes(self._stream, self._sblk)
            for index in indexes:
                offset = index * self._sblk.fsize
                directory = self._scan_results.directoryMap.get(offset)
                if directory:
                    for direct in directory.get_directs():
                        if direct._name == '..' or direct._name == '.':
                            continue
                        child = directNodeMap.get(direct.get_offset())
                        node.add_child(child)
                        child.add_parent(node)
                    claimedDirectories.add(directory.get_offset())
                else:
                    Logger.log(f"Warning: Node \"{node.get_name()}\" Expected a directory at 0x{offset:X} checking if one exists...")
                    directory = add_directory(offset)
                    if directory:
                        Logger.log(f"Success: directory found!")
                        # create nodes from directory
                        create_nodes_from_directs(directory.get_directs())

        
        t2 = time.time()
        Logger.log(f"Step 3: {t2 - t1}")
        # endregion
        # region | Step 4: Connect child directories with parent directories using "." direct
        # Matches direct -> direct[] using the "." (this folder) direct.
        t1 = time.time()
        for directory in self._scan_results.directoryMap.values():
            if directory.get_offset() in claimedDirectories:
                continue
            # Get the direct that references the parent directories ino
            upperDirect = directory.get_direct(".")
            if not upperDirect:
                continue
            # Find the parent direct or directs that claim that ino
            parent_directs = self._scan_results.inoDirectMap.get(upperDirect.ino)
            
            # Nodes that claim to be the parents
            parent_nodes = []

            if not parent_directs:
                Logger.log(f"[!] No directs claim the parent ino {upperDirect.ino}\n")
                continue
            else:
                # Collect nodes from the directs
                for pDirect in parent_directs:
                    # Get the Node of the parent direct
                    node:Node = directNodeMap.get(pDirect.get_offset())
                    parent_nodes.append(node)

            for p_node in parent_nodes:
                if p_node.get_type() != NodeType.DIRECTORY:
                    continue
                # Don't child active nodes to deleted parent nodes
                if directory.get_offset() in active_directories and not p_node.get_active():
                    Logger.log(f"[-] Handled: Not adding active directory at 0x{directory.get_offset()} to deleted node {p_node.get_name()}")
                    continue
                Logger.log(f" + Found parent directory {p_node._name} at 0x{p_node.get_direct_offset()} for directs at 0x{directory.get_offset()}")
                # Get the children of this directory 
                for direct in directory.get_directs():
                    if direct._name == "." or direct._name == "..":
                        continue
                    child:Node = directNodeMap.get(direct.get_offset())
                    Logger.log(f" |- adding child... \"{child.get_name()}\"")
                    p_node.add_child(child)
                    child.add_parent(p_node)
                                    
                directory_offset = directory.get_offset()
                claimedDirectories.add(directory_offset)
                Logger.log("")

        # for directory in self._scan_results.directoryMap.values():
        #     dot_direct = directory.get_direct(".")
        #     dotdot_direct = directory.get_direct("..")

        #     dot_node = inoNodeMap.get(dot_direct.ino)
        #     dotdot_node = inoNodeMap.get(dotdot_direct.ino)

        #     if not dotdot_node or not dot_node:
        #         continue
        #     if dot_node.get_type() != NodeType.DIRECTORY or dotdot_node.get_type() != NodeType.DIRECTORY:
        #         continue

        #     Logger.log(f"[+] Found parent {dotdot_node.get_name()} for the folder {dot_node.get_name()}")
        #     dotdot_node.add_child(dot_node)
        #     dot_node.add_parent(dotdot_node)

        
        t2 = time.time()
        Logger.log(f"Step 4: {t2 - t1}")
        # endregion
        # region | Step 5: Create nodes for any inode's that weren't claimed
        t1 = time.time()
        for inode in self._scan_results.inodeMap.values():
            if inode.get_offset() in claimedInodes:
                continue
            node = None
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
            #nodes.append(node)
            self._scan_results.nodes.append(node)
        # endregion
        # region | Step 6: Create nodes for unclaimed directories
        for directory in self._scan_results.directoryMap.values():
            offset = directory.get_offset()
            if offset in claimedDirectories:
                continue
            node = Node(NodeType.DIRECTORY)
            node.set_directory_offset(directory.get_offset())
            for direct in directory.get_directs():
                if direct._name == "." or direct._name == "..":
                    continue
                child = directNodeMap.get(direct.get_offset())
                node.add_child(child)
                child.add_parent(node)
            self._scan_results.nodes.append(node)
        
        t2 = time.time()
        Logger.log(f"Step 5: {t2 - t1}")
        # endregion
        # region | Step 7: Extract only top level nodes
        root_nodes = []
        for node in self._scan_results.nodes:
            if len(node.get_parents()) == 0:
                root_nodes.append(node)

        # print_directory(root_nodes)
        # endregion

        return root_nodes

    def _extract_directs(self, addr, extract_active=False):
        result = Directory(addr)
        started = False

        # Initial buffer
        self._stream.seek(addr)
        buf = self._stream.read(self._sblk.bsize)

        offset = 0
        direct = self.read_direct(buf, offset)

        if not direct:
            return None

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
            if absolute_offset not in self._active_directs and name != "." and name != "..":
                Logger.log(f"Direct found at offset 0x{absolute_offset:X}: {name}")
            if absolute_offset not in self._active_directs or extract_active:
                direct.set_name(name)
                direct.set_offset(addr+offset)
                result.add_direct(direct)

            # We hit the end of a block
            # Maybe continue reading?
            if offset >= 0x4000:
                Logger.log(f"Log: Hit end of block when parsing direct table at 0x{addr:X}!")
                return result

            expected_length = (8 + direct.namlen)
            if expected_length % 4 == 0:
                expected_length += 4
            else:
                expected_length = ((expected_length + 0x3) & 0xFFFFFFFC)
            expected_end = offset + expected_length
            direct_end = offset + direct.reclen

            if (expected_end + 8) >= 0x4000:
                Logger.log(f"Log: Hit end of block when parsing direct table at 0x{addr:X}!")
                return result
                
            direct = self.read_direct(buf, expected_end)
            if not direct:
                if (direct_end + 8) >= 0x4000:
                    Logger.log(f"Log: Hit end of block when parsing direct table at 0x{addr:X}!")
                    return result
                direct = self.read_direct(buf, direct_end)
                if not direct:
                    return result
                offset = direct_end
            else:
                offset = expected_end

    def read_direct(self, buffer, offset):
        buf = bytearray(buffer[offset:offset+8])
        direct = self.direct_class.from_buffer(buf)

        #if direct.ino > self._ninodes:
        #    return None

        if direct.reclen % 4 != 0:
            return None

        if direct.reclen == 0 or direct.reclen > 0x200:
            return None

        if direct.namlen > 255 or direct.namlen == 0:
            return None

        if direct.type not in (0,1,2,3,4,6,8,10,12,14,0x88): # 0x88 is a weird PS4 thing
            return None

        if len(buffer) < 0x8 + direct.namlen:
            return None

        name = ''
        try:
            name = buffer[offset+8:offset+8+direct.namlen].decode('utf-8', "ignore")
        except:
            return None

        direct.set_name(name)
        
        return direct