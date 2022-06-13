import math
from analysis.ufs import SuperBlock, InodeReader
from common.logger import Logger

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
        self._file_ext = None
        self._active = False
        self._valid = True
        self._file_offset = None
        self._debug_info = ""

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
        if inode:
            self.set_inode_offset(inode.get_offset())
            self.set_size(inode.size)
            self.set_creation_time(inode.ctime)
            self.set_last_access_time(inode.atime)
            self.set_last_modified_time(inode.mtime)
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
    def set_file_ext(self, ext):
        self._file_ext = ext
    def get_file_ext(self):
        return self._file_ext
    def set_valid(self, valid):
        self._valid = valid
    def get_valid(self):
        return self._valid
    def set_file_offset(self, offset):
        self._file_offset = offset
    def get_file_offset(self):
        return self._file_offset
    def set_debug_info_text(self, text):
        self._debug_info = text
    def append_debug_info_text(self, text):
        self._debug_info += text + "\n"
    def get_debug_info_text(self):
        return self._debug_info
    def __repr__(self):
        return self.get_name()


class NodeValidator():
    def __init__(self, stream):
        self._stream = stream
        self._inode_reader = InodeReader(self._stream)
        self._superblock = SuperBlock(self._stream)

        self._block_map = {}

    def validate(self, node):
        inode = node.get_inode()
        if not node.get_inode():
            node.append_debug_info_text(f'[Missing Inode] No inode can be found for this direct.')
            return
        
        block_indexes = self._inode_reader.get_block_indexes(inode)

        # Check if a more recently written node claims that data block already
        node_is_invalid = False
        i = 0
        for index in block_indexes:
            claim_block = True
            if index in self._block_map:
                other_node = self._block_map.get(index)
                if other_node.get_last_modified_time() == node.get_last_modified_time():
                    continue
                if other_node.get_last_modified_time() > node.get_last_modified_time():
                    # This node is invalid
                    Logger.log(f'{node.get_name()} block is overwritten at file offset: 0x{i * self._superblock.bsize:X} by file {other_node.get_name()}')
                    node.append_debug_info_text(f'[Overwritten] at file offset: 0x{i * self._superblock.bsize:X} by file {other_node.get_name()}')
                    claim_block = False
                    node_is_invalid = True
                    node.set_valid(False)
                else:
                    # The other node is invalid
                    Logger.log(f'{other_node.get_name()} block is overwritten at file offset: 0x{i * self._superblock.bsize:X} by file {node.get_name()}')
                    other_node.append_debug_info_text(f'[Overwritten] at file offset: 0x{i * self._superblock.bsize:X} by file {node.get_name()}')
                    other_node.set_valid(False)
        
            if claim_block:
                self._block_map[index] = node

            i += 1

        if node_is_invalid:
            return False

        # Check that the node has all the required datablocks that the file size requires
        required_blocks = math.ceil(inode.size / self._superblock.bsize)
        if len(block_indexes) != required_blocks:
            node.append_debug_info_text(f'[Missing data blocks] Has {len(block_indexes)} of the {required_blocks} required block indexes')
            node.set_valid(False)
            return False
        return True