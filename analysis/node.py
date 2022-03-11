import math
from analysis.ufs import SuperBlock, InodeReader

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
    def __repr__(self):
        return self.get_name()


class NodeValidator():
    def __init__(self, stream):
        self._inode_reader = InodeReader(stream)
        self._superblock = SuperBlock(stream)
    
    def validate(self, node):
        inode = node.get_inode()
        if not node.get_inode():
            return
        block_indexes = self._inode_reader.get_block_indexes(inode)
        required_blocks = math.ceil(inode.size / self._superblock.bsize)
        if len(block_indexes) != required_blocks:
            node.set_valid(False)
            return False
        return True