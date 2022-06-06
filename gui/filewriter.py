import os
import math

from common.logger import Logger
from analysis.ufs import SuperBlock, Endianness, InodeReader
from analysis.node import Node, NodeType

import tkinter.ttk as ttk


class FileReader():
    def __init__(self, stream):
        self._stream = stream
        self._superblock = SuperBlock(self._stream)
        self._max_bindex = stream.getLength() / self._superblock.fsize
        self._inode_reader = InodeReader(stream)

    def get_node_bytes(self, node):
        inode = node.get_inode()
        node_bytes = bytearray()
        
        # If an inode exists read the inodes blocks
        if inode is not None:
            # Read direct blocks
            block_indexes = self._inode_reader.get_block_indexes(inode)
            # Read data
            remaining = node.get_size()
            required_blocks = math.ceil(remaining / self._superblock.bsize)
            total_blocks = len(block_indexes)
            if required_blocks != total_blocks:
                Logger.log(f"+ File {node.get_name()} is missing {required_blocks-total_blocks} block indexes of total {required_blocks}")
                Logger.log(f"|- Attempting to fill missing data blocks beginning at 0x{total_blocks * self._superblock.fsize:X}")
                self._inode_reader.fill_missing_block_indexes(block_indexes, required_blocks)
            block_count = 0
            while remaining > 0:
                index = block_indexes[block_count]
                data_offset = index * self._superblock.fsize
                self._stream.seek(data_offset)
                read = min(remaining, self._superblock.bsize)
                file_bytes = self._stream.read(read)
                node_bytes += file_bytes
                block_count += 1
                remaining -= read
        
        # Carved files
        elif node.get_size() and node.get_file_offset(): 
            self._stream.seek(node.get_file_offset())
            remaining = node.get_size()
            while remaining > 0:
                read_offset = node.get_file_offset() + (node.get_size() - remaining)
                self._stream.seek(read_offset)
                read = min(remaining, self._superblock.bsize)
                file_bytes = self._stream.read(read)
                node_bytes += file_bytes
                remaining -= read
            
        return node_bytes



class FileWriter():
    def __init__(self, stream, fs_tree, node_item_map):
        self._stream = stream
        self._fs_tree:ttk.Treeview = fs_tree
        self._node_item_map = node_item_map
        self._superblock = SuperBlock(self._stream)
        self._max_bindex = stream.getLength() / self._superblock.fsize
        self._inode_reader = InodeReader(stream)

    def get_item_path(self, item, start_item=None):
        path = ""
        current_item = item
        while True:
            if current_item == "I001" or current_item == start_item:
                return f"{self.get_item_name(start_item)}\\{path}"
            path = self._fs_tree.item(current_item)['text'] + "\\" + path
            current_item = str(self._fs_tree.parent(current_item))
    
    def write_items(self, outpath, items, recursive=True):
        for item in items:
            if self._fs_tree.parent(item) in items:
                continue
            node = self._node_item_map[item]
            if node.get_type() is NodeType.DIRECTORY:
                self.write_item_directory(outpath, item, item, recursive)
            else:
                self.write_item_file(outpath, item)

    def write_item_file(self, outpath, item):
        block_indexes = []
        file_bytes = bytearray()
        node = self._node_item_map[item]
        node:Node
        inode = node.get_inode()

        # Write the file     
        file_path = f"{outpath}\\{self._fs_tree.item(item)['text']}"
        file_path = os.path.normpath(file_path)

        # If an inode exists read the inodes blocks
        if inode is not None:
            # Read direct blocks
            block_indexes = self._inode_reader.get_block_indexes(inode)
            # Read data
            remaining = node.get_size()
            required_blocks = math.ceil(remaining / self._superblock.bsize)
            total_blocks = len(block_indexes)
            if required_blocks != total_blocks:
                Logger.log(f"+ File {node.get_name()} is missing {required_blocks-total_blocks} block indexes of total {required_blocks}")
                Logger.log(f"|- Attempting to fill missing data blocks beginning at 0x{total_blocks * self._superblock.fsize:X}")
                self._inode_reader.fill_missing_block_indexes(block_indexes, required_blocks)
            block_count = 0
            if os.path.exists(file_path):
                os.remove(file_path)
            file = open(file_path, 'ab')
            while remaining > 0:
                index = block_indexes[block_count]
                data_offset = index * self._superblock.fsize
                self._stream.seek(data_offset)
                read = min(remaining, self._superblock.bsize)
                file_bytes = self._stream.read(read)
                file.write(file_bytes)
                block_count += 1
                remaining -= read
            file.close()
       
        # Carved files
        elif node.get_size() and node.get_file_offset(): 
            self._stream.seek(node.get_file_offset())
            remaining = node.get_size()
            read_buffer_max = 0x80000
            if os.path.exists(file_path):
                os.remove(file_path)
            file = open(file_path, 'ab')
            while remaining > 0:
                read_offset = node.get_file_offset() + (node.get_size() - remaining)
                self._stream.seek(read_offset)
                read = min(remaining, read_buffer_max)
                file_bytes = self._stream.read(read)
                file.write(file_bytes)
                remaining -= read
            file.close()
        
        # Set the time stamp
        if inode is not None:
            self.set_file_ts(file_path, node)

    def write_item_directory(self, outpath, item, start_item=None, recursive=True):
        node = self._node_item_map[item]
        if node.get_type() is not NodeType.DIRECTORY:
            return None

        rel_path = self.get_item_path(item, start_item)
        abs_path = f"{outpath}\\{rel_path}"

        self.create_dir(abs_path)

        for child_item in self._fs_tree.get_children(item):
            child_node = self._node_item_map[child_item]
            if child_node.get_type() == NodeType.DIRECTORY:
                if recursive:
                    self.write_item_directory(outpath, child_item, start_item)
            else:
                self.write_item_file(abs_path, child_item)
    
    def get_item_name(self, item):
        return self._fs_tree.item(item)['text']

    def create_dir(self, outpath, name='', node=None):
        path = os.path.join(outpath, name)
        if os.path.exists(path):
            return
        os.makedirs(path)
        if node:
            self.set_file_ts(path, node)

    def set_file_ts(self, path, node):
        if node.get_inode() is None:
            return
        atime = node.get_last_access_time()
        mtime = node.get_last_modified_time()

        os.utime(path, (atime, mtime))
    
    # Hack-ish: Previously the direct scanner ignored utf-8 errors 
    # this should make sure only valid utf-8 is written to the file name
    def _replace_invalid_utf8_chars(self, s):
        s1 = bytes(s, "utf-8", 'ignore')
        s1 = s1.decode('utf-8','replace')
        s1 = s1.replace("\x00", "")
        return s1