import os
import math

from common.logger import Logger
from analysis.ufs import SuperBlock, Endianness, InodeReader
from analysis.node import Node, NodeType

import tkinter.ttk as ttk


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
        inode = node.get_inode()

        # If an inode exists read the inodes blocks
        if inode is not None:
            # Read direct blocks
            block_indexes = self._inode_reader.get_block_indexes(inode)
            # Read data
            remaining = node.get_size()
            required_blocks = math.ceil(remaining / self._superblock.bsize)
            total_blocks = len(block_indexes)
            if required_blocks != total_blocks:
                Logger.log(f"+ File {node.get_name()} is missing {total_blocks-required_blocks} block indexes of total {total_blocks}")
                Logger.log(f"|- Attempting to fill missing data blocks beginning at 0x{(total_blocks + 1) * self._superblock.fsize:X}")
                self._inode_reader.fill_missing_block_indexes(block_indexes, required_blocks)
            block_count = 0
            while remaining > 0:
                index = block_indexes[block_count]
                data_offset = index * self._superblock.fsize
                self._stream.seek(data_offset)
                read = min(remaining, self._superblock.bsize)
                file_bytes += self._stream.read(read)
                remaining -= read
                block_count += 1
        
        # Write the file     
        file_path = f"{outpath}\\{self._fs_tree.item(item)['text']}"
        file_path = os.path.normpath(file_path)

        with open(file_path, 'wb') as f:
            f.write(file_bytes)
        
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