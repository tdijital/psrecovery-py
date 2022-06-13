import math
import os
import time

import tkinter as tk
import tkinter
from tkinter.constants import ANCHOR, BOTH, DISABLED, LEFT, NORMAL
import tkinter.ttk as ttk
from tkinter import Entry, Frame, Text, Label, Menu, PhotoImage, Button, Radiobutton, filedialog, simpledialog
from turtle import bgcolor
from typing import Text

from analysis.analyzer import Scanner, UFS2Linker
from analysis.node import Node, NodeType, NodeValidator
from analysis.carver import InodeIdentifier
from analysis.ufs import Endianness, endianness, ino_to_offset
import analysis.ufs
from common.logger import Logger
from common.event import Event

import disklib
from gui.filewriter import FileWriter


class FindDialog(tk.simpledialog.Dialog):
    def __init__(self, root, initial_value):
        self.search_query = None
        self.find_recoverable_only = tk.BooleanVar()
        super().__init__(root, "Search")

    def body(self, frame):
        self.search_box = tk.Entry(frame, width=40)
        self.search_box.pack(expand=1, fill=tk.X)
        self.search_box.focus_set()

        self.chk_btn_active_only = tk.Checkbutton(
            frame, text='Ignore Unrecoverable.', variable=self.find_recoverable_only, onvalue=True, offvalue=False)
        self.chk_btn_active_only.pack(anchor='w')

        return frame

    def search_pressed(self):
        self.search_query = self.search_box.get()
        self.destroy()

    def buttonbox(self):
        self.find_button = tk.Button(
            self, text='Find', width=10, command=self.search_pressed)
        self.find_button.pack(side=tkinter.RIGHT, padx=5, pady=5)
        self.bind("<Return>", lambda event: self.search_pressed())


class FileBrowser(tk.Frame):
    def __init__(self, root, stream, nodes):
        super(FileBrowser, self).__init__()
        self._root = root
        self._stream = stream
        self.item_right_click_on = None
        self._search_text = ""
        self._find_recoverable_only = False
        self.recovered_files = 0
        self.recovered_inodes = 0
        self.recovered_directs = 0
        self.node_map = {}
        self.fs_tree = None

        self.pack(fill=BOTH, expand=True)
        self._create_treeview()
        ysb = ttk.Scrollbar(self, orient='vertical', command=self.fs_tree.yview)
        xsb = ttk.Scrollbar(self, orient='horizontal', command=self.fs_tree.xview)
        self.fs_tree.configure(yscroll=ysb.set, xscroll=xsb.set)
        self.fs_tree.grid(row=0, column=0, sticky='nesw')
        ysb.grid(row=0, column=1, sticky='ns')
        xsb.grid(row=1, column=0, sticky='ew')

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Make the content column wider than others
        self.fs_tree.column("#0", minwidth=0, width=400)

        self.folder_ico = PhotoImage(file='assets/icon-folder.gif')
        self.folder_direct_ico = PhotoImage(file='assets/icon-folder-direct.gif')
        self.folder_direct_ref_ico = PhotoImage(file='assets/icon-folder-direct-ref.gif')
        self.folder_inode_ico = PhotoImage(file='assets/icon-folder-inode.gif')
        self.folder_recovered_ico = PhotoImage(file='assets/icon-folder-recovered.gif')
        self.file_ico = PhotoImage(file='assets/icon-file.gif')
        self.file_direct_ico = PhotoImage(file='assets/icon-file-direct.gif')
        self.file_inode_ico = PhotoImage(file='assets/icon-file-inode.gif')
        self.file_warning_ico = PhotoImage(file='assets/icon-file-warning.gif')
        self.file_recovered_ico = PhotoImage(file='assets/icon-file-recovered.gif')

        #
        # Input
        #
        root.bind('<Control-f>', self.open_find_dialog)
        root.bind('<F3>', self.find_next)
        # Previous
        root.bind('<Shift-F3>', lambda event: self.find_next(event, True))

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label='Recover Selected',
                                      command=self.recover_selected_files)
        self.context_menu.add_command(label='Get Info',
                                      command=self.display_file_info)
        self.fs_tree.bind("<ButtonRelease-3>", self.open_context_menu)

        self.load_nodes(nodes)

    def _create_treeview(self):
       # Implement in classes extending this class
       pass

    def load_nodes(self, nodes):
        self.clear_nodes()
        Logger.log("Processing directories...")
        self._process_nodes(nodes)
        Logger.log(f"Fully Recovered: {self.recovered_files} files!")
        Logger.log(f"Orphaned Inodes: {self.recovered_inodes} inodes!")
        Logger.log(f"Orphaned Directs: {self.recovered_directs} directs!")

        self._nodes = self.get_all_nodes()

    def clear_nodes(self):
        self.fs_tree.delete(*self.fs_tree.get_children())
        self.node_map = {}

    def _process_nodes(self, nodes, parent=None):
        #Implement in the classes extending this class
        pass

    def open_context_menu(self, event):
        item = self.fs_tree.identify('row', event.x, event.y)
        self.item_right_click_on = item
        self.context_menu.tk_popup(event.x_root, event.y_root, 0)

    def display_file_info(self):
        info_window = tk.Toplevel()
        info_window.geometry("250x200")
        info_window.title(
            f"{self.fs_tree.item(self.item_right_click_on)['text']} Info")
        #info_window.resizable(0,1)
        
        grid_frame = Frame(info_window)

        def add_attribute_row_item(label, value, row):
            entryText = tk.StringVar()
            entryText.set(value)
            lbl = Label(grid_frame, text=f'{label:<20}')
            entry = Entry(grid_frame, textvariable=entryText,
                          state='readonly')
            lbl.grid(row=row, column=0, padx=2, sticky=tk.W)
            entry.grid(row=row, column=1, sticky=tk.E)

        add_attribute_row_item("Filename: ", self.fs_tree.item(self.item_right_click_on)['text'],0)
        add_attribute_row_item("Direct Offset: ",self.node_map[self.item_right_click_on].get_direct_offset(),1)
        add_attribute_row_item("Directory Offset: ", self.node_map[self.item_right_click_on].get_directory_offset(), 2)
        add_attribute_row_item("Inode Offset: ", self.node_map[self.item_right_click_on].get_inode_offset(), 3)
        add_attribute_row_item("Has Inode: ", 'True' if self.node_map[self.item_right_click_on].get_inode() else 'False', 4)
        add_attribute_row_item("Node ID: ", id(self.node_map[self.item_right_click_on]), 5)
        if self.node_map[self.item_right_click_on].get_inode():
            # 0x800 is a hardcoded fragment size
            add_attribute_row_item("First DB Offset: ", id(self.node_map[self.item_right_click_on].get_file_offset()), 6)
        grid_frame.pack(anchor=tk.NW)

        debug_text = tk.Text(info_window, font=("regular", 8), wrap="word", padx=4, pady=4)
        debug_text.pack(fill='both', expand=True)
        debug_text.tag_config('note', foreground="#6B6B6B")

        debug_text.insert('end', 'File validation errors:\n', 'note')
        debug_text.insert('end', self.node_map[self.item_right_click_on].get_debug_info_text())


    def recover_selected_files(self):
        outpath = filedialog.askdirectory()
        if outpath == '':
            return
        logfile = open(outpath + '\\dump-log.txt', 'w', encoding='utf8')
        Logger.streams.append(logfile)
        Logger.log(f"Dumping files to: {outpath} ...")
        filewriter = FileWriter(self._stream, self.fs_tree, self.node_map)
        filewriter.write_items(outpath, self.fs_tree.selection())
        Logger.log("Dumping completed!")
        Logger.streams.remove(logfile)

    def format_bytes(self, filesize):
        for count in ['bytes', 'KB', 'MB', 'GB']:
            if filesize > -1024.0 and filesize < 1024.0:
                return "%3.2f%s" % (filesize, count)
            filesize /= 1024.0
        return "%3.2f%s" % (filesize, 'TB')

    def set_file_ts(self, path, node):
        if node.get_inode() is None:
            return
        atime = node.get_last_access_time()
        mtime = node.get_last_modified_time()

        os.utime(path, (atime, mtime))

    def get_all_nodes(self, node=None):
        nodes = []
        for child in self.fs_tree.get_children(node):
            nodes.append(child)
            if self.fs_tree.get_children(child):
                nodes.extend(self.get_all_nodes(child))
        return nodes

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
            text = self.fs_tree.item(self._nodes[i])['text']
            if query in text.lower():
                if self._find_recoverable_only and not self.node_map[self._nodes[i]].get_inode():
                    continue
                return self._nodes[i]
        for i in range(end_index, start_index, increment):
            text = self.fs_tree.item(self._nodes[i])['text']
            if query in text.lower():
                if self._find_recoverable_only and not self.node_map[self._nodes[i]].get_inode():
                    continue
                return self._nodes[i]
        return None

    def find_next(self, event, reversed=False):
        if self._search_text != '':
            focused = self.fs_tree.focus()
            found = self.find_text(self._search_text, focused, reversed)
            if found:
                self.fs_tree.see(found)
                self.fs_tree.focus(found)
                self.fs_tree.selection_set(found)

    def open_find_dialog(self, event):
        search = FindDialog(self._root, self._search_text)
        if search.search_query:
            self._search_text = search.search_query.lower()
            self._find_recoverable_only = search.find_recoverable_only.get()
            focused = self.fs_tree.focus()
            found = self.find_text(self._search_text, focused)
            if found:
                self.fs_tree.see(found)
                self.fs_tree.focus(found)
                self.fs_tree.selection_set(found)


class MetaAnalysisFileBrowser(FileBrowser):
    def __init__(self, root, stream, nodes):
        super().__init__(root, stream, nodes)

    def clear_nodes(self):
        super().clear_nodes()
        self.recovered_directs = 0
        self.recovered_files = 0
        self.recovered_inodes = 0

    def _create_treeview(self):
        tree_columns = ('filesize', 'cdate', 'mdate', 'adate')
        self.fs_tree = ttk.Treeview(self, columns=tree_columns)
        self.fs_tree.heading('#0', text='Contents', anchor='w')
        self.fs_tree.heading('filesize', text='File Size', anchor="w")
        self.fs_tree.heading('cdate', text='Date Created', anchor="w")
        self.fs_tree.heading('mdate', text='Date Modified', anchor="w")
        self.fs_tree.heading('adate', text='Date Accessed', anchor="w")

    def _process_nodes(self, nodes, parent=None):
        if not parent:
            parent = self.fs_tree.insert('', tk.END, text='Root', image=self.folder_direct_ref_ico)
        for node in nodes:
            node: Node
            # Exclude meta data
            if node.get_name() == '.' or node.get_name() == '..':
                continue
            size = node.get_size()
            ctime = node.get_creation_time()
            atime = node.get_last_access_time()
            mtime = node.get_last_modified_time()
            # Icon
            if node.get_type() == NodeType.FILE:
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
                if not node.get_valid():
                    icon = self.file_warning_ico
            else:
                if node.get_inode() and node.get_direct():
                    if node.get_active() is True:
                        icon = self.folder_ico
                    else:
                        icon = self.folder_recovered_ico
                elif node.get_inode():
                    icon = self.folder_inode_ico
                elif node.get_direct():
                    icon = self.folder_direct_ico
                else:
                    icon = self.folder_direct_ref_ico
            # Name
            name = node.get_name()
            if name == None:
                if node.get_type() == NodeType.DIRECTORY:
                    if node.get_inode_offset():
                        name = f"Folder{node.get_inode_offset():X}"
                    elif node.get_direct_offset():
                        name = f"Folder{node.get_direct_offset():X}"
                else:
                    if node.get_inode_offset():
                        name = f"File{node.get_inode_offset():X}{node.get_file_ext() or ''}"
                    elif node.get_direct_offset():
                        name = f"File{node.get_direct_offset():X}{node.get_file_ext() or ''}"
            if name == None:
                name = "Unknown"

            # Tree Item
            item = self.fs_tree.insert(parent, tk.END, text=name,
                                       values=(
                                           f'{self.format_bytes(size):<10} ({size} bytes)' if size else '',
                                           time.ctime(ctime) if ctime and ctime < 32536799999 else '',
                                           time.ctime(atime) if atime and atime < 32536799999 else '',
                                           time.ctime(mtime) if mtime and mtime < 32536799999 else '',
                                       ), image=icon)
            self.node_map[item] = node
            if node.get_type() == 1:
                self._process_nodes(node.get_children(), item)


class FileCarverFileBrowser(FileBrowser):
    def __init__(self, root, stream, nodes):
        super().__init__(root, stream, nodes)

    def _create_treeview(self):
        tree_columns = ('filesize', 'fileoffset')
        self.fs_tree = ttk.Treeview(self, columns=tree_columns)
        self.fs_tree.heading('#0', text='Contents', anchor='w')
        self.fs_tree.heading('filesize', text='File Size', anchor="w")
        self.fs_tree.heading('fileoffset', text='File Offset', anchor="w")
 
    def _process_nodes(self, nodes, parent=None):
        if parent == None:
            parent = self.fs_tree.insert('', tk.END, text='Files', image=self.folder_direct_ref_ico)
        for node in nodes:
            node: Node
            size = node.get_size()
            icon = self.file_recovered_ico if size else self.file_ico
            if node.get_name() == None:
                name = f"File{node.get_file_offset():X}"
            else:
                name = node.get_name()
            if node.get_file_ext() != None:
                name += node.get_file_ext()
            # Tree Item
            item = self.fs_tree.insert(parent, tk.END, text=name, 
            values=(
                f'{self.format_bytes(size):<10} ({size} bytes)' if size else '', 
                f'0x{node.get_file_offset():X}',
            ), image=icon)
            self.node_map[item] = node


class UnrealFileBrowser(FileBrowser):
    def __init__(self, root, stream, nodes):
        super().__init__(root, stream, nodes)

    def _create_treeview(self):
        tree_columns = ('filesize', 'fileoffset')
        self.fs_tree = ttk.Treeview(self, columns=tree_columns)
        self.fs_tree.heading('#0', text='Contents', anchor='w')
        self.fs_tree.heading('filesize', text='File Size', anchor="w")
        self.fs_tree.heading('fileoffset', text='File Offset', anchor="w")
    
    def _process_nodes(self, nodes, parent=None):
        if parent == None:
            parent = self.fs_tree.insert('', tk.END, text='Unreal', image=self.folder_direct_ref_ico)
        for node in nodes:
            node: Node
            size = node.get_size()

            # Icon
            if node.get_type() == NodeType.FILE:
                if node.get_file_offset():
                    icon = self.file_inode_ico
                else:
                    icon = self.file_direct_ico
            else:
                icon = self.folder_ico

            # Naming
            file_offset = None
            if node.get_file_offset():
                file_offset = f'0x{node.get_file_offset():X}'
            else:
                file_offset = 'Unknown'
            if node.get_name() == None:
                name = f"File{node.get_file_offset():X}"
            else:
                name = node.get_name()
            if node.get_file_ext() != None:
                name += node.get_file_ext()
            # Tree Item
            item = self.fs_tree.insert(parent, tk.END, text=name, 
            values=(
                f'{self.format_bytes(size):<10} ({size} bytes)' if size else '', 
                file_offset,
            ), image=icon)
            self.node_map[item] = node

            # Process children nodes
            if node.get_type() == NodeType.DIRECTORY:
                self._process_nodes(node.get_children(), item)