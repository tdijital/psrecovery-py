import math
import os
import time
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import Entry, Label, Menu, PhotoImage, filedialog, simpledialog

from PIL import Image, ImageTk

from analyzer import Node, NodeType
from carver import all_filesigs
from logger import Logger
from ufs import endianness, Endianness

class App(tk.Frame):
    def __init__(self, master, nodes, disk, super_block):
        
        self._super_block = super_block
        self.item_right_click_on = None
        self._search_text = ""
        self.recovered_files = 0
        self.recovered_inodes = 0
        self.recovered_directs = 0
        self._nodes = nodes
        
        # File System
        if endianness is Endianness.BIG:
            # PS3
            self._partition = disk.getPartitionByName('dev_hdd0')
        elif endianness is Endianness.LITTLE:
            # PS4
            self._partition = disk.getPartitionByName('user')
        self._stream = self._partition.getDataProvider()

        self.max_block_index = self._partition.getLength() / self._super_block.fsize

        # Tkinter
        self._master = master
        self._master.geometry("1280x960")
        tk.Frame.__init__(self, master)
        
        tab_control = ttk.Notebook(master)

        # Menubar
        menubar = Menu(self._master)
        self._master.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)

        file_menu.add_command(label="Scan Image")
        file_menu.add_command(label="Scan Image (Encrypted)")
        file_menu.add_separator()
        file_menu.add_command(label="Run File Carver")
        file_menu.add_command(label="Run UE3 Carver")


        # Tab: File System
        tab_fs = ttk.Frame(tab_control)

        tab_fs.pack(fill='both', expand=True)
        tree_columns = ('filesize', 'cdate', 'mdate', 'adate')
        self.fs_tree = ttk.Treeview(tab_fs, columns=tree_columns)
        ysb = ttk.Scrollbar(tab_fs, orient='vertical', command=self.fs_tree.yview)
        xsb = ttk.Scrollbar(tab_fs, orient='horizontal', command=self.fs_tree.xview)
        self.fs_tree.configure(yscroll=ysb.set, xscroll=xsb.set)
        self.fs_tree.heading('#0', text='Contents', anchor='w')
        self.fs_tree.heading('filesize', text='File Size', anchor="w") #, command=lambda: self.sort_column(2, False))
        self.fs_tree.heading('cdate', text='Date Created', anchor="w")
        self.fs_tree.heading('mdate', text='Date Modified', anchor="w")
        self.fs_tree.heading('adate', text='Date Accessed', anchor="w")

        tab_fs.grid_rowconfigure(0, weight=1)
        tab_fs.grid_columnconfigure(0, weight=1)

        # Tab: File Carver
        tab_carver = ttk.Frame(tab_control)

        tab_control.add(tab_fs, text="File System")
        tab_control.add(tab_carver, text="File Carver")
        tab_control.pack(expand = 1, fill ="both")

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
        self.fs_tree.column("#0", minwidth=0, width=400)

        # self.pack()
        root_node = self.fs_tree.insert('', tk.END, text='Root', image=self.folder_direct_ref_ico)
        self.node_map = {}
        Logger.log("Processing directories...")
        self.process_directory(root_node, nodes)
        Logger.log(f"Fully Recovered: {self.recovered_files} files!")
        Logger.log(f"Inodes: {self.recovered_inodes} inodes!")
        Logger.log(f"Directs: {self.recovered_directs} directs!")
        Logger.log("Sorting directories...")
        # self.sort_root_folders_to_top()
        # self.fs_tree.grid(sticky='nesw')
        # self.fs_tree.pack(side='left', fill='both', expand=True)

        self.fs_tree.grid(row=0, column=0, sticky='nesw')
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
        self.fs_tree.bind("<ButtonRelease-3>", self.open_context_menu)
    
    def open_context_menu(self, event):
        item = self.fs_tree.identify('row', event.x, event.y)
        self.item_right_click_on = item
        #self.fs_tree.selection_set(item)
        #self.fs_tree.focus(item)
        self.context_menu.tk_popup( event.x_root + 60, event.y_root + 10, 0)
    
    def identify_file(self, node):
        if node.get_direct() is None:
            inode = node.get_inode()
            file_offset = inode.db[0] * self._super_block.fsize
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
        info_window.title(f"{self.fs_tree.item(self.item_right_click_on)['text']} Info")

        def add_attribute_row_item(label, value, row):
            entryText = tk.StringVar()
            entryText.set(value)
            lbl = Label(info_window, text=f'{label:<20}')
            entry = Entry(info_window, textvariable=entryText, state='readonly')
            lbl.grid(row=row, column=0, padx=2)
            entry.grid(row=row, column=1)

        add_attribute_row_item( "Filename: ",
                                self.fs_tree.item(self.item_right_click_on)['text'],
                                0)
        add_attribute_row_item( "Direct Offset: ",
                                self.node_map[self.item_right_click_on].get_direct_offset(),
                                1)
        add_attribute_row_item( "Directory Offset: ",
                                self.node_map[self.item_right_click_on].get_directory_offset(),
                                2)
        add_attribute_row_item( "Inode Offset: ",
                                self.node_map[self.item_right_click_on].get_inode_offset(),
                                3)
        add_attribute_row_item( "Has Inode: ",
                                'True' if self.node_map[self.item_right_click_on].get_inode() else 'False',
                                4)
        add_attribute_row_item( "Node ID: ",
                                id(self.node_map[self.item_right_click_on]),
                                5)
        
    def recover_selected_files(self):
        outpath = filedialog.askdirectory()
        if outpath == '':
            return 
        Logger.log("Recover files...")
        recover_items = []
        for item in self.fs_tree.selection():
            recover_items.append(item)
            child_items = self.get_all_nodes(item)
            for item in child_items:
                recover_items.append(item)

        logfile = open(outpath + '\\recovery-log.txt','w')
        Logger.streams.append(logfile)

        for item in recover_items:
            node:Node = self.node_map[item]

            # Create any parent folders for the file
            item_path = self.get_item_full_path(item)
            path = outpath + "\\" + item_path
            path = os.path.normpath(path)
            dirname = os.path.dirname(__file__)
            fullpath = os.path.join(dirname, path)
            if not os.path.exists(fullpath):
                os.makedirs(fullpath)
                self.set_ts(fullpath, node)
            
            # Read blocks
            if node.get_type() == NodeType.FILE:

                block_indexes = []
                file_bytes = bytearray()
                inode = node.get_inode()

                # If an inode exists read the inodes blocks
                if inode is not None:
                    # Read direct blocks
                    block_indexes = inode.get_block_indexes(self._stream, self._super_block)
                    # Read data
                    remaining = node.get_size()
                    required_blocks = math.ceil(remaining / self._super_block.bsize)
                    block_count = 0
                    while remaining > 0:
                        if block_count+1 > len(block_indexes):
                            Logger.log(f"Error: Not all block indexes ({block_count}/{required_blocks}) recovered")
                            break
                        index = block_indexes[block_count]
                        data_offset = index * self._super_block.fsize
                        self._stream.seek(data_offset)
                        read = min(remaining, self._super_block.bsize)
                        Logger.log(f"Read {read} bytes at offset: 0x{data_offset:X}")
                        file_bytes += self._stream.read(read)
                        remaining -= read
                        block_count += 1
                    Logger.log(f"Recovered: {item_path}{self.fs_tree.item(item)['text']}")
                else:
                    Logger.log(f"Recovered [Direct Only]: {item_path}{self.fs_tree.item(item)['text']}")
                
                # Write the file     
                file_path = fullpath + "\\" + self.fs_tree.item(item)['text']
                file_path = os.path.normpath(file_path)

                with open(file_path, 'wb') as f:
                    f.write(file_bytes)
                
                self.set_ts(file_path, node)
            
        
        Logger.log("Recovery Completed!")
        Logger.remove_stream(logfile)
        

    def set_ts(self, path, node):
        if node.get_inode() is None:
            return
        atime = node.get_last_access_time()
        mtime = node.get_last_modified_time()

        os.utime(path, (atime, mtime))

    def get_item_full_path(self, item):
        path = ""
        current_parent = str(self.fs_tree.parent(item))
        while True:
            if current_parent == "I001":
                return path
            path = self.fs_tree.item(current_parent)['text'] + "\\" + path
            current_parent = str(self.fs_tree.parent(current_parent))

    def get_all_nodes(self, node=None):
        nodes = []
        for child in self.fs_tree.get_children(node):
            nodes.append(child)
            if self.fs_tree.get_children(child):
                nodes.extend(self.get_all_nodes(child))
        return nodes

    def sort_column(self, column, reverse):
        items = self.fs_tree.get_children('I001')
        l = [(self.fs_tree.set(k, column), k) for k in items]
        l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.fs_tree.move(k, '', index)
        
        self.fs_tree.heading(column, command=lambda: \
            self.sort_column(column, not reverse))

    def sort_root_folders_to_top(self):
        items = self.fs_tree.get_children('I001')
        for item in items:
            if self.node_map[item].get_type() == NodeType.DIRECTORY:
                self.fs_tree.move(item,'I001',0)

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
                return self._nodes[i]
        for i in range(end_index, start_index, increment):
            text = self.fs_tree.item(self._nodes[i])['text']
            if query in text.lower():
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

    def find(self, event):
        Logger.log("Find")
        query = simpledialog.askstring("Find File", "Enter file name:", initialvalue=self._search_text,
            parent=self)
        if query:
            self._search_text = query.lower()
            focused = self.fs_tree.focus()
            found = self.find_text(self._search_text, focused)
            if found:
                self.fs_tree.see(found)
                self.fs_tree.focus(found)
                self.fs_tree.selection_set(found)

    def check_if_inode_indexes_valid(self, node):
        def check_if_indexes_valid(indexes):
            for index in indexes:
                if index > self.max_block_index:
                    return False
            return True
        if node.get_type() == NodeType.FILE:
                # If an inode exists read the inodes blocks
                if node.get_inode() is not None:
                    Logger.log(f"Checking if inode is valid at offset: 0x{node.get_inode_offset():X}")
                    # Check direct blocks
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
            #if node.get_type() != NodeType.FILE and len(node.get_children()) <= 2 and str(parent) == "I001" and not node.get_active():
            #    continue
            # Data
            size = node.get_size()
            ctime = node.get_creation_time()
            atime = node.get_last_access_time()
            mtime = node.get_last_modified_time()
            # Icon
            if node.get_type() == NodeType.FILE:
                #valid = self.check_if_inode_indexes_valid(node)
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
                #if not valid:
                #    icon = self.file_warning_ico
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
            if not node.get_direct() and not node.get_inode() and node.get_directory_offset():
                if name == None:
                    name = f"Folder{node.get_directory_offset():X}"
            elif not node.get_direct() and node.get_inode():
                # self.identify_file(node)
                if node.get_type != NodeType.DIRECTORY:
                    name = f"Inode{node.get_inode_offset():X}{node._filesignature.extension if node._filesignature is not None else ''}"
                else:
                    name = f"Folder{node.get_inode_offset():X}{node._filesignature.extension if node._filesignature is not None else ''}"
            # Tree Item
            item = self.fs_tree.insert(parent, tk.END, text=name,
                values=(
                f'{self.format_bytes(size):<10} ({size} bytes)' if size else '',
                time.ctime(ctime) if ctime and ctime < 32536799999 else '',
                time.ctime(atime) if atime and atime < 32536799999 else '',
                time.ctime(mtime) if mtime and mtime < 32536799999 else '',
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

