import math
import os
import time
import tkinter as tk
import tkinter
from tkinter.constants import ANCHOR, BOTH, DISABLED, LEFT, NORMAL
import tkinter.ttk as ttk
from tkinter import Entry, Label, Menu, PhotoImage, Button, Radiobutton, Text, filedialog, mainloop, simpledialog

from analysis.analyzer import Node, NodeType, Scanner, UFS2Linker
from analysis.carver import all_filesigs
from analysis.ufs import Endianness, endianness
from common.logger import Logger
from common.event import Event
from analysis.carver import InodeIdentifier, all_filesigs

import disklib

class App(tk.Frame):
    def __init__(self, master, path = None, key=None, deep_scan=None):
        # Tkinter
        tk.Frame.__init__(self, master)

        self._master = master
        self._recovered_file_browser = None
        self._disk = None
        self._splash = None

        # Menubar
        menubar = Menu(self._master)
        self._master.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)

        file_menu.add_command(label="Open HDD img",command=self.display_open_image_modal)

        self._master.after(100, self.scan_new_hdd, path, key, deep_scan)
        self.show_splash()

    def show_splash(self):
        splash_image = PhotoImage(file='assets/app-icon2.gif')
        self._splash = inner_frame = tk.Frame(self._master, borderwidth=25, bg="black")
        inner_frame.pack(fill="both", expand=True)
        Label(inner_frame, image=splash_image, background='black').pack(fill="both", expand=True)
        self._master.mainloop()

    def scan_new_hdd(self, path, keyfile=None, is_deep_scan=False):

        # Open img
        file_disk_stream = disklib.FileDiskStream(path)
        config = disklib.DiskConfig()
        config.setStream(file_disk_stream)
        
        # Open eid keyfile
        if keyfile:
            keys = open(keyfile, 'rb').read()
            config.setKeys(keys)
        else:
            Logger.log("\nDecrypted drive support is broken currently... \nOpen an encrypted drive with a keyfile")

        self._disk = disklib.DiskFormatFactory.detect(config)

        stream = self._disk.getDataProvider()

        ps3_magic1 = bytes.fromhex('0FACE0FF')
        ps3_magic2 = bytes.fromhex('DEADFACE')
        stream.seek(0x14)
        magic1 = stream.read(0x4)
        stream.seek(0x1C)
        magic2 = stream.read(0x4)

        global endianness

        scan_partition = ''
        if ps3_magic1 == magic1 or ps3_magic2 == magic2:
            endianness = Endianness.BIG
            scan_partition = 'dev_hdd0'
            Logger.log("Scanning PS3 HDD img...")
        else:
            endianness = Endianness.LITTLE
            scan_partition = 'user'
            Logger.log("Scanning PS4 HDD img...")

        scanner = Scanner(self._disk, scan_partition)
        scan_logfile = None
        
        load_path = os.path.normpath(f"{os.getcwd()}\\scans") + "\\" + os.path.basename(path).split(".")[0]
        load_path = load_path.lower()

        # If this scan hasn't completed before write a log
        if not os.path.exists(load_path + "\\scan-log.txt"):
            scan_logfile = open('scan-log.txt','w', encoding='utf8')
            Logger.streams.append(scan_logfile)

        # Find deleted inodes and directs
        scanner.scan(load_path, is_deep_scan)

        # Stop logging for the scan
        if scan_logfile:
            Logger.remove_stream(scan_logfile)

        self.open_scan_results(self._disk, scanner.scan_results)

    def open_scan_results(self, disk, scan_results):
        # Creates nodes and makes associations between inodes and directs
        linker = UFS2Linker(disk, scan_results)
        
        nodes = linker.get_root_nodes()

        # Identify file types
        Logger.log("Identifying unknown files filetypes...")
        inode_ident = InodeIdentifier(disk, scan_results.partition_name)
        identified_count = 0
        for node in nodes:
            node:Node
            if not node.get_inode() or node.get_type() == NodeType.DIRECTORY or node.get_direct():
                continue
            file_sig = inode_ident.identify_unk_inode_filetype(node.get_inode())
            if file_sig:
                identified_count += 1
                node.set_file_ext(file_sig.extension)

        Logger.log(f"Identified {identified_count} unknown filetypes!")
        
        if self._splash:
            self._splash.pack_forget()
            self._splash.grid_forget()
            self._splash.destroy()
            self._splash = None

        if self._recovered_file_browser:
            self._recovered_file_browser.load_nodes(nodes)
        else:
            self._recovered_file_browser = RecoveredFilesBrowser(self._master, nodes)


    def display_open_image_modal(self):
        open_image_modal = OpenHDDImageModal()
        open_image_modal.on_scan_initiated += self.scan_new_hdd



class OpenHDDImageModal(tk.Frame):
    def __init__(self):
        # Init Vars
        self._default_text_browse_img:str = "Browse for HDD img..."
        self._default_text_browse_eid = "Browse for EID key..."
        self.img_path_string = tk.StringVar()
        self.img_path_string.set(self._default_text_browse_img)
        self.eid_path_string = tk.StringVar()
        self.eid_path_string.set(self._default_text_browse_eid)
        self.deep_scan = tk.IntVar()
        self.deep_scan.set(1)
        self.on_scan_initiated = Event()
        
        # GUI
        self.modal = tk.Toplevel()
        self.modal.geometry("460x150")
        self.modal.title("Open PS3 or PS4 HDD Img...")
        self.entry_image_path = Entry(self.modal, textvariable=self.img_path_string, fg="#AAAAAA")
        self.entry_image_path.place(x=10,y=10,width=390,height=28)
        img_browser_btn = Button(self.modal, text="Browse", command=self.open_filedialog_image).place(x=400,y=10)
        self.entry_eid_path = Entry(self.modal, textvariable=self.eid_path_string, fg="#AAAAAA")
        self.entry_eid_path.place(x=10,y=40,width=390,height=28)
        eid_browse_btn = Button(self.modal, text="Browse", command=self.open_filedialog_eid).place(x=400,y=40)
        fast_scan = Radiobutton(self.modal, text="Fast Scan*", variable=self.deep_scan, value=1).place(x=10,y=70)
        deep_scan = Radiobutton(self.modal, text="Deep Scan", variable=self.deep_scan, value=2).place(x=100,y=70)
        help_label = Label(self.modal, text="*Fast scan is much faster and more reliable.", font=("Arial", 8), fg="#AAAAAA", justify=LEFT, anchor="w").place(x=10,y=90,width=450,height=20)
        self.scan_btn = Button(self.modal, text="Scan", command=self.begin_scan, state=DISABLED)
        self.scan_btn.place(x=400,y=120)


    def open_filedialog_image(self):
        outpath = filedialog.askopenfilename(title="Open a PS3 or PS4 img...", filetypes=[('HDD Image', '*.img')], initialdir='/')
        self.modal.lift()
        if(outpath == ""):
            return
        self.img_path_string.set(outpath)
        self.scan_btn['state'] = NORMAL
        self.entry_image_path['fg'] = "#000000"
    
    def open_filedialog_eid(self):
        initialdir = "/"
        if(self.img_path_string.get() != self._default_text_browse_img) :
            initialdir = os.path.dirname(self.img_path_string.get())
        outpath = filedialog.askopenfilename(title="Open EID key...", initialdir=initialdir)
        self.modal.lift()
        if(outpath == ""):
            return
        self.eid_path_string.set(outpath)
        self.entry_eid_path['fg'] = "#000000"

    def begin_scan(self):
        path = self.img_path_string.get()
        keyfile = self.eid_path_string.get()
        deep_scan = self.deep_scan.get()
        if path == None or path in self._default_text_browse_img:
            return
        self.modal.destroy()
        self.on_scan_initiated(path,keyfile,deep_scan)


class FindDialog(tk.simpledialog.Dialog):
    def __init__(self, root, initial_value):
        self.search_query = None
        self.find_recoverable_only = tk.BooleanVar()
        super().__init__(root, "Search")

    def body(self, frame):
        self.search_box = tk.Entry(frame, width=40)
        self.search_box.pack(expand=1, fill=tk.X)
        self.search_box.focus_set()

        self.chk_btn_active_only = tk.Checkbutton(frame, text='Ignore Unrecoverable.',variable=self.find_recoverable_only, onvalue=True, offvalue=False)
        self.chk_btn_active_only.pack(anchor='w')

        return frame

    def search_pressed(self):
        self.search_query = self.search_box.get()
        self.destroy()

    def buttonbox(self):
        self.find_button = tk.Button(self, text='Find', width=10, command=self.search_pressed)
        self.find_button.pack(side=tkinter.RIGHT, padx=5, pady=5)
        self.bind("<Return>", lambda event: self.search_pressed())


class RecoveredFilesBrowser(tk.Frame):
    def __init__(self, root, nodes):
        super(RecoveredFilesBrowser, self).__init__()
        self.item_right_click_on = None
        self._search_text = ""
        self._find_recoverable_only = False
        self.recovered_files = 0
        self.recovered_inodes = 0
        self.recovered_directs = 0
        self.node_map = {}

        root.geometry("1440x960")

        tab_control = ttk.Notebook(root)

        # Tab: File System
        tab_fs = ttk.Frame(tab_control)

        tab_fs.pack(fill=BOTH, expand=True)
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

        # Tabs Header
        tab_control.add(tab_fs, text="File System")
        tab_control.add(tab_carver, text="File Carver")
        tab_control.pack(expand = 1, fill =BOTH)

        self.folder_ico = PhotoImage(file='assets/icon-folder.gif')
        self.folder_direct_ico = PhotoImage(file='assets/icon-folder-direct.gif')
        self.folder_direct_ref_ico = PhotoImage (file='assets/icon-folder-direct-ref.gif')
        self.folder_inode_ico = PhotoImage(file='assets/icon-folder-inode.gif')
        self.folder_recovered_ico = PhotoImage(file='assets/icon-folder-recovered.gif')
        self.file_ico = PhotoImage(file='assets/icon-file.gif')
        self.file_direct_ico = PhotoImage(file='assets/icon-file-direct.gif')
        self.file_inode_ico = PhotoImage(file='assets/icon-file-inode.gif')
        self.file_warning_ico = PhotoImage(file='assets/icon-file-warning.gif')
        self.file_recovered_ico = PhotoImage(file='assets/icon-file-recovered.gif')

        # Make the content column wider than others
        self.fs_tree.column("#0", minwidth=0, width=400)

        self.fs_tree.grid(row=0, column=0, sticky='nesw')
        ysb.grid(row=0, column=1, sticky='ns')
        xsb.grid(row=1, column=0, sticky='ew')
        root.bind('<Control-f>', self.open_find_dialog)
        root.bind('<F3>', self.find_next)
        root.bind('<Shift-F3>', lambda event:self.find_next(event, True)) # Previous

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label='Recover Selected',
                                      command=self.recover_selected_files)
        self.context_menu.add_command(label='Get Info',
                                      command=self.display_file_info)
        self.fs_tree.bind("<ButtonRelease-3>", self.open_context_menu)

        self.load_nodes(nodes)

    def load_nodes(self, nodes):
        self.clear_nodes()
        Logger.log("Processing directories...")
        self._process_nodes(nodes)
        Logger.log(f"Fully Recovered: {self.recovered_files} files!")
        Logger.log(f"Orphaned Inodes: {self.recovered_inodes} inodes!")
        Logger.log(f"Orphaned Directs: {self.recovered_directs} directs!")
        
        self._nodes = self.get_all_nodes()

    def clear_nodes(self):
        self.recovered_directs = 0
        self.recovered_files = 0
        self.recovered_inodes = 0
        self.fs_tree.delete(*self.fs_tree.get_children())
        self.node_map = {}

    def _process_nodes(self, nodes, parent=None):
        if not parent:
            parent = self.fs_tree.insert('', tk.END, text='Root', image=self.folder_direct_ref_ico)
        for node in nodes:
            node:Node
            # Exclude meta data
            if node.get_name() == '.' or node.get_name() == '..':
                continue
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

    def open_context_menu(self, event):
        item = self.fs_tree.identify('row', event.x, event.y)
        self.item_right_click_on = item
        #self.fs_tree.selection_set(item)
        #self.fs_tree.focus(item)
        self.context_menu.tk_popup( event.x_root + 60, event.y_root + 10, 0)

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
                self.set_file_ts(fullpath, node)
            
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
                
                self.set_file_ts(file_path, node)
            
        
        Logger.log("Recovery Completed!")
        Logger.remove_stream(logfile)
        
    def format_bytes(self, filesize):
        for count in ['bytes','KB','MB','GB']:
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
        search = FindDialog(self._master, self._search_text)
        if search.search_query:
            self._search_text = search.search_query.lower()
            self._find_recoverable_only = search.find_recoverable_only.get()
            focused = self.fs_tree.focus()
            found = self.find_text(self._search_text, focused)
            if found:
                self.fs_tree.see(found)
                self.fs_tree.focus(found)
                self.fs_tree.selection_set(found)