import math
import os
import time

import tkinter as tk
import tkinter
from tkinter.constants import ANCHOR, BOTH, DISABLED, LEFT, NORMAL
import tkinter.ttk as ttk
from tkinter import Entry, Label, Menu, PhotoImage, Button, Radiobutton, filedialog, simpledialog

from analysis.analyzer import Scanner, UFS2Linker
from analysis.node import Node, NodeType, NodeValidator
from analysis.carver import InodeIdentifier
from analysis.ufs import Endianness, endianness
import analysis.ufs
from common.logger import Logger
from common.event import Event

import disklib
from gui.filewriter import FileWriter


class DiskType():
    PS3 = 0
    PS4 = 1

_file_disk_stream = None

class App(tk.Frame):
    def __init__(self, master, path = None, key=None, deep_scan=None):
        # Tkinter
        tk.Frame.__init__(self, master)

        self._master = master
        self._recovered_file_browser = None
        self._splash = None
        self._tab_control = ttk.Notebook(self._master)

        self._current_disk = None
        self._current_diskpath = ''
        self._current_keypath = ''
        self._current_partition_name = ''
        self._deep_scan = deep_scan

        # Menubar
        menubar = Menu(self._master)
        self._master.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)

        file_menu.add_command(label="Open HDD img",command=self.display_open_hdd_img_modal)

        if path:
            self._master.after(100, self.begin_disk_scan, path, key, deep_scan)

        self.show_splash()

    def show_splash(self):
        splash_image = PhotoImage(file='assets/app-icon.gif')
        self._splash = inner_frame = tk.Frame(self._master, borderwidth=25, bg="#1F67F6")
        inner_frame.pack(fill="both", expand=True)
        Label(inner_frame, image=splash_image, background='#1F67F6').pack(fill="both", expand=True)
        self._master.mainloop()

    def begin_disk_scan(self, path, keyfile=None, is_deep_scan=False):
        # Open the disk
        self._current_disk = self._open_disk(path, keyfile)

        # Scan the disks partition
        scan_results = self.scan_partition(self._current_disk, self._current_partition_name, is_deep_scan)
        
        # Create nodes from the scans results
        nodes = self.create_nodes_from_scan_results(self._current_disk, scan_results)

        # Create Stream
        partition = self._current_disk.getPartitionByName(self._current_partition_name)
        stream = partition.getDataProvider()
        
        # Attempt to identify unknown nodes with inodes
        nodes = self.identify_unknown_node_filetypes(stream, nodes)

        # Check validity of nodes
        self.check_nodes_validity(stream, nodes)

        # Show results
        self.display_scan_results_tab(stream, nodes)

    def _open_disk(self, path, keyfile=None, is_deep_scan=False):
        global _file_disk_stream
        _file_disk_stream = disklib.FileDiskStream(path)
        config = disklib.DiskConfig()
        config.setStream(_file_disk_stream)
        
        # Open eid keyfile
        if keyfile:
            keys = open(keyfile, 'rb').read()
            config.setKeys(keys)
  
        disk = disklib.DiskFormatFactory.detect(config)

        self._current_diskpath = path
        self._current_keypath = keyfile

        disktype = self._get_disktype(disk)
        self.set_disktype(disktype)
        
        return disk

    def _get_disktype(self, disk):
        stream = disk.getDataProvider()

        ps3_magic1 = bytes.fromhex('0FACE0FF')
        ps3_magic2 = bytes.fromhex('DEADFACE')
        stream.seek(0x14)
        magic1 = stream.read(0x4)
        stream.seek(0x1C)
        magic2 = stream.read(0x4)

        disktype = None

        if ps3_magic1 == magic1 or ps3_magic2 == magic2:
            Logger.log("Detected PS3 HDD img...")
            disktype = DiskType.PS3
        else:
            Logger.log("Detected PS4 HDD img...")
            disktype = DiskType.PS4

        return disktype

    def set_disktype(self, disktype):
        if disktype == DiskType.PS3:
            analysis.ufs.endianness = Endianness.BIG
            self._current_partition_name = 'dev_hdd0'
            Logger.log("Set disk type to PS3: Partition dev_hdd0")
        if disktype == DiskType.PS4:
            analysis.ufs.endianness = Endianness.LITTLE
            self._current_partition_name = 'user'
            Logger.log("Set disk type to PS4: Partition user")

    def scan_partition(self, disk, partition_name, is_deep_scan):
        scanner = Scanner(disk, partition_name)
        scan_logfile = None
        
        load_path = os.path.normpath(f"{os.getcwd()}\\scans") + "\\" + os.path.basename(self._current_diskpath).split(".")[0]
        load_path = load_path.lower()
        load_path += "(deep)" if is_deep_scan else "(fast)"

        # If this scan hasn't completed before write a scan-log
        if not os.path.exists(load_path + "\\inodes.txt"):
            if not os.path.exists(load_path):
                os.makedirs(load_path)
            scan_logfile = open(load_path + '\\scan-log.txt','w', encoding='utf8')
            Logger.streams.append(scan_logfile)

        # Find deleted inodes and directs
        scanner.scan(load_path, is_deep_scan)

        # Stop logging for the scan
        if scan_logfile:
            Logger.remove_stream(scan_logfile)
        
        return scanner.scan_results

    def create_nodes_from_scan_results(self, disk, scan_results):
        # Creates nodes and makes associations between inodes and directs
        linker = UFS2Linker(disk, scan_results)
        nodes = linker.get_root_nodes()
        return nodes

    def identify_unknown_node_filetypes(self, stream, nodes):
        Logger.log("Identifying unknown files filetypes...")
        inode_ident = InodeIdentifier(stream)
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
        return nodes

    def check_nodes_validity(self, stream, nodes):
        Logger.log("Checking validity of nodes...")
        validator = NodeValidator(stream)
        for node in nodes:
            validator.validate(node)
            if len(node.get_children()) > 0:
                self.check_nodes_validity(stream, node.get_children())

    def display_scan_results_tab(self, stream, nodes):
        if self._splash:
            self._splash.pack_forget()
            self._splash.grid_forget()
            self._splash.destroy()
            self._splash = None
        
        if self._recovered_file_browser:
            self._recovered_file_browser.load_nodes(nodes)
        else:
            self._master.geometry("1440x960")

            # Create frame for viewing the scan results
            self._recovered_file_browser = RecoveredFilesBrowser(self._master, stream, nodes)
            
            # Put the tab for the frame in the _tab_control
            self._tab_control.add(self._recovered_file_browser, text="File System")
            self._tab_control.pack(expand = 1, fill =BOTH)

    def display_open_hdd_img_modal(self):
        open_image_modal = OpenHDDImageModal()
        open_image_modal.on_scan_initiated += self.begin_disk_scan



class OpenHDDImageModal(tk.Frame):
    def __init__(self):
        # Init Vars
        self._default_text_browse_img:str = "Browse for HDD img..."
        self._default_text_browse_eid = "Browse for EID key..."
        self.img_path_string = tk.StringVar()
        self.img_path_string.set(self._default_text_browse_img)
        self.eid_path_string = tk.StringVar()
        self.eid_path_string.set(self._default_text_browse_eid)
        self.deep_scan = tk.BooleanVar()
        self.deep_scan.set(False)
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
        fast_scan = Radiobutton(self.modal, text="Fast Scan*", variable=self.deep_scan, value=False).place(x=10,y=70)
        deep_scan = Radiobutton(self.modal, text="Deep Scan", variable=self.deep_scan, value=True).place(x=100,y=70)
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
        if self._default_text_browse_eid in keyfile:
            keyfile = None
        if self._default_text_browse_img in path:
            path = None
        deep_scan = self.deep_scan.get()
        if path == None:
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
    def __init__(self, root, stream, nodes):
        super(RecoveredFilesBrowser, self).__init__()
        self._root = root
        self._stream = stream
        self.item_right_click_on = None
        self._search_text = ""
        self._find_recoverable_only = False
        self.recovered_files = 0
        self.recovered_inodes = 0
        self.recovered_directs = 0
        self.node_map = {}

        self.pack(fill=BOTH, expand=True)
        tree_columns = ('filesize', 'cdate', 'mdate', 'adate')
        self.fs_tree = ttk.Treeview(self, columns=tree_columns)
        ysb = ttk.Scrollbar(self, orient='vertical', command=self.fs_tree.yview)
        xsb = ttk.Scrollbar(self, orient='horizontal', command=self.fs_tree.xview)
        self.fs_tree.configure(yscroll=ysb.set, xscroll=xsb.set)
        self.fs_tree.heading('#0', text='Contents', anchor='w')
        self.fs_tree.heading('filesize', text='File Size', anchor="w") #, command=lambda: self.sort_column(2, False))
        self.fs_tree.heading('cdate', text='Date Created', anchor="w")
        self.fs_tree.heading('mdate', text='Date Modified', anchor="w")
        self.fs_tree.heading('adate', text='Date Accessed', anchor="w")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

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

    def open_context_menu(self, event):
        item = self.fs_tree.identify('row', event.x, event.y)
        self.item_right_click_on = item
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
        logfile = open(outpath + '\\dump-log.txt','w', encoding='utf8')
        Logger.streams.append(logfile)
        Logger.log(f"Dumping files to: {outpath} ...")
        filewriter = FileWriter(self._stream, self.fs_tree, self.node_map)
        filewriter.write_items(outpath, self.fs_tree.selection())
        Logger.log("Dumping completed!")
        Logger.streams.remove(logfile)
        
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