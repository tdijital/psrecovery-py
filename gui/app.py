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
from analysis.carver import FileCarver, InodeIdentifier
from analysis.ufs import Endianness, endianness
import analysis.ufs
from common.logger import Logger
from common.event import Event

import disklib
from gui.filewriter import FileWriter

from gui.filebrowser import FileBrowser, FileCarverFileBrowser, MetaAnalysisFileBrowser


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
        self._carved_file_browser = None
        self._splash = None
        self._tab_control = ttk.Notebook(self._master)

        self._current_disk = None
        self._current_diskpath = ''
        self._current_keypath = ''
        self._current_partition_name = ''
        self._deep_scan = deep_scan

        # Menubar
        self.menubar = Menu(self._master)
        self._master.config(menu=self.menubar)

        self.file_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=self.file_menu)

        self.file_menu.add_command(label="Open HDD img",command=self.display_open_hdd_img_modal)

        self.scan_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Scan", menu=self.scan_menu)

        #self.scan_menu.add_command(label="Run Metadata Analyzer",command=self.display_open_hdd_img_modal)
        self.scan_menu.add_command(label="Run File Carver",command=self.begin_file_carver_scan)

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
        Logger.log("Checking validity of nodes...")
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
            self._recovered_file_browser = MetaAnalysisFileBrowser(self._master, stream, nodes)
            
            self.pack_notebook()

    def begin_file_carver_scan(self):
        if self._current_disk is None:
            Logger.log("Cannot begin file carver no disk has been opened.")
            return
        # This scans the whole disk not just the partition
        stream = self._current_disk.getDataProvider()
        filecarver = FileCarver(stream)
        filecarver.scan(stream)
        nodes =  filecarver.get_nodes()
        self._carved_file_browser = FileCarverFileBrowser(self._master, stream, nodes)
        
        self.pack_notebook()

    def pack_notebook(self):
        self._tab_control.pack_forget()
        if self._recovered_file_browser:
            self._tab_control.add(self._recovered_file_browser, text="Metadata Analysis")
        if self._carved_file_browser:
            self._tab_control.add(self._carved_file_browser, text="File Carver Results")
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