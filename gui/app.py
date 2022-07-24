import math
import os
import time
import threading

import tkinter as tk
import tkinter
from tkinter.constants import ANCHOR, BOTH, DISABLED, LEFT, NORMAL, HORIZONTAL, SE, SW, S, N, NE, NW, NSEW
import tkinter.ttk as ttk
from tkinter import Entry, Label, Menu, PhotoImage, Button, Radiobutton, StringVar, OptionMenu, filedialog, simpledialog
from tkinter.ttk import Progressbar

from analysis.analyzer import Scanner, UFS2Linker
from analysis.node import Node, NodeType, NodeValidator
from analysis.carver import FileCarverScanner, InodeIdentifier
from analysis.ufs import Endianness, endianness
from analysis.unreal import UnrealAnalyzer
import analysis.ufs
from common.logger import Logger
from common.event import Event

import disklib
from gui.filewriter import FileWriter

from gui.filebrowser import FileBrowser, FileCarverFileBrowser, MetaAnalysisFileBrowser, UnrealFileBrowser


class DiskType():
    PS3 = 0
    PS4 = 1


_file_disk_stream = None

class MetaDataScannerThread(threading.Thread):
    def __init__(self, disk, partition_name):
        threading.Thread.__init__(self)
        self.meta_data_scanner = Scanner(disk, partition_name)
        self.nodes = []
        self.name = 'Scanner'
        self._disk = disk
        self._partition_name = partition_name
        self._loadpath = ''
        self._deep_scan = False
        self._scan_complete = False
        self._terminate_thread = False

    def set_scan_args(self, loadpath, deep_scan=False):
        self._loadpath = loadpath
        self._deep_scan = deep_scan
        
    def run(self):
        self._terminate_thread = False

        self.meta_data_scanner.scan(self._loadpath,self._deep_scan)

        if self._terminate_thread:
            return
        
        self.meta_data_scanner.scan_active_filesystem()
        
        # Creates nodes and makes associations between inodes and directs
        linker = UFS2Linker(self._disk, self.meta_data_scanner.scan_results)
        self.nodes = linker.get_root_nodes()

        # Create Stream
        partition = self._disk.getPartitionByName(self._partition_name)
        stream = partition.getDataProvider()
        
        # Attempt to identify unknown nodes with inodes
        nodes = self.identify_unknown_node_filetypes(stream, self.nodes)

        # Check validity of nodes
        Logger.log("Checking validity of nodes...")
        self.check_nodes_validity(stream, self.nodes)

        self._scan_complete = True
        self.is_alive = False

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
                if file_sig.name != '':
                    node.set_name(file_sig.name)

        Logger.log(f"Identified {identified_count} unknown filetypes!")
        return nodes

    def check_nodes_validity(self, stream, nodes):
        validator = NodeValidator(stream)
        for node in nodes:
            validator.validate(node)
            if len(node.get_children()) > 0:
                self.check_nodes_validity(stream, node.get_children())

    def terminate(self):
        self._terminate_thread = True
        self.meta_data_scanner.abort_scan = True


class App(tk.Frame):
    def __init__(self, master, path = None, key=None, deep_scan=None):
        
        self.metadata_analysis_window:ScanMetaDataWindow = None
        
        # Tkinter
        tk.Frame.__init__(self, master)

        self._master = master
        self._recovered_file_browser = None
        self._carved_file_browser = None
        self._unreal_analyzer_browser = None
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

        self.file_menu.add_command(label="Open HDD img",command=self.display_open_hdd_img_window)

        self.scan_menu = None
        self.analysis_menu = None

        # Threads
        self._meta_data_scanner_thread = None
        self._filecarver_scanner_thread = None

        if path:
            self._master.after(100, self.begin_disk_scan_metaanalysis, path, key, deep_scan)

        self._master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.show_splash()

    def show_splash(self):
        splash_image = PhotoImage(file='assets/app-icon.gif')
        self._splash = inner_frame = tk.Frame(self._master, borderwidth=25, bg="#1F67F6")
        inner_frame.pack(fill="both", expand=True)
        Label(inner_frame, image=splash_image, background='#1F67F6').pack(fill="both", expand=True)
        self._master.mainloop()

    def on_closing(self):
        if self._meta_data_scanner_thread:
            self._meta_data_scanner_thread.terminate()
            self._meta_data_scanner_thread.join()
        self._master.destroy()
    
    #
    # Disk
    #
    def _open_disk(self, path, keyfile=None):
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

    def get_loadpath(self):
        load_path = os.path.normpath(f"{os.getcwd()}\\scans") + "\\" + os.path.basename(self._current_diskpath).split(".")[0]
        load_path = load_path.lower()
        return load_path
    
    def begin_disk_scan_active_fs(self):
        # Scan the disks partition
        scan_results = self.scan_active_fs_on_partition(self._current_disk, self._current_partition_name)
        
        # Create nodes from the scans results
        nodes = self.create_nodes_from_scan_results(self._current_disk, scan_results)

        # Create Stream
        partition = self._current_disk.getPartitionByName(self._current_partition_name)
        stream = partition.getDataProvider()

        # Show results
        self.display_scan_results_tab(nodes)

    def scan_active_fs_on_partition(self, disk, partition_name):
        scanner = Scanner(disk, partition_name)
        scanner.scan_active_filesystem()
        return scanner.scan_results
    
    def create_nodes_from_scan_results(self, disk, scan_results):
        # Creates nodes and makes associations between inodes and directs
        linker = UFS2Linker(disk, scan_results)
        nodes = linker.get_root_nodes()
        return nodes
    
    #
    # Meta Data Analysis
    #
    def begin_disk_scan_metaanalysis(self, is_deep_scan=False):
        
        load_path = self.get_loadpath()
        load_path_meta_analysis = self.get_loadpath()
        load_path_meta_analysis += "\\deep_scan" if is_deep_scan else "\\fast_scan"

        # If this scan hasn't completed before write a scan-log
        if not os.path.exists(load_path_meta_analysis + "\\inodes.txt"):
            if not os.path.exists(load_path_meta_analysis):
                os.makedirs(load_path_meta_analysis)
        
        self._meta_data_scanner_thread = MetaDataScannerThread(self._current_disk, self._current_partition_name)
        self._meta_data_scanner_thread.set_scan_args(load_path_meta_analysis, is_deep_scan)
        self._meta_data_scanner_thread.start()

        self.check_if_scan_complete()

    def check_if_scan_complete(self):

        if self._meta_data_scanner_thread._scan_complete:
            self.on_metadata_scan_complete(self._meta_data_scanner_thread.meta_data_scanner)
        else:
            # check every 100ms
            self.after(100, self.check_if_scan_complete)
    
    def on_metadata_scan_complete(self, scanner):

        # Set the nodes from the scanner
        nodes = self._meta_data_scanner_thread.nodes

        # Show results
        self.display_scan_results_tab(nodes)

        # Update the FileCarverBrowser if it exists to remove any files that meta data scanner may have found
        if self._carved_file_browser and self._filecarver_scanner_thread:
            self.on_filecarver_complete()

    #
    # File Carver
    #
    def begin_file_carver_scan(self):
        if self._current_disk is None:
            Logger.log("Cannot begin file carver no disk has been opened.")
            return
        # This scans the whole disk not just the partition
        # stream = self._current_disk.getDataProvider()

        loadpath = self.get_loadpath() + "\\file_carver"

        self._filecarver_scanner_thread = FileCarverScanner(self._current_disk, self._current_partition_name, loadpath)
        self._filecarver_scanner_thread.start()

        self.check_if_filecarver_complete()
    
    def check_if_filecarver_complete(self):

        if self._filecarver_scanner_thread._scan_complete:
            self.on_filecarver_complete()
        else:
            # check every 100ms
            self.after(100, self.check_if_filecarver_complete)

    def on_filecarver_complete(self):
        nodes =  self._filecarver_scanner_thread.get_nodes()

        # Remove any nodes that were already recovered / in the active filesystem
        file_offsets = []

        for recovered_node in self._recovered_file_browser.node_map.values():
            file_offsets.append(recovered_node.get_file_offset())

        for node in list(nodes):
            if node.get_file_offset() in file_offsets:
                nodes.remove(node)
        
        # Instantiate the file browser GUI
        self._carved_file_browser = FileCarverFileBrowser(self._master, self._current_disk, self._current_partition_name, nodes)
        
        self.update_gui()


    #
    # Unreal Analyzer
    #
    def begin_unreal_analysis(self):
        if self._current_disk is None:
            Logger.log("Cannot begin file carver no disk has been opened.")
            return
        # This scans the whole disk not just the partition
        # stream = self._current_disk.getDataProvider()

        # This scans just the partition
        partition = self._current_disk.getPartitionByName(self._current_partition_name)
        stream = partition.getDataProvider()

        # loadpath = self.get_loadpath() + "\\file_carver"
        # if not os.path.exists(loadpath):
        #     os.makedirs(loadpath)
        # scan_logfile = open(loadpath + '\\filecarver-log.txt','w', encoding='utf8')
        # Logger.streams.append(scan_logfile)

        analyze_nodes = []

        if self._carved_file_browser:
            for value in self._carved_file_browser.node_map.values():
                analyze_nodes.append(value)

        if self._recovered_file_browser:
            for value in self._recovered_file_browser.node_map.values():
                analyze_nodes.append(value)

        if not self._recovered_file_browser and not self._carved_file_browser:
            Logger.log("There are no recovered files to attempt to anlyze. Run the meta data analysis, file carver or both before attempting the Unreal Analysis.")
            return
        
        unrealanalyzer = UnrealAnalyzer(analyze_nodes, stream)
        unrealanalyzer.search_for_file_matches()
        unrealanalyzer.assign_file_matches()

        nodes =  unrealanalyzer.get_root_unodes()
        self._unreal_analyzer_browser = UnrealFileBrowser(self._master, self._current_disk, self._current_partition_name, nodes)
        
        self.update_gui()

    #
    # Validation & Identification
    #
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

    #
    # Display other GUI windows
    #
    def display_scan_results_tab(self, nodes):
        if self._splash:
            self._splash.pack_forget()
            self._splash.grid_forget()
            self._splash.destroy()
            self._splash = None
        
        if self._recovered_file_browser:
            self._recovered_file_browser.load_nodes(nodes)
        else:
            self._master.geometry("1440x960")

            # Create Stream
            partition = self._current_disk.getPartitionByName(self._current_partition_name)
            stream = partition.getDataProvider()

            # Create frame for viewing the scan results
            self._recovered_file_browser = MetaAnalysisFileBrowser(self._master, self._current_disk, self._current_partition_name, nodes)
            
            self.update_gui()

    def display_open_hdd_img_window(self):
        open_image_window = OpenHDDImageWindow()
        open_image_window.on_open_img += self.on_open_img_clicked

    def display_metadata_analysis_window(self):
        self.metadata_analysis_window = ScanMetaDataWindow()

    def update_gui(self):
        self._tab_control.pack_forget()
        if self._recovered_file_browser:
            self._tab_control.add(self._recovered_file_browser, text="File Browser")
        if self._carved_file_browser:
            self._tab_control.add(self._carved_file_browser, text="File Carver")
        if self._unreal_analyzer_browser:
            self._tab_control.add(self._unreal_analyzer_browser, text="Unreal Games")
        self._tab_control.pack(expand = 1, fill =BOTH)

        if self.scan_menu == None:
            self.scan_menu = Menu(self.menubar, tearoff=0)
            self.menubar.add_cascade(label="Scan", menu=self.scan_menu)

            self.scan_menu.add_command(label="UFS2 Metadata Scan (Fast)",command=lambda: self.begin_disk_scan_metaanalysis())
            self.scan_menu.add_command(label="UFS2 Metadata Scan (Deep)",command=lambda: self.begin_disk_scan_metaanalysis(True))
            self.scan_menu.add_command(label="File Carver",command=self.begin_file_carver_scan)

        if self.analysis_menu == None:
            self.analysis_menu = Menu(self.menubar, tearoff=0)
            self.menubar.add_cascade(label="Analysis", menu=self.analysis_menu)

            self.analysis_menu.add_command(label="Unreal Engine 3 Analyzer",command=lambda: self.begin_unreal_analysis())


    #
    # Events
    #
    def on_open_img_clicked(self, path, keyfile):
        # Open the disk
        self._current_disk = self._open_disk(path, keyfile)

        self.begin_disk_scan_active_fs()

        # Add the Scan options to the menu once a drive is opened

        

    def on_scan_clicked(self, is_deep):
        self.begin_disk_scan_metaanalysis(is_deep)


class ScanMetaDataWindow(tk.Frame):
    def __init__(self):
        # Init Vars
        self.scan_options = [
            "Fast",
            "Deep"
        ]

        self.modal = tk.Toplevel()
        self.on_scan = Event()

        self.scan_type = StringVar()
        self.scan_type.set( "Fast" )

        # Progress Bar
        self.progress = Progressbar(self.modal, orient = HORIZONTAL,length = 500, mode = 'determinate')
        self.progress.pack(padx=10, pady=10)
        
        # Create Label
        label = Label( self.modal , text = " Scan Type:" )
        label.pack()

        # Create Dropdown menu
        drop = OptionMenu( self.modal , self.scan_type, *self.scan_options )
        drop.pack()
        
        # Create button, it will change label text
        button = Button( self.modal , text = "Scan" , command = self.on_scan_clicked )
        button.place(rely=1.0, relx=1.0, x=-10, y=-10, anchor=SE)

    def update_progress(self, percent):
        self.progress['value'] = percent
        self.update_idletasks()

    def on_scan_clicked(self):
        is_deep = False
        if self.scan_type.get() == "Deep":
            is_deep = True
        self.on_scan(is_deep)


class OpenHDDImageWindow(tk.Frame):
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
        self.on_open_img = Event()
        
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
        #fast_scan = Radiobutton(self.modal, text="Fast Scan*", variable=self.deep_scan, value=False).place(x=10,y=70)
        #deep_scan = Radiobutton(self.modal, text="Deep Scan", variable=self.deep_scan, value=True).place(x=100,y=70)
        self.scan_btn = Button(self.modal, text="Open", command=self.begin_scan, state=DISABLED)
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
        self.on_open_img(path,keyfile)