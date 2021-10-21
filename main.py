import argparse
import os
import sys
import tkinter as tk

import disklib
from common.logger import Logger

from analysis.analyzer import Node, NodeType, Scanner, UFS2Linker
from analysis.ufs import endianness, Endianness
from gui.app import App
from analysis.carver import InodeIdentifier, all_filesigs


def main(path, keyfile=None, is_deep_scan=False):
    
    Logger.streams.append(sys.stdout)
    logfile = open('log.txt','w', encoding='utf8')
    Logger.streams.append(logfile)

    with open(path, 'rb') as fp:
        file_disk_stream = disklib.FileDiskStream(path)
        config = disklib.DiskConfig()
        config.setStream(file_disk_stream)
        
        if keyfile:
            keys = open(keyfile, 'rb').read()
            config.setKeys(keys)
        else:
            Logger.log("\nDecrypted drive support is broken currently... \nOpen an encrypted drive with a keyfile")

        disk = disklib.DiskFormatFactory.detect(config)

        stream = disk.getDataProvider()

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

        scanner = Scanner(disk, scan_partition)
        
        load_path = os.path.normpath(f"{os.getcwd()}\\scans") + "\\" + os.path.basename(path).split(".")[0]
        load_path = load_path.lower()

        # Find deleted inodes and directs
        scanner.scan(load_path, is_deep_scan)

        # Creates nodes and makes associations between inodes and directs
        linker = UFS2Linker(disk, scanner.scan_results)
        
        nodes = linker.get_root_nodes()

        # Identify file types
        Logger.log("Identifying unknown files filetypes...")
        inode_ident = InodeIdentifier(disk, scan_partition)
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

        root = tk.Tk()
        root.title("PS Recovery Prototype")
        app = App(root, nodes, disk, scanner._sblk)
        app.mainloop()



if __name__ == "__main__":
    if len(sys.argv) == 1 or len(sys.argv) > 4:
        Logger.log(f"Usage: {sys.argv[0]}\n Encrypted Image: <image path> <keyfile path> \n Decrypted Image: <image path> \n Optional: --deep-scan")
        exit()

    deep_scan = False
    img_path = sys.argv[1]
    key_path = None

    if(len(sys.argv) == 3):
        if (sys.argv[2] == '--deep-scan'):
            deep_scan = True
        else:
            key_path = sys.argv[2]

    if(len(sys.argv) == 4):
        key_path = sys.argv[2]
        if (sys.argv[3] == '--deep-scan'):
            deep_scan = True
        
    main(img_path, key_path, deep_scan)
