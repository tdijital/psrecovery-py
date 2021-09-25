import argparse
import os
import sys
import tkinter as tk

import disklib
from common.logger import Logger

from analysis.analyzer import Scanner2
from analysis.ufs import endianness, Endianness
from gui.app import App


def main(path, keyfile=None, deep_scan=False):
    
    Logger.streams.append(sys.stdout)
    logfile = open('log.txt','w', encoding='utf8')
    Logger.streams.append(logfile)

    with open(path, 'rb') as fp:
        stream = disklib.FileDiskStream(path)
        config = disklib.DiskConfig()
        config.setStream(stream)
        
        if keyfile:
            keys = open(keyfile, 'rb').read()
            config.setKeys(keys)
        else:
            Logger.log("\nDecrypted drive support is broken currently... \nOpen an encrypted drive with a keyfile")

        disk = disklib.DiskFormatFactory.detect(config)

        disk_stream = disk.getDataProvider()

        ps3_magic1 = bytes.fromhex('0FACE0FF')
        ps3_magic2 = bytes.fromhex('DEADFACE')
        disk_stream.seek(0x14)
        magic1 = disk_stream.read(0x4)
        disk_stream.seek(0x1C)
        magic2 = disk_stream.read(0x4)

        global endianness

        if ps3_magic1 == magic1 or ps3_magic2 == magic2:
            endianness = Endianness.BIG
            Logger.log("Scanning PS3 HDD img...")
        else:
            endianness = Endianness.LITTLE
            Logger.log("Scanning PS4 HDD img...")

        scanner = Scanner2(disk, 0x200)
        
        load_path = os.path.normpath(f"{os.getcwd()}\\scans") + "\\" + os.path.basename(path).split(".")[0]
        load_path = load_path.lower()

        inodes = scanner.scan(load_path,deep_scan)


        root = tk.Tk()
        root.title("PS Recovery Prototype")
        app = App(root, inodes, disk, scanner._sblk)
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
