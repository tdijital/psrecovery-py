import sys
import tkinter as tk
from tkinter import PhotoImage

from common.logger import Logger
from gui.app import App


def main(path=None, keyfile=None, is_deep_scan=False):
    
    Logger.streams.append(sys.stdout)
    logfile = open('log.txt','w', encoding='utf8')
    Logger.streams.append(logfile)

    # GUI Root
    root = tk.Tk()
    root.title("PS Recovery Prototype")
    icon = PhotoImage(file='assets/app-icon.gif')
    root.iconphoto(True, icon)
    

    if path:
        app = App(root, path, keyfile, is_deep_scan)
    else:
        app = App(root)
        
    app.mainloop()

if __name__ == "__main__":
    
    img_path = None
    key_path = None
    deep_scan = False

    if len(sys.argv) >= 2:
        if sys.argv[1] == 'help':
            print(f"Usage: {sys.argv[0]}\n Encrypted Image: <image path> <keyfile path> \n Decrypted Image: <image path> \n Optional: --deep-scan")
            exit()
        else:
            img_path = sys.argv[1]

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
